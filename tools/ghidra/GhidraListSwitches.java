//@category AnalogRytm
// Lists switch-statement jump tables Ghidra's own auto-analysis already found
// (symbols named switchdataD_/caseD_/JTable, or functions whose body contains
// a computed/indirect jump), filtered to small tables (3-6 cases) -- a good
// shape match for a 4-valued enum dispatch.
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;

import java.util.HashMap;
import java.util.Map;
import java.util.TreeMap;

public class GhidraListSwitches extends GhidraScript {
    @Override
    public void run() throws Exception {
        SymbolTable st = currentProgram.getSymbolTable();
        var fm = currentProgram.getFunctionManager();

        Map<String, Integer> caseCountByFunc = new TreeMap<>();
        Map<String, Function> funcByName = new HashMap<>();
        int switchTables = 0, caseLabels = 0;

        SymbolIterator it = st.getAllSymbols(true);
        while (it.hasNext()) {
            Symbol s = it.next();
            String name = s.getName();
            if (name.startsWith("switchD_") || name.startsWith("switchdataD_")) {
                switchTables++;
                Function f = fm.getFunctionContaining(s.getAddress());
                String key = (f != null ? f.getName() + "@" + f.getEntryPoint() : "?") ;
                println("switch table symbol " + name + " @ " + s.getAddress() + "  in " + key);
                if (f != null) funcByName.put(key, f);
            } else if (name.startsWith("caseD_")) {
                caseLabels++;
                Function f = fm.getFunctionContaining(s.getAddress());
                String key = (f != null ? f.getName() + "@" + f.getEntryPoint() : "?");
                caseCountByFunc.merge(key, 1, Integer::sum);
                if (f != null) funcByName.put(key, f);
            }
        }

        println("\n[GhidraListSwitches] switch table symbols: " + switchTables
                + "   total case labels: " + caseLabels);
        println("\n=== functions with 3-6 case labels (candidate small enum dispatch) ===");
        for (var e : caseCountByFunc.entrySet()) {
            if (e.getValue() >= 3 && e.getValue() <= 6) {
                println("  " + e.getValue() + " cases  " + e.getKey());
            }
        }
        println("\n[GhidraListSwitches] done.");
    }
}
