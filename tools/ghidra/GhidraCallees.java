//@category AnalogRytm
// Lists every function FUN_4003fc14 (the PatternSelectionView event dispatcher
// that owns the PTN CHG picker) calls, with call-site address -- to find the
// setter it invokes when the user actually confirms a new PTN CHG mode.
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.symbol.FlowType;

import java.util.TreeMap;

public class GhidraCallees extends GhidraScript {
    @Override
    public void run() throws Exception {
        var af = currentProgram.getAddressFactory().getDefaultAddressSpace();
        var fm = currentProgram.getFunctionManager();
        var lst = currentProgram.getListing();

        Function target = fm.getFunctionAt(af.getAddress(0x4003fc14L));
        if (target == null) {
            println("no function at 0x4003fc14 (body not created?)");
            return;
        }
        AddressSetView body = target.getBody();
        println("FUN_4003fc14 body size: " + body.getNumAddresses() + " bytes, min="
                + body.getMinAddress() + " max=" + body.getMaxAddress());

        TreeMap<Long, String> calls = new TreeMap<>();
        Instruction ins = lst.getInstructionAt(target.getEntryPoint());
        while (ins != null && body.contains(ins.getAddress())) {
            FlowType ft = ins.getFlowType();
            if (ft.isCall()) {
                var refs = ins.getReferencesFrom();
                for (var r : refs) {
                    if (r.getReferenceType().isCall()) {
                        long dest = r.getToAddress().getOffset();
                        Function f = fm.getFunctionAt(r.getToAddress());
                        calls.put(dest, (f != null ? f.getName() : "sub_" + Long.toHexString(dest))
                                + "  <- call@" + ins.getAddress());
                    }
                }
            }
            ins = ins.getNext();
        }
        println("\n=== " + calls.size() + " unique callees ===");
        for (var e : calls.entrySet()) {
            println(String.format("  0x%x  %s", e.getKey(), e.getValue()));
        }
        println("\n[GhidraCallees] done.");
    }
}
