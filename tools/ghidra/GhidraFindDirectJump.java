//@category AnalogRytm
// Locates the PTN CHG mode-name table (SEQUENTIAL/DIRECT START/DIRECT JUMP/TEMP JUMP)
// found in PatternSelectionView's string pool, finds who references the table itself
// (not just the strings), and decompiles those functions.
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.util.task.ConsoleTaskMonitor;

import java.util.LinkedHashSet;
import java.util.Set;

public class GhidraFindDirectJump extends GhidraScript {
    @Override
    public void run() throws Exception {
        var af = currentProgram.getAddressFactory().getDefaultAddressSpace();
        var fm = currentProgram.getFunctionManager();
        var rm = currentProgram.getReferenceManager();
        var lst = currentProgram.getListing();

        long tableBase = 0x4019af64L;
        String[] names = {"PTN: SEQUENTIAL", "PTN: DIRECT START", "PTN: DIRECT JUMP", "PTN: TEMP JUMP"};

        println("=== PTN CHG mode-name table @ 0x" + Long.toHexString(tableBase) + " ===");
        Set<Function> callers = new LinkedHashSet<>();
        for (int i = 0; i < 4; i++) {
            Address entry = af.getAddress(tableBase + i * 4L);
            println("  [" + i + "] 0x" + entry + " = \"" + names[i] + "\"");
            var ri = rm.getReferencesTo(entry);
            while (ri.hasNext()) {
                var r = ri.next();
                Function f = fm.getFunctionContaining(r.getFromAddress());
                println("      xref from " + r.getFromAddress() + " (" + r.getReferenceType() + ")"
                        + (f != null ? " in " + f.getName() + " @ " + f.getEntryPoint() : " (no function)"));
                if (f != null) callers.add(f);
            }
        }

        // Also: who references the table BASE address as a whole (array indexing
        // often computes base + d0*4, which shows as one ref to the base symbol).
        var riBase = rm.getReferencesTo(af.getAddress(tableBase));
        println("\n=== direct refs to table base 0x" + Long.toHexString(tableBase) + " ===");
        while (riBase.hasNext()) {
            var r = riBase.next();
            Function f = fm.getFunctionContaining(r.getFromAddress());
            println("  xref from " + r.getFromAddress() + " (" + r.getReferenceType() + ")"
                    + (f != null ? " in " + f.getName() + " @ " + f.getEntryPoint() : " (no function)"));
            if (f != null) callers.add(f);
        }

        println("\n=== decompiling " + callers.size() + " candidate function(s) ===");
        DecompInterface dec = new DecompInterface();
        dec.openProgram(currentProgram);
        ConsoleTaskMonitor mon = new ConsoleTaskMonitor();
        for (Function f : callers) {
            println("\n---------------- " + f.getName() + " @ " + f.getEntryPoint() + " ----------------");
            var res = dec.decompileFunction(f, 90, mon);
            if (res != null && res.decompileCompleted()) {
                println(res.getDecompiledFunction().getC());
            } else {
                println("  (decompile failed: " + (res != null ? res.getErrorMessage() : "no result") + ")");
            }
        }
        println("\n[GhidraFindDirectJump] done.");
    }
}
