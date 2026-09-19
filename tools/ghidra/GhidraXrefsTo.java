//@category AnalogRytm
// Lists every caller (with containing function) of a fixed list of target
// addresses, using Ghidra's already-computed reference manager.
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;

public class GhidraXrefsTo extends GhidraScript {
    @Override
    public void run() throws Exception {
        var af = currentProgram.getAddressFactory().getDefaultAddressSpace();
        var fm = currentProgram.getFunctionManager();
        var rm = currentProgram.getReferenceManager();

        long[] targets = {0x400b3db2L, 0x40158d68L, 0x40155f42L};
        for (long va : targets) {
            var addr = af.getAddress(va);
            println("=== xrefs to 0x" + Long.toHexString(va) + " ===");
            var it = rm.getReferencesTo(addr);
            int c = 0;
            while (it.hasNext()) {
                var r = it.next();
                Function f = fm.getFunctionContaining(r.getFromAddress());
                println("  from " + r.getFromAddress() + " (" + r.getReferenceType() + ")"
                        + (f != null ? "  in " + f.getName() + " @ " + f.getEntryPoint() : "  (no function)"));
                c++;
            }
            if (c == 0) println("  (none)");
        }
        println("\n[GhidraXrefsTo] done.");
    }
}
