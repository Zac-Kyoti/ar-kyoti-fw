//@category AnalogRytm
// Decompiles a fixed list of target functions (small helpers, more likely to
// survive Ghidra's ColdFire decompiler than the giant dispatcher).
// Scratch tool: edit the `targets` array below per use, see NOTES.md for the
// addresses examined so far and what they turned out to be.
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.util.task.ConsoleTaskMonitor;

public class GhidraDecompileTargets extends GhidraScript {
    @Override
    public void run() throws Exception {
        var af = currentProgram.getAddressFactory().getDefaultAddressSpace();
        var fm = currentProgram.getFunctionManager();

        long[] targets = {};

        DecompInterface dec = new DecompInterface();
        dec.openProgram(currentProgram);
        ConsoleTaskMonitor mon = new ConsoleTaskMonitor();

        for (long va : targets) {
            var a = af.getAddress(va);
            Function f = fm.getFunctionAt(a);
            if (f == null) {
                try {
                    disassemble(a);
                    f = createFunction(a, "FUN_" + Long.toHexString(va));
                } catch (Exception e) {
                    println("---- 0x" + Long.toHexString(va) + ": could not create function: " + e);
                    continue;
                }
            }
            println("\n==================== " + f.getName() + " @ 0x" + Long.toHexString(va)
                    + "  (body " + f.getBody().getNumAddresses() + " bytes) ====================");
            var res = dec.decompileFunction(f, 60, mon);
            if (res != null && res.decompileCompleted()) {
                println(res.getDecompiledFunction().getC());
            } else {
                println("  (decompile failed: " + (res != null ? res.getErrorMessage() : "no result") + ")");
            }
        }
        println("\n[GhidraDecompileTargets] done.");
    }
}
