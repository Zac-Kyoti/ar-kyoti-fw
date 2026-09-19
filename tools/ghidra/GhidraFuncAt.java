//@category AnalogRytm
// Prints the function containing a given address, then decompiles it.
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.util.task.ConsoleTaskMonitor;

public class GhidraFuncAt extends GhidraScript {
    static final long ADDR = 0x400411e8L;

    @Override
    public void run() throws Exception {
        var af = currentProgram.getAddressFactory().getDefaultAddressSpace();
        var fm = currentProgram.getFunctionManager();
        Function f = fm.getFunctionContaining(af.getAddress(ADDR));
        if (f == null) {
            println("no function contains 0x" + Long.toHexString(ADDR));
            return;
        }
        println("Containing function: " + f.getName() + " @ " + f.getEntryPoint()
                + "  body=" + f.getBody().getNumAddresses() + " bytes");

        DecompInterface dec = new DecompInterface();
        dec.openProgram(currentProgram);
        ConsoleTaskMonitor mon = new ConsoleTaskMonitor();
        var res = dec.decompileFunction(f, 90, mon);
        if (res != null && res.decompileCompleted()) {
            println(res.getDecompiledFunction().getC());
        } else {
            println("(decompile failed: " + (res != null ? res.getErrorMessage() : "no result") + ")");
        }
        println("\n[GhidraFuncAt] done.");
    }
}
