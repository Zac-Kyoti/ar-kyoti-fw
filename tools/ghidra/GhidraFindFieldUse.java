//@category AnalogRytm
// Decompiles a list of candidate functions and prints only the ones whose
// decompiled C references a given field offset (as a grep over the output) --
// avoids manually scanning many full decompiles by eye.
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.util.task.ConsoleTaskMonitor;

public class GhidraFindFieldUse extends GhidraScript {
    @Override
    public void run() throws Exception {
        var af = currentProgram.getAddressFactory().getDefaultAddressSpace();
        var fm = currentProgram.getFunctionManager();

        long[] targets = {
            0x4015948cL, 0x40159544L, 0x4007502cL, 0x40076a90L, 0x400748a8L,
            0x40076a9cL, 0x40076ea0L, 0x40076a9eL, 0x40076f10L, 0x40076aaaL,
            0x40076ab6L, 0x40076cb8L, 0x40074fb4L, 0x40076ac2L, 0x40076ac6L,
            0x40076acaL, 0x4007703eL, 0x4007704aL, 0x40074f96L, 0x40074ae4L,
            0x40074b38L, 0x4007489cL
        };
        // Needles to search for in the decompiled C of each candidate.
        String[] needles = {"0x98", "+ 0x26", "[0x26]", "0x26)"};

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
            var res = dec.decompileFunction(f, 60, mon);
            if (res == null || !res.decompileCompleted()) {
                println(String.format("0x%x  %-20s DECOMPILE FAILED", va, f.getName()));
                continue;
            }
            String c = res.getDecompiledFunction().getC();
            boolean hit = false;
            for (String n : needles) {
                if (c.contains(n)) { hit = true; break; }
            }
            println(String.format("0x%x  %-20s body=%-6d %s", va, f.getName(),
                    f.getBody().getNumAddresses(), hit ? "*** REFERENCES +0x98/word26 ***" : ""));
            if (hit) {
                println(c);
            }
        }
        println("\n[GhidraFindFieldUse] done.");
    }
}
