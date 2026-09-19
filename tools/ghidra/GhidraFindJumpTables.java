//@category AnalogRytm
// Lists small (3-6 entry) address tables whose every entry lands on an
// existing instruction -- candidate switch-statement jump tables. A 4-valued
// enum (SEQUENTIAL/DIRECT START/DIRECT JUMP/TEMP JUMP) dispatched via switch
// would show up as one of these.
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.mem.Memory;

public class GhidraFindJumpTables extends GhidraScript {
    @Override
    public void run() throws Exception {
        var af = currentProgram.getAddressFactory().getDefaultAddressSpace();
        var fm = currentProgram.getFunctionManager();
        var lst = currentProgram.getListing();
        Memory mem = currentProgram.getMemory();

        long start = 0x40000400L;
        long end = start + mem.getSize();
        int found = 0;

        for (long base = start; base < end - 24; base += 2) {
            if (monitor.isCancelled()) break;
            int n = 0;
            long[] entries = new long[8];
            boolean ok = true;
            for (; n < 8; n++) {
                Address a = af.getAddress(base + n * 4L);
                int v;
                try {
                    v = mem.getInt(a);
                } catch (Exception e) { ok = false; break; }
                long target = v & 0xFFFFFFFFL;
                if (target < start || target >= end) break;
                Instruction ins = lst.getInstructionAt(af.getAddress(target));
                if (ins == null) break;
                entries[n] = target;
            }
            if (n < 3 || n > 6) continue;
            // require the NEXT word to NOT also be a valid in-range code address
            // pointing to an instruction that is itself a plausible table continuation
            // (best-effort cutoff already handled by the loop above).
            // Heuristic: reject tables where all entries are identical (padding).
            boolean allSame = true;
            for (int i = 1; i < n; i++) if (entries[i] != entries[0]) allSame = false;
            if (allSame) continue;

            found++;
            println(String.format("table @ 0x%x  (%d entries)", base, n));
            for (int i = 0; i < n; i++) {
                Function f = fm.getFunctionContaining(af.getAddress(entries[i]));
                println(String.format("    [%d] 0x%x%s", i, entries[i],
                        f != null ? "  in " + f.getName() + " @ " + f.getEntryPoint() : ""));
            }
            if (found > 400) {
                println("... stopping, too many candidates (raise the filter)");
                break;
            }
        }
        println("\n[GhidraFindJumpTables] candidate tables: " + found);
    }
}
