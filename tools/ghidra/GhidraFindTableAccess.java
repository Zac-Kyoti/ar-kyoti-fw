//@category AnalogRytm
// Scans one or more functions' decompiled P-code for any memory access (LOAD/STORE)
// whose address computation touches the flattened pattern-table base (0x40b6a620), its
// per-record stride (0x14f00), or the current/pending/previous pattern-index globals
// (DAT_40566754/55/56) -- including indirect/computed accesses that a plain grep over
// literal immediates in the decompiled C would miss (a base precomputed once into a
// register/local and reused many times, register-plus-register addressing, etc). This
// is the mechanical version of the manual field check from earlier sessions -- see
// NOTES.md "NEXT for this thread" item 1 for why it exists: the manual check only ever
// caught literal immediate offsets.
//
// Edit TARGETS below per use. Each entry is treated as an address *inside* the function
// to scan (getFunctionContaining), not necessarily its entry point.
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.PcodeOpAST;
import ghidra.program.model.pcode.Varnode;
import ghidra.util.task.ConsoleTaskMonitor;

import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;

public class GhidraFindTableAccess extends GhidraScript {
    static final long[] TARGETS = {};

    static final long TABLE_BASE = 0x40b6a620L;
    static final long TABLE_STRIDE = 0x14f00L;
    static final long[] INDEX_GLOBALS = {0x40566754L, 0x40566755L, 0x40566756L};

    @Override
    public void run() throws Exception {
        var af = currentProgram.getAddressFactory().getDefaultAddressSpace();
        var fm = currentProgram.getFunctionManager();

        DecompInterface dec = new DecompInterface();
        dec.setOptions(new DecompileOptions());
        dec.openProgram(currentProgram);
        ConsoleTaskMonitor mon = new ConsoleTaskMonitor();

        for (long va : TARGETS) {
            var entry = af.getAddress(va);
            Function f = fm.getFunctionContaining(entry);
            if (f == null) {
                println("---- 0x" + Long.toHexString(va) + ": no function found");
                continue;
            }
            println("\n==================== " + f.getName() + " @ " + f.getEntryPoint()
                    + " ====================");
            var res = dec.decompileFunction(f, 90, mon);
            if (res == null || !res.decompileCompleted()) {
                println("  (decompile failed: " + (res != null ? res.getErrorMessage() : "no result") + ")");
                continue;
            }
            HighFunction hf = res.getHighFunction();
            if (hf == null) {
                println("  (no high function)");
                continue;
            }

            int hits = 0;
            Iterator<PcodeOpAST> it = hf.getPcodeOps();
            while (it.hasNext()) {
                PcodeOpAST op = it.next();
                int opc = op.getOpcode();
                if (opc != PcodeOp.LOAD && opc != PcodeOp.STORE) continue;
                Varnode addrVn = op.getInput(1);
                if (addrVn == null) continue;

                Set<String> signals = new HashSet<>();
                Set<Long> allConsts = new HashSet<>();
                traceBase(addrVn, signals, allConsts, new HashSet<>(), 0);
                if (!signals.isEmpty()) {
                    hits++;
                    // Any constant seen in the chain that isn't the base/stride itself is
                    // a plausible field-offset-within-record candidate -- surface it so
                    // results can be cross-checked against the already-known offsets
                    // (0x14eb3/b5/b9/ba) without re-reading raw listings by hand.
                    Set<String> otherConsts = new HashSet<>();
                    for (long c : allConsts) {
                        if (c != TABLE_BASE && c != TABLE_STRIDE) {
                            otherConsts.add("0x" + Long.toHexString(c));
                        }
                    }
                    String kind = (opc == PcodeOp.LOAD) ? "LOAD " : "STORE";
                    println(String.format("  [%s] %-12s %-60s <- %s  offsets=%s",
                            kind, op.getSeqnum().getTarget(), op.toString(), signals, otherConsts));
                }
            }
            if (hits == 0) {
                println("  (no matches -- this function does not touch the flattened table"
                        + " or the pattern-index globals, directly or indirectly)");
            } else {
                println("  (" + hits + " matching LOAD/STORE ops)");
            }
        }
        println("\n[GhidraFindTableAccess] done.");
    }

    // Bounded backward DFS through the def-chain of a varnode, looking for the table
    // base constant, the record-stride constant, or a LOAD of one of the pattern-index
    // globals feeding into this address computation. Every constant encountered along
    // the way is also recorded in allConsts (field-offset candidates).
    private void traceBase(Varnode vn, Set<String> signals, Set<Long> allConsts,
            Set<Varnode> visited, int depth) {
        if (vn == null || depth > 30 || visited.size() > 500) return;
        if (!visited.add(vn)) return;

        if (vn.isConstant()) {
            long v = vn.getOffset();
            allConsts.add(v);
            if (v == TABLE_BASE) signals.add("table-base-const(0x40b6a620)");
            if (v == TABLE_STRIDE) signals.add("stride-const(0x14f00)");
            return;
        }

        PcodeOp def = vn.getDef();
        if (def == null) return;

        int opc = def.getOpcode();
        if (opc == PcodeOp.LOAD) {
            Varnode a = def.getInput(1);
            if (a != null && a.isConstant()) {
                long v = a.getOffset();
                for (long g : INDEX_GLOBALS) {
                    if (v == g) signals.add("load-of-DAT_" + Long.toHexString(g));
                }
                if (v == TABLE_BASE) signals.add("load-via-table-base-const(0x40b6a620)");
            }
            traceBase(a, signals, allConsts, visited, depth + 1);
            return;
        }

        if (opc == PcodeOp.INDIRECT) {
            // input(1) of INDIRECT encodes the affecting op, not a real data value.
            traceBase(def.getInput(0), signals, allConsts, visited, depth + 1);
            return;
        }

        switch (opc) {
            case PcodeOp.INT_ADD:
            case PcodeOp.INT_SUB:
            case PcodeOp.INT_MULT:
            case PcodeOp.PTRADD:
            case PcodeOp.PTRSUB:
            case PcodeOp.COPY:
            case PcodeOp.CAST:
            case PcodeOp.INT_SEXT:
            case PcodeOp.INT_ZEXT:
            case PcodeOp.INT_2COMP:
            case PcodeOp.MULTIEQUAL:
                for (int i = 0; i < def.getNumInputs(); i++) {
                    traceBase(def.getInput(i), signals, allConsts, visited, depth + 1);
                }
                break;
            default:
                // Unhandled op kind -- don't traverse further, but don't crash either.
                break;
        }
    }
}
