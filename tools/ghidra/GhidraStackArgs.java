//@category AnalogRytm
// Mechanically resolves the stack-argument layout at a call site: walks
// straight-line code from a start address to a target jsr, tracking every
// SP-affecting instruction (PEA, MOVE.x -(SP)/(SP)+, CLR.x -(SP), ADDQ/SUBQ
// #n,SP, LEA (n,SP),SP), and reports each pushed item's offset as the callee
// would see it (return address at +0, first arg at +4).
//
// This exists because hand-computing this by eye is error-prone (see
// NOTES.md Session 3 continued) -- byte-sized pushes to SP still move it by
// 2 (m68k alignment quirk), odd SUBQ/ADDQ #n,SP adjustments for packed
// struct args, and PEA vs plain MOVE all interleave, and a single miscount
// anywhere invalidates every offset after it.
//
// Usage: edit START/TARGET_CALL below, run via analyzeHeadless -postScript.
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.scalar.Scalar;

import java.util.ArrayList;
import java.util.List;

public class GhidraStackArgs extends GhidraScript {
    // Edit these two addresses per use.
    static final long START = 0x40040846L;
    static final long TARGET_CALL = 0x4004088aL;

    static class Push {
        long insnAddr;
        String desc;
        int depthBefore, depthAfter; // bytes below the depth at START
        Push(long a, String d, int before, int after) { insnAddr = a; desc = d; depthBefore = before; depthAfter = after; }
    }

    @Override
    public void run() throws Exception {
        var af = currentProgram.getAddressFactory().getDefaultAddressSpace();
        Listing listing = currentProgram.getListing();
        Address startAddr = af.getAddress(START);
        Address targetAddr = af.getAddress(TARGET_CALL);

        List<Push> pushes = new ArrayList<>();
        int depth = 0; // bytes SP has moved down relative to its value at START
        Instruction ins = listing.getInstructionAt(startAddr);
        boolean reachedTarget = false;

        while (ins != null) {
            long addr = ins.getAddress().getOffset();
            if (addr == TARGET_CALL) { reachedTarget = true; break; }
            if (addr > TARGET_CALL) { break; }

            String mnFull = ins.getMnemonicString().toLowerCase(); // e.g. "move.l", "pea", "subq.l"
            String mn = mnFull.contains(".") ? mnFull.substring(0, mnFull.indexOf('.')) : mnFull;
            String opStr = ins.toString();

            if (mn.equals("pea")) {
                int before = depth;
                depth += 4;
                pushes.add(new Push(addr, opStr, before, depth));
            } else if ((mn.equals("move") || mn.equals("movea") || mn.equals("clr")) && opStr.contains("-(SP)")) {
                int size = 4;
                if (mnFull.endsWith(".b")) size = 2; // m68k SP byte push still moves 2 (alignment)
                else if (mnFull.endsWith(".w")) size = 2;
                int before = depth;
                depth += size;
                pushes.add(new Push(addr, opStr, before, depth));
            } else if (mn.equals("subq") || mn.equals("addq") || mn.equals("suba") || mn.equals("adda")) {
                // e.g. "subq.l #0x3,SP" / "addq.l #0x4,SP" -- direct SP adjustment
                if (opStr.contains(",SP")) {
                    Object[] opObjs = ins.getOpObjects(0);
                    Integer n = null;
                    for (Object o : opObjs) {
                        if (o instanceof Scalar) { n = (int) ((Scalar) o).getSignedValue(); }
                    }
                    if (n != null) {
                        int before = depth;
                        if (mn.startsWith("sub")) depth += n; else depth -= n;
                        pushes.add(new Push(addr, opStr + "  [SP " + (mn.startsWith("sub") ? "-=" : "+=") + n + "]", before, depth));
                    } else {
                        println("  ! could not read immediate at " + ins.getAddress() + ": " + opStr);
                    }
                }
            } else if (mn.equals("lea") && opStr.contains(",SP") && opStr.contains("(SP)")) {
                // e.g. "lea (0x1c,SP),SP" -- SP += 0x1c (stack cleanup after a call)
                Object[] opObjs = ins.getOpObjects(0);
                Integer n = null;
                for (Object o : opObjs) {
                    if (o instanceof Scalar) { n = (int) ((Scalar) o).getSignedValue(); }
                }
                if (n != null) {
                    int before = depth;
                    depth -= n;
                    pushes.add(new Push(addr, opStr + "  [SP += " + n + "]", before, depth));
                }
            } else if (mn.equals("jsr") || mn.equals("bsr")) {
                pushes.add(new Push(addr, opStr + "  [CALL, not a push -- but if it's not the target, its own callee cleans its own args; SP unaffected here under callee-cleans-nothing convention]", depth, depth));
            }
            ins = ins.getNext();
        }

        if (!reachedTarget) {
            println("!! never reached target call 0x" + Long.toHexString(TARGET_CALL)
                    + " walking straight-line from 0x" + Long.toHexString(START)
                    + " -- there may be a branch in between this script doesn't follow.");
        }

        println("Final depth at call site: " + depth + " (0x" + Integer.toHexString(depth) + ") bytes pushed");
        println("Callee's return address will sit at (SP_at_target - 4); first arg (param_1) at entry+4.\n");
        println(String.format("%-10s %-45s %8s %8s %10s", "addr", "instruction", "before", "after", "calleeOff"));
        // entryOffsetBase: for a push with depthAfter == D, its item's lowest address is at
        // (SP_at_START - D). The callee's SP-at-entry = SP_at_target - 4 = (SP_at_START - depth) - 4.
        // calleeOffset = (SP_at_START - D) - ((SP_at_START - depth) - 4) = depth - D + 4.
        for (Push p : pushes) {
            int calleeOff = depth - p.depthAfter + 4;
            println(String.format("%08x   %-45s %8d %8d   +0x%x (%d)",
                    p.insnAddr, p.desc, p.depthBefore, p.depthAfter, calleeOff, calleeOff));
        }
        println("\n[GhidraStackArgs] done.");
    }
}
