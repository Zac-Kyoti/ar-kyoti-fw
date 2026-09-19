//@category AnalogRytm
// Prints Ghidra's own disassembly listing (address, bytes, mnemonic) over a
// range -- ground truth to cross-check against other disassemblers.
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Instruction;

public class GhidraListing extends GhidraScript {
    @Override
    public void run() throws Exception {
        var af = currentProgram.getAddressFactory().getDefaultAddressSpace();
        var lst = currentProgram.getListing();
        long start = 0x400407e0L;
        long end = 0x40040900L;
        Instruction ins = lst.getInstructionAt(af.getAddress(start));
        if (ins == null) {
            ins = lst.getInstructionContaining(af.getAddress(start));
        }
        while (ins != null && ins.getAddress().getOffset() < end) {
            byte[] b = ins.getBytes();
            StringBuilder hex = new StringBuilder();
            for (byte bb : b) hex.append(String.format("%02x", bb));
            println(String.format("%08x  %-14s %s", ins.getAddress().getOffset(), hex, ins.toString()));
            ins = ins.getNext();
        }
        println("[GhidraListing] done.");
    }
}
