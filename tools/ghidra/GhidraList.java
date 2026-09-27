//@category AnalogRytm
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
public class GhidraList extends GhidraScript {
  public void run() throws Exception {
    String[] a = getScriptArgs();
    long lo = Long.parseLong(a[0].replace("0x",""),16), hi = Long.parseLong(a[1].replace("0x",""),16);
    AddressSpace sp = currentProgram.getAddressFactory().getDefaultAddressSpace();
    InstructionIterator it = currentProgram.getListing().getInstructions(sp.getAddress(lo), true);
    Address end = sp.getAddress(hi);
    while (it.hasNext()) {
      Instruction ins = it.next();
      if (ins.getAddress().compareTo(end) > 0) break;
      println(String.format("%08x  %s", ins.getAddress().getOffset(), ins.toString()));
    }
  }
}
