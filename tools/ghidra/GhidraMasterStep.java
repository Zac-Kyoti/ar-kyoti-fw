//@category AnalogRytm
// Session 9 (AR), prompted from the OT side. AR's DIRECT JUMP commit computes
//   new_step = masterStep(0x405666e4) mod patternLen(+0x14eb3)
// and then per track `new_step mod trackLen`. Everything about how AR compares to the OT
// implementation hinges on ONE untraced fact: is 0x405666e4 a position bounded by the
// current pattern's length, or a free-running absolute counter?
//
//   bounded  -> AR means "carry the playhead index into the new pattern"
//   absolute -> AR means "where the new pattern would be had it been playing all along"
//
// The OT user reports the second behaviour on real AR hardware. Trace it instead of
// assuming: find every site that writes 0x405666e4 (and the master resolution 0x405666e6
// that sets its rate), including cursor setups, since a reference-only scan under-reports
// register-indirect stores.
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.*;
import java.util.*;

public class GhidraMasterStep extends GhidraScript {
  public void run() throws Exception {
    long[] targets = {0x405666e4L, 0x405666e6L, 0x405666e8L};
    Listing listing = currentProgram.getListing();
    ReferenceManager rm = currentProgram.getReferenceManager();
    FunctionManager fm = currentProgram.getFunctionManager();
    LinkedHashMap<Long, List<String>> hits = new LinkedHashMap<>();
    for (long t : targets) hits.put(t, new ArrayList<>());

    long n = 0;
    InstructionIterator it = listing.getInstructions(true);
    while (it.hasNext()) {
      if (monitor.isCancelled()) break;
      Instruction ins = it.next();
      n++;
      long pc = ins.getAddress().getOffset();
      Function f = fm.getFunctionContaining(ins.getAddress());
      String fn = f != null ? f.getName() : "-";
      for (Reference r : rm.getReferencesFrom(ins.getAddress())) {
        if (!r.getReferenceType().isData()) continue;
        long to = r.getToAddress().getOffset();
        if (hits.containsKey(to)) {
          String how = r.getReferenceType().isWrite() ? "WRITE" :
                       r.getReferenceType().isRead() ? "read " : "data ";
          hits.get(to).add(String.format("%08x  %-40s %s  (%s)", pc, ins.toString(), how, fn));
        }
      }
      for (int i = 0; i < ins.getNumOperands(); i++)
        for (Object o : ins.getOpObjects(i)) {
          long v = (o instanceof Scalar) ? ((Scalar) o).getUnsignedValue()
                 : (o instanceof Address) ? ((Address) o).getOffset() : -1;
          if (hits.containsKey(v)) {
            String line = String.format("%08x  %-40s %s  (%s)", pc, ins.toString(), "CURSOR", fn);
            List<String> L = hits.get(v);
            if (L.isEmpty() || !L.get(L.size() - 1).equals(line)) L.add(line);
          }
        }
    }
    println("=== scanned " + n + " instructions ===");
    for (long t : targets) {
      println("");
      println("=== " + String.format("%08x", t) + " ===");
      for (String s : new LinkedHashSet<>(hits.get(t))) println("  " + s);
    }
  }
}
