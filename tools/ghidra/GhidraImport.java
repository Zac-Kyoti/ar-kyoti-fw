//@category AnalogRytm
// Imports out/pointers_to_strings.csv (from tools/find_base.py): defines each
// string at its vaddr, labels it, and defines the 4-byte pointer at the site
// that references it, so cross-references show up in the disassembly/decompiler.
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.TerminatedStringDataType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.symbol.SourceType;

import java.io.BufferedReader;
import java.io.FileReader;
import java.nio.file.Paths;

public class GhidraImport extends GhidraScript {
    private static String slug(String s) {
        StringBuilder sb = new StringBuilder();
        for (char c : s.trim().toCharArray()) {
            sb.append(Character.isLetterOrDigit(c) ? c : '_');
        }
        String out = sb.toString();
        if (out.length() > 40) out = out.substring(0, 40);
        while (out.startsWith("_")) out = out.substring(1);
        while (out.endsWith("_")) out = out.substring(0, out.length() - 1);
        return out.isEmpty() ? "str" : out;
    }

    @Override
    public void run() throws Exception {
        String csvPath = Paths.get(getSourceFile().getParentFile().getParentFile().getParentFile().getAbsolutePath(),
                "out", "pointers_to_strings.csv").toString();
        println("[GhidraImport] reading " + csvPath);

        var af = currentProgram.getAddressFactory().getDefaultAddressSpace();
        var symtab = currentProgram.getSymbolTable();

        int definedStrings = 0, definedPtrs = 0, labeled = 0, line = 0;
        try (BufferedReader br = new BufferedReader(new FileReader(csvPath))) {
            String header = br.readLine(); // ptr_site_vaddr,ptr_value,string_vaddr,file_offset,string
            String row;
            while ((row = br.readLine()) != null) {
                line++;
                // fields: ptr_site_vaddr,ptr_value,string_vaddr,file_offset,"string..."
                int c1 = row.indexOf(',');
                int c2 = row.indexOf(',', c1 + 1);
                int c3 = row.indexOf(',', c2 + 1);
                int c4 = row.indexOf(',', c3 + 1);
                if (c1 < 0 || c2 < 0 || c3 < 0 || c4 < 0) continue;
                String ptrSiteStr = row.substring(0, c1);
                String strVaddrStr = row.substring(c2 + 1, c3);
                String text = row.substring(c4 + 1);
                if (text.startsWith("\"") && text.endsWith("\"")) {
                    text = text.substring(1, text.length() - 1).replace("\"\"", "\"");
                }

                long sVa = Long.decode(strVaddrStr);
                long pSite = Long.decode(ptrSiteStr);
                Address sAddr = af.getAddress(sVa);
                Address pAddr = af.getAddress(pSite);

                try {
                    Data d = getDataAt(sAddr);
                    if (d == null || !d.isDefined()) {
                        clearListing(sAddr);
                        createData(sAddr, new TerminatedStringDataType());
                        definedStrings++;
                    }
                } catch (Exception e) { /* best-effort */ }

                try {
                    symtab.createLabel(sAddr, "s_" + slug(text), SourceType.USER_DEFINED);
                    labeled++;
                } catch (Exception e) { /* best-effort */ }

                try {
                    clearListing(pAddr, pAddr.add(3));
                    createData(pAddr, new PointerDataType());
                    definedPtrs++;
                } catch (Exception e) { /* best-effort */ }

                if (line % 2000 == 0) println("  ... " + line + " rows processed");
            }
        }

        println("[GhidraImport] strings defined: " + definedStrings);
        println("[GhidraImport] labels created: " + labeled);
        println("[GhidraImport] pointers defined: " + definedPtrs);
        println("[GhidraImport] done.");
    }
}
