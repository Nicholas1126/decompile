//Decompiler script for Ghidra headless mode
//Exports all decompiled functions to a single .c file
//@category Decompiler

import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;
import ghidra.program.model.address.AddressSet;

import java.io.FileWriter;
import java.io.PrintWriter;
import java.io.File;

public class ExportDecompiled extends GhidraScript {

    private static final int TIMEOUT_SECONDS = 30;

    @Override
    public void run() throws Exception {
        String outputPath = getScriptArgs().length > 0 ? getScriptArgs()[0] : null;
        if (outputPath == null) {
            String programName = currentProgram.getName();
            String baseName = programName.contains(".")
                ? programName.substring(0, programName.lastIndexOf('.'))
                : programName;
            outputPath = "/data/decompiled/" + baseName + "/decompiled.c";
        }

        File outFile = new File(outputPath);
        outFile.getParentFile().mkdirs();

        DecompInterface decompiler = new DecompInterface();
        decompiler.openProgram(currentProgram);

        FunctionManager funcMgr = currentProgram.getFunctionManager();
        int funcCount = funcMgr.getFunctionCount();
        int exported = 0;
        int skipped = 0;

        PrintWriter writer = new PrintWriter(new FileWriter(outFile));
        writer.println("// Decompiled by Ghidra " + currentProgram.getName());
        writer.println("// Functions: " + funcCount);
        writer.println();

        for (Function func : funcMgr.getFunctions(true)) {
            if (func.isThunk() || func.isExternal()) {
                skipped++;
                continue;
            }

            DecompileResults results = decompiler.decompileFunction(func, TIMEOUT_SECONDS, monitor);
            if (results.decompileCompleted()) {
                writer.println("// ---- " + func.getName() + " @ " + func.getEntryPoint() + " ----");
                writer.println(results.getDecompiledFunction().getC());
                writer.println();
                exported++;
            } else {
                skipped++;
            }
        }

        writer.flush();
        writer.close();
        decompiler.dispose();

        println("Exported " + exported + " functions, skipped " + skipped + " (total: " + funcCount + ")");
        println("Output: " + outputPath);
    }
}
