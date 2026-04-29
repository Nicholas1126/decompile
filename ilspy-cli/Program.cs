using System;
using System.IO;
using ICSharpCode.Decompiler;
using ICSharpCode.Decompiler.CSharp;

namespace IlspyCli
{
    class Program
    {
        static int Main(string[] args)
        {
            if (args.Length < 1)
            {
                Console.WriteLine("Usage: ilspy-cli <input.dll/exe> [output-dir]");
                return 1;
            }

            string inputPath = args[0];
            string outputDir = args.Length > 1 ? args[1] : ".";

            if (!File.Exists(inputPath))
            {
                Console.Error.WriteLine($"File not found: {inputPath}");
                return 1;
            }

            Directory.CreateDirectory(outputDir);

            try
            {
                var decompiler = new CSharpDecompiler(inputPath, new DecompilerSettings());
                var fullOutput = decompiler.DecompileWholeModuleAsString();
                var name = Path.GetFileNameWithoutExtension(inputPath);
                var outputPath = Path.Combine(outputDir, name + ".cs");
                File.WriteAllText(outputPath, fullOutput);
                Console.WriteLine($"Decompiled {inputPath} -> {outputPath}");
                return 0;
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"Decompilation failed: {ex.Message}");
                return 1;
            }
        }
    }
}
