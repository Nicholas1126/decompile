using System;
using System.Collections.Generic;
using System.IO;
using System.Threading.Tasks;
using ICSharpCode.Decompiler;
using ICSharpCode.Decompiler.CSharp;
using ICSharpCode.Decompiler.Metadata;

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
                var settings = new DecompilerSettings();
                var netfxPaths = new[] { "/usr/lib/mono/4.7.2-api", "/usr/lib/mono/4.6.2-api" };
                var resolver = new SafeAssemblyResolver(inputPath, ".NETFramework,Version=v4.7.2", netfxPaths);
                var file = new PEFile(inputPath);
                var decompiler = new CSharpDecompiler(file, resolver, settings);
                var fullOutput = decompiler.DecompileWholeModuleAsString();
                var name = Path.GetFileNameWithoutExtension(inputPath);
                var outputPath = Path.Combine(outputDir, name + ".cs");
                File.WriteAllText(outputPath, fullOutput);
                Console.WriteLine($"Decompiled {inputPath} -> {outputPath}");
                return 0;
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"Decompilation failed: {ex}");
                return 1;
            }
        }
    }

    class SafeAssemblyResolver : IAssemblyResolver
    {
        readonly UniversalAssemblyResolver inner;
        readonly string[] fallbackPaths;
        readonly Dictionary<string, MetadataFile> cache = new();
        bool disposed;

        public SafeAssemblyResolver(string mainAssemblyPath, string targetFramework, string[] fallbackPaths)
        {
            inner = new UniversalAssemblyResolver(mainAssemblyPath, true, targetFramework);
            this.fallbackPaths = fallbackPaths;
        }

        public MetadataFile Resolve(IAssemblyReference reference)
        {
            try
            {
                return inner.Resolve(reference);
            }
            catch (Exception ex) when (ex is NotSupportedException or ResolutionException)
            {
                return FallbackResolve(reference.Name);
            }
        }

        public Task<MetadataFile?> ResolveAsync(IAssemblyReference reference)
        {
            try
            {
                var result = inner.ResolveAsync(reference);
                return CatchFallback(result, reference.Name);
            }
            catch (Exception ex) when (ex is NotSupportedException or ResolutionException)
            {
                return Task.FromResult<MetadataFile?>(FallbackResolve(reference.Name));
            }
        }

        async Task<MetadataFile?> CatchFallback(Task<MetadataFile?> task, string name)
        {
            try
            {
                return await task;
            }
            catch (Exception ex) when (ex is NotSupportedException or ResolutionException)
            {
                return FallbackResolve(name);
            }
        }

        public MetadataFile ResolveModule(MetadataFile mainModule, string moduleName)
        {
            try
            {
                return inner.ResolveModule(mainModule, moduleName);
            }
            catch (Exception ex) when (ex is NotSupportedException or ResolutionException)
            {
                return FallbackResolve(moduleName);
            }
        }

        public Task<MetadataFile?> ResolveModuleAsync(MetadataFile mainModule, string moduleName)
        {
            try
            {
                return inner.ResolveModuleAsync(mainModule, moduleName);
            }
            catch (Exception ex) when (ex is NotSupportedException or ResolutionException)
            {
                return Task.FromResult<MetadataFile?>(FallbackResolve(moduleName));
            }
        }

        MetadataFile? FallbackResolve(string name)
        {
            if (cache.TryGetValue(name, out var cached))
                return cached;

            var fileName = name + ".dll";
            foreach (var path in fallbackPaths)
            {
                var fullPath = Path.Combine(path, fileName);
                if (File.Exists(fullPath))
                {
                    var peFile = new PEFile(fullPath);
                    cache[name] = peFile;
                    return peFile;
                }
            }
            return null;
        }

        public void Dispose()
        {
            if (!disposed)
            {
                cache.Clear();
                disposed = true;
            }
        }
    }
}
