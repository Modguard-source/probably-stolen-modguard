using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using DseCecil;

namespace ModGuard.Core
{
    public enum NativeRisk
    {
        None,
        /// <summary>One suspicious ability on its own. Rare in a mod, but not proof.</summary>
        Risky,
        /// <summary>Can both fetch something from the internet and start a program.</summary>
        Dropper,
    }

    /// <summary>What can be learned from one DLL without running any of it.</summary>
    public sealed class DllInfo
    {
        public List<(string module, string entry)> Imports = new List<(string, string)>();
        public int EntryPoints;
        public string Sha256;
    }

    public sealed class NativeReport
    {
        public NativeRisk Risk;
        public List<string> Findings = new List<string>();
        /// <summary>A listed DLL could not be read, so this report may be missing something.</summary>
        public bool Unreadable;
        /// <summary>Mod classes across the listed DLLs. The game runs one from each DLL, so a loader packed beside a normal mod shows up here.</summary>
        public int EntryPoints;
        public List<string> FileHashes = new List<string>();

        public string Summary => string.Join(", ", Findings);
    }

    /// <summary>
    /// Reads which Windows functions a DLL imports, without loading it. The game forbids mods from starting programs
    /// and enforces that on Process.Start, but a direct import of the Windows functions only counts as the "native"
    /// capability. Real malware on this Workshop uses exactly that, and this rule needs no list entry, so it still
    /// applies to a re-upload from a new account. It is not hard to evade (a mod can look functions up at run time,
    /// which only reaches Risky), so it adds to the list and does not replace it.
    /// </summary>
    public static class NativeImports
    {
        private static readonly string[] NetworkModules = { "urlmon", "wininet", "winhttp", "ws2_32", "wsock32" };

        private static readonly (string module, string prefix)[] LaunchFunctions =
        {
            ("shell32", "shellexecute"),
            ("kernel32", "createprocess"),
            ("kernel32", "winexec"),
            ("advapi32", "createprocess"),
            ("ntdll", "ntcreateuserprocess"),
            ("ntdll", "ntcreateprocess"),
            ("ntdll", "rtlcreateuserprocess"),
            // Running code inside another program is the same ability by a different road.
            ("kernel32", "createremotethread"),
            ("kernel32", "virtualallocex"),
            ("kernel32", "writeprocessmemory"),
            ("kernel32", "queueuserapc"),
            ("ntdll", "ntcreatethreadex"),
            ("user32", "setwindowshookex"),
        };

        /// <summary>The COM calls that can start a program without any of the functions above.</summary>
        private static readonly (string module, string prefix)[] ComFunctions =
        {
            ("ole32", "cocreateinstance"),
            ("ole32", "clsidfromprogid"),
            ("ole32", "cogetclassobject"),
            ("combase", "cocreateinstance"),
        };

        /// <summary>
        /// Worth a question, not enough for a block even beside a network import. A video-playing mod uses these
        /// through WinRT, and most of what combase exports (string helpers, say) is not even asked about.
        /// </summary>
        private static readonly (string module, string prefix)[] ActivationFunctions =
        {
            ("combase", "roactivateinstance"),
            ("combase", "rogetactivationfactory"),
        };

        private static readonly (string module, string prefix)[] LookupFunctions =
        {
            ("kernel32", "loadlibrary"),
            ("kernel32", "getprocaddress"),
            ("ntdll", "ldrloaddll"),
            ("ntdll", "ldrgetprocedureaddress"),
        };

        /// <summary>Only parses metadata, so no code from the DLL can run.</summary>
        public static DllInfo ReadDll(byte[] dll)
        {
            var info = new DllInfo { Sha256 = Sha256Hex(dll) };
            using var stream = new MemoryStream(dll, writable: false);
            using AssemblyDefinition assembly = AssemblyDefinition.ReadAssembly(stream, new ReaderParameters { ReadingMode = ReadingMode.Deferred });
            foreach (ModuleDefinition module in assembly.Modules)
            {
                foreach (TypeDefinition type in module.GetTypes())
                {
                    if (IsModClass(type))
                    {
                        info.EntryPoints++;
                    }
                    foreach (MethodDefinition method in type.Methods)
                    {
                        if (method.HasPInvokeInfo)
                        {
                            info.Imports.Add((method.PInvokeInfo.Module?.Name ?? "", method.PInvokeInfo.EntryPoint ?? method.Name));
                        }
                    }
                }
            }
            return info;
        }

        /// <summary>
        /// Follows base classes, because the game runs anything assignable to IMod. It only follows them inside one DLL:
        /// a base class in another DLL goes uncounted. Counting those instead would flag ordinary multi-part mods, and
        /// this rule only asks a question anyway.
        /// </summary>
        private static bool IsModClass(TypeDefinition type)
        {
            if (type.IsInterface || type.IsAbstract)
            {
                return false;
            }
            // A generic base (class Loader : Base<int>) shows up as an instance type; its element type is the definition.
            for (TypeDefinition current = type; current != null;
                current = current.BaseType as TypeDefinition ?? (current.BaseType as GenericInstanceType)?.ElementType as TypeDefinition)
            {
                if (current.HasInterfaces && current.Interfaces.Any(i => i.InterfaceType.FullName == "IMod"))
                {
                    return true;
                }
            }
            return false;
        }

        internal static string Sha256Hex(byte[] data)
        {
            using SHA256 sha = SHA256.Create();
            var sb = new StringBuilder(64);
            foreach (byte b in sha.ComputeHash(data))
            {
                sb.Append(b.ToString("x2"));
            }
            return sb.ToString();
        }

        /// <param name="imports">What the mod's DLLs import.</param>
        /// <param name="declaresNetwork">The manifest declares "network", so it can download from managed code and needs no network import.</param>
        public static NativeReport Assess(IEnumerable<(string module, string entry)> imports, bool declaresNetwork = false)
        {
            var report = new NativeReport();
            bool network = false;
            bool launch = false;
            bool lookup = false;
            bool com = false;
            bool activation = false;
            foreach ((string rawModule, string rawEntry) in imports)
            {
                string module = ModuleKey(rawModule);
                string entry = (rawEntry ?? "").ToLowerInvariant();
                // An import by ordinal hides the name, so it counts as whatever that module can do.
                bool byOrdinal = entry.StartsWith("#", StringComparison.Ordinal);

                bool isNetwork = NetworkModules.Contains(module);
                bool isLaunch = LaunchFunctions.Any(f => f.module == module && (entry.StartsWith(f.prefix, StringComparison.Ordinal) || byOrdinal));
                bool isLookup = LookupFunctions.Any(f => f.module == module && entry.StartsWith(f.prefix, StringComparison.Ordinal));
                bool isCom = ComFunctions.Any(f => f.module == module && (entry.StartsWith(f.prefix, StringComparison.Ordinal) || byOrdinal));
                bool isActivation = ActivationFunctions.Any(f => f.module == module && entry.StartsWith(f.prefix, StringComparison.Ordinal));
                if (isNetwork || isLaunch || isLookup || isCom || isActivation)
                {
                    string finding = module + "!" + rawEntry;
                    if (!report.Findings.Contains(finding))
                    {
                        report.Findings.Add(finding);
                    }
                }
                network |= isNetwork;
                launch |= isLaunch;
                lookup |= isLookup;
                com |= isCom;
                activation |= isActivation;
            }

            // Can fetch something and can run something. Hiding which function will run it (a run-time lookup, COM)
            // does not make the combination any more innocent.
            if ((network && (launch || lookup || com)) || (declaresNetwork && launch))
            {
                report.Risk = NativeRisk.Dropper;
            }
            else if (network || launch || lookup || com || activation)
            {
                report.Risk = NativeRisk.Risky;
            }
            return report;
        }

        private static string ModuleKey(string module)
        {
            string name = (module ?? "").Replace('\\', '/');
            int slash = name.LastIndexOf('/');
            if (slash >= 0)
            {
                name = name.Substring(slash + 1);
            }
            name = name.ToLowerInvariant();
            return name.EndsWith(".dll", StringComparison.Ordinal) ? name.Substring(0, name.Length - 4) : name;
        }
    }
}
