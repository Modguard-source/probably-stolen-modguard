using System;
using System.Collections.Generic;
using System.Linq;

namespace ModGuard.Core
{
    public sealed class SelfReport
    {
        public readonly List<string> Changed = new List<string>();
        public readonly List<string> Missing = new List<string>();
        /// <summary>Language files the release did not ship. The game loads every csv in the folder.</summary>
        public readonly List<string> Extra = new List<string>();

        /// <summary>The messages can be shown as written: no language file was changed, removed or added.</summary>
        public bool TextTrusted = true;
        /// <summary>The manifest and the lists are the ones the release shipped.</summary>
        public bool DataTrusted = true;

        public bool Ok => Changed.Count == 0 && Missing.Count == 0 && Extra.Count == 0;

        public IEnumerable<string> Problems => Changed.Concat(Missing).Concat(Extra);
    }

    /// <summary>
    /// Compares the guard's own files with the hashes the build wrote into the DLL. The DLL cannot vouch for itself,
    /// so this catches exactly one kind of fake: the original DLL shipped with changed files beside it, such as an
    /// emptied list, a list that names innocent mods, or messages rewritten to send players somewhere.
    /// A changed DLL can skip this check; that is what the published DLL hash is for.
    /// </summary>
    public static class SelfFiles
    {
        public const string LocalizationFolder = "Localization/";

        /// <summary>
        /// True when the DLL on disk is no longer the one the game loaded, which is what Steam updating the mod while
        /// the game runs looks like: the running DLL then carries the old hashes and the files beside it are the new
        /// release. Without this, every update would show every player the "altered" warning. A repack cannot use it,
        /// because a copy that is packed and then started loads the very DLL that is on disk. Something that can change
        /// files during the session is already running code on the machine, which no mod can defend against.
        /// </summary>
        public static bool ReplacedSinceLoad(string loadedDllHash, Func<byte[]> readDiskDll)
        {
            // The game hashed the DLL when it loaded it. Without that there is nothing to compare, so stay strict.
            if (string.IsNullOrEmpty(loadedDllHash) || loadedDllHash == "missing")
            {
                return false;
            }
            byte[] disk;
            try
            {
                disk = readDiskDll();
            }
            catch (Exception)
            {
                // Locked or half-written: Steam is replacing it right now.
                return true;
            }
            return disk == null || !string.Equals(NativeImports.Sha256Hex(disk), loadedDllHash, StringComparison.OrdinalIgnoreCase);
        }

        public static SelfReport Check(IEnumerable<(string path, string sha256)> expected, Func<string, byte[]> read, IEnumerable<string> languages)
        {
            var report = new SelfReport();
            var shippedLanguages = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach ((string path, string sha256) in expected)
            {
                bool text = path.StartsWith(LocalizationFolder, StringComparison.OrdinalIgnoreCase);
                if (text && path.EndsWith(".csv", StringComparison.OrdinalIgnoreCase))
                {
                    shippedLanguages.Add(path.Substring(LocalizationFolder.Length, path.Length - LocalizationFolder.Length - 4));
                }

                byte[] bytes;
                try
                {
                    bytes = read(path);
                }
                catch (Exception)
                {
                    bytes = null;
                }

                bool bad;
                if (bytes == null)
                {
                    report.Missing.Add(path);
                    bad = true;
                }
                else if (!string.Equals(NativeImports.Sha256Hex(bytes), sha256, StringComparison.OrdinalIgnoreCase))
                {
                    report.Changed.Add(path);
                    bad = true;
                }
                else
                {
                    bad = false;
                }

                if (bad && text)
                {
                    report.TextTrusted = false;
                }
                else if (bad)
                {
                    report.DataTrusted = false;
                }
            }

            foreach (string language in languages ?? Enumerable.Empty<string>())
            {
                if (!shippedLanguages.Contains(language ?? ""))
                {
                    report.Extra.Add(LocalizationFolder + TextSafe.Clean(language, 40) + ".csv");
                    report.TextTrusted = false;
                }
            }
            return report;
        }
    }
}
