using System;
using System.Linq;
using ModGuard.Core;
using UnityEngine;

namespace ModGuard
{
    /// <summary>
    /// What this copy of the guard can say about itself. Mod Guard is open source and players trust it, so it is the
    /// most useful thing to imitate. A changed DLL can remove all of this, which is why the README publishes the
    /// official item and the DLL hash. What this does catch is the cheap fake: the original DLL re-uploaded under
    /// another item, or shipped with changed files or extra DLLs beside it.
    /// </summary>
    internal static class SelfCheck
    {
        private const string DllName = "ModGuard.dll";

        private static SelfReport _report;

        internal static SelfReport Report => _report;

        /// <summary>The guard's own entry in the game's mod list, once Run has found it.</summary>
        internal static LoadedMod Self { get; private set; }

        /// <summary>Steam replaced the files during this session. The running DLL then works with the new files until a restart.</summary>
        internal static bool UpdatedSinceLoad { get; private set; }

        /// <summary>Workshop item this copy runs from (0 for a local mod) when that is not the official item. Null otherwise.</summary>
        internal static ulong? UnofficialItem { get; private set; }

        internal static bool TextTrusted => _report?.TextTrusted ?? true;
        internal static bool DataTrusted => _report?.DataTrusted ?? true;

        /// <summary>False until the game has registered this mod, since only then can it read its own files.</summary>
        internal static bool Run()
        {
            if (_report != null)
            {
                return true;
            }
            LoadedMod self = ModLoader.Mods.Find(m => m?.Manifest?.ID == ModEntry.Id);
            if (self == null)
            {
                return false;
            }
            Self = self;

            SelfReport report = SelfFiles.Check(
                SelfData.Files.Select(f => (f[0], f[1])),
                path => ModHelper.ReadModFileBytes(ModEntry.Id, path),
                self.Localization?.Keys);
            if (!report.Ok)
            {
                string loadedDll = self.Fingerprint?.Files.FirstOrDefault(f => string.Equals(f.path, DllName, StringComparison.OrdinalIgnoreCase)).hash;
                if (SelfFiles.ReplacedSinceLoad(loadedDll, () => ModHelper.ReadModFileBytes(ModEntry.Id, DllName)))
                {
                    // An update, not a repack: the files beside the DLL are the new release. Use them as they are;
                    // the next launch loads the new DLL, which checks them properly.
                    Debug.Log("[ModGuard] Steam updated Mod Guard while the game was running (" + string.Join(", ", report.Problems)
                        + "). Its files are checked again after a restart.");
                    UpdatedSinceLoad = true;
                    report = new SelfReport();
                }
                else
                {
                    Debug.LogError("[ModGuard] Own files differ from the release: " + string.Join(", ", report.Problems)
                        + (report.DataTrusted ? "" : ". The list is not used.") + (report.TextTrusted ? "" : ". Built-in messages only."));
                }
            }
            _report = report;

            // 0 means this build has no official item yet, so there is nothing to compare with.
            if (SelfData.OfficialItem != 0)
            {
                ulong item = self.Source == ModSource.Workshop ? self.WorkshopId : 0;
                if (item != SelfData.OfficialItem)
                {
                    UnofficialItem = item;
                    Debug.LogWarning("[ModGuard] This copy runs from " + (item == 0 ? "a local folder" : "Workshop item " + item)
                        + ", not from the official item " + SelfData.OfficialItem + ".");
                }
            }
            return true;
        }
    }
}
