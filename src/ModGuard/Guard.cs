using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using HarmonyLib;
using ModGuard.Core;
using UnityEngine;

namespace ModGuard
{
    internal static class Guard
    {
        private const string AckFile = "ack.txt";
        private const int MaxReportLines = 12;

        private static Blocklist _list;
        private static KnownMods _known;

        private static readonly Dictionary<string, GateResult> Findings = new Dictionary<string, GateResult>(StringComparer.Ordinal);
        private static readonly HashSet<ulong> OwnerQueried = new HashSet<ulong>();
        private static readonly HashSet<string> DuplicateIds = new HashSet<string>(StringComparer.Ordinal);
        private static readonly HashSet<ulong> InstalledWaitingForOwner = new HashSet<ulong>();
        private static readonly Dictionary<string, NativeReport> NativeReports = new Dictionary<string, NativeReport>(StringComparer.OrdinalIgnoreCase);

        private static readonly MethodInfo SelectModMethod = AccessTools.Method(typeof(ModUIManager), "SelectMod");
        private static readonly MethodInfo RefreshRowsMethod = AccessTools.Method(typeof(ModUIManager), "RefreshRowIssues");

        /// <summary>Worth interrupting the player or marking a row for. Trouble with the check itself only matters at the moment of activating.</summary>
        private static bool Reportable(GateResult result)
        {
            return (result.Action == GateAction.Block || result.Action == GateAction.Prompt)
                && result.Key != "gate_unverified" && result.Key != "gate_error" && result.Key != "gate_list_broken";
        }

        internal static bool EnsureLoaded()
        {
            if (_list != null)
            {
                return true;
            }
            if (!SelfCheck.Run())
            {
                return false;
            }
            // A changed list could be empty, or could name innocent mods. Neither may be acted on.
            _list = SelfCheck.DataTrusted ? ReadList() : Blocklist.Broken("Mod Guard's own files were changed");
            _known = SelfCheck.DataTrusted ? ReadKnown() : new KnownMods();
            _known.AddGuard(ModEntry.Id, SelfData.OfficialItem, SelfData.OfficialPublisher);
            Debug.Log("[ModGuard] List loaded: " + _list.Count + " entries, " + _known.Count + " known mods.");
            foreach (string error in _list.Errors.Concat(_known.Errors))
            {
                Debug.LogWarning("[ModGuard] " + error);
            }
            return true;
        }

        private static Blocklist ReadList()
        {
            try
            {
                string json = ModHelper.ReadModFileText(ModEntry.Id, "blocklist.json");
                return json != null ? Blocklist.Parse(json) : Blocklist.Broken("blocklist.json is missing");
            }
            catch (Exception ex)
            {
                return Blocklist.Broken(ex.Message);
            }
        }

        private static KnownMods ReadKnown()
        {
            try
            {
                return KnownMods.Parse(ModHelper.ReadModFileText(ModEntry.Id, "known_mods.json"));
            }
            catch (Exception ex)
            {
                var known = new KnownMods();
                known.Errors.Add(ex.Message);
                return known;
            }
        }

        internal static GateResult InspectForEnable(LoadedMod mod)
        {
            if (!EnsureLoaded())
            {
                throw new InvalidOperationException("the guard's own files are not available");
            }
            // Steam can replace the files while the game runs, so judge what is on disk now, not what was there at startup.
            ModManifest manifest = ModLoader.ParseManifestForTools(mod.FolderPath, out string _) ?? mod.Manifest;
            // Hashing can be slow on a huge file, so it only happens on an explicit click, and only if the list uses it.
            ModFingerprint fingerprint = _list.HasVersionEntries ? ModFingerprint.Compute(mod.FolderPath, manifest) : null;
            return Decide(mod, manifest, fingerprint?.Combined, fingerprint?.Files.Select(f => f.hash), ReadNative(mod, manifest));
        }

        /// <summary>Reads the mod's DLLs as bytes through the game's own helper and only parses their metadata, so nothing from them runs.</summary>
        private static NativeReport ReadNative(LoadedMod mod, ModManifest manifest)
        {
            var imports = new List<(string, string)>();
            var fileHashes = new List<string>();
            bool unreadable = false;
            int entryPoints = 0;
            foreach (string relative in manifest.Assemblies)
            {
                try
                {
                    byte[] bytes = ModHelper.ReadModFileBytes(mod.Manifest.ID, relative);
                    if (bytes != null)
                    {
                        DllInfo info = NativeImports.ReadDll(bytes);
                        imports.AddRange(info.Imports);
                        entryPoints += info.EntryPoints;
                        fileHashes.Add(info.Sha256);
                    }
                }
                catch (Exception ex)
                {
                    unreadable = true;
                    Debug.LogWarning("[ModGuard] Could not read " + relative + " of '" + mod.Manifest.ID + "': " + ex.Message);
                }
            }
            NativeReport report = NativeImports.Assess(imports, manifest.Capabilities.Contains("network"));
            report.Unreadable = unreadable;
            report.EntryPoints = entryPoints;
            report.FileHashes = fileHashes;
            return report;
        }

        /// <summary>
        /// For the startup pass, where reading every mod would let one huge file stall the menu. Mods skipped here are
        /// still read on an explicit click. They can skip this because the game refuses undeclared imports and runs only
        /// one class per DLL, and the known loaders all come as a second DLL declaring "native".
        /// </summary>
        private static NativeReport CachedNative(LoadedMod mod)
        {
            if (!mod.Manifest.Capabilities.Contains("native") && mod.Manifest.Assemblies.Count < 2)
            {
                return null;
            }
            string key = mod.FolderPath ?? mod.Manifest.ID;
            if (!NativeReports.TryGetValue(key, out NativeReport report))
            {
                report = ReadNative(mod, mod.Manifest);
                NativeReports[key] = report;
            }
            return report;
        }

        private static GateResult Decide(LoadedMod mod, ModManifest manifest, string versionHash, IEnumerable<string> fileHashes, NativeReport native)
        {
            ulong item = mod.Source == ModSource.Workshop ? mod.WorkshopId : 0;
            ulong owner = 0;
            bool finished = true;
            if (item != 0 && !ModWorkshop.TryGetOwner(item, out owner))
            {
                finished = OwnerQueryFinished(item);
            }

            ModTrustRecord record = mod.TrustRecord;
            bool comparable = item != 0 && record != null && record.source == ModSource.Workshop.ToString();
            return Gate.Decide(new GateInput
            {
                Item = item,
                Owner = owner,
                OwnerQueryFinished = finished,
                VersionHash = versionHash,
                FileHashes = fileHashes,
                ModId = manifest.ID,
                ModName = manifest.Name,
                ModAuthor = manifest.Author,
                ApprovedItem = comparable ? record.workshopId : null,
                Native = native,
            }, _list, _known);
        }

        private static bool OwnerQueryFinished(ulong item)
        {
            if (!ModWorkshop.IsAvailable || ModWorkshop.HasDetails(item))
            {
                return true;
            }
            if (ModWorkshop.IsDetailsPending(item))
            {
                return false;
            }
            if (OwnerQueried.Add(item))
            {
                ModWorkshop.RequestDetails(new[] { item });
                return false;
            }
            return true;
        }

        /// <summary>The game adds one entry per DLL that has a mod class, so a mod can appear twice. Malicious ones here do.</summary>
        private static List<LoadedMod> OtherMods()
        {
            return ModLoader.Mods
                .Where(m => m?.Manifest != null && m.Manifest.ID != ModEntry.Id)
                .GroupBy(m => m.Manifest.ID)
                .Select(g => g.FirstOrDefault(m => m.IsEnabled) ?? g.First())
                .ToList();
        }

        private static void Refresh()
        {
            if (!EnsureLoaded())
            {
                return;
            }
            Findings.Clear();
            foreach (LoadedMod mod in OtherMods())
            {
                // Only hashes the game already computed: reading every mod's files here would let a huge file stall the menu.
                Findings[mod.Manifest.ID] = Decide(mod, mod.Manifest, mod.Fingerprint?.Combined, mod.Fingerprint?.Files.Select(f => f.hash), CachedNative(mod));
            }
        }

        private static void FindDuplicateIds()
        {
            DuplicateIds.Clear();
            var seen = new HashSet<string>(StringComparer.Ordinal);
            foreach ((ulong _, string folder) in ModWorkshop.GetInstalledItems())
            {
                ModManifest manifest = ModLoader.ParseManifestForTools(folder, out string _);
                if (manifest != null && !seen.Add(manifest.ID))
                {
                    DuplicateIds.Add(manifest.ID);
                }
            }
        }

        internal static void OnDetailsUpdated()
        {
            try
            {
                Refresh();
                // The loader's own listener runs before this one, so the menu has already redrawn without these findings.
                if (ModUIManager.Instance != null)
                {
                    RefreshRowsMethod.Invoke(ModUIManager.Instance, null);
                }
                foreach (ulong item in InstalledWaitingForOwner.ToList())
                {
                    if (ModWorkshop.TryGetOwner(item, out ulong owner))
                    {
                        InstalledWaitingForOwner.Remove(item);
                        WarnIfListed(item, owner);
                    }
                }
            }
            catch (Exception ex)
            {
                Debug.LogError("[ModGuard] Refresh failed: " + ex);
            }
        }

        /// <summary>Fires when Steam finishes a download while the game is open. The item cannot run before it is activated.</summary>
        internal static void OnItemInstalled(ulong item)
        {
            try
            {
                if (!EnsureLoaded())
                {
                    return;
                }
                // The files may have just changed.
                NativeReports.Clear();
                if (ModWorkshop.TryGetOwner(item, out ulong owner))
                {
                    WarnIfListed(item, owner);
                    return;
                }
                if (!WarnIfListed(item, 0))
                {
                    InstalledWaitingForOwner.Add(item);
                    ModWorkshop.RequestDetails(new[] { item });
                }
            }
            catch (Exception ex)
            {
                Debug.LogError("[ModGuard] Could not check the new item " + item + ": " + ex);
            }
        }

        private static bool WarnIfListed(ulong item, ulong owner)
        {
            (string name, IEnumerable<string> hashes) = InspectInstalled(item);
            Entry entry = _list.Match(item, owner, null, hashes);
            if (entry == null)
            {
                return false;
            }
            Dialog.Show(ModEntry.L("installed_head"), ModEntry.L("installed_body", item, ReasonText(entry), entry.Case, name),
                danger: entry.Level == Level.Confirmed, Dialog.CloseButton());
            return true;
        }

        /// <summary>A new item is not in the game's mod list yet, so its file hashes come from the game's fingerprint helper.</summary>
        private static (string name, IEnumerable<string> hashes) InspectInstalled(ulong item)
        {
            foreach ((ulong id, string folder) in ModWorkshop.GetInstalledItems())
            {
                if (id == item)
                {
                    ModManifest manifest = ModLoader.ParseManifestForTools(folder, out string _);
                    return manifest == null
                        ? ("?", null)
                        : (TextSafe.Clean(manifest.Name), ModFingerprint.Compute(folder, manifest).Files.Select(f => f.hash).ToList());
                }
            }
            return ("?", null);
        }

        internal static void RunStartupReport()
        {
            try
            {
                if (!EnsureLoaded())
                {
                    return;
                }
                Refresh();
                FindDuplicateIds();
                ShowStartupReport();
            }
            catch (Exception ex)
            {
                Debug.LogError("[ModGuard] Startup report failed: " + ex);
            }
        }

        private static void ShowStartupReport()
        {
            HashSet<string> acked = ReadAcks();
            var lines = new List<string>();
            var newAcks = new List<string>();
            string focus = null;
            bool activeMalicious = false;
            int maliciousLines = 0;
            var maliciousNames = new List<string>();
            bool duplicateGuard = false;

            // Shown on every launch, never remembered as seen: a fake copy must not be able to go quiet.
            List<string> selfLines = SelfLines();
            if (selfLines.Count > 0)
            {
                focus = ModEntry.Id;
            }
            // After an update during the session the old DLL may not read the new list. "Reinstall" would be wrong
            // advice then: the next launch runs the new DLL.
            else if (_list.IsBroken && !SelfCheck.UpdatedSinceLoad)
            {
                lines.Add(ModEntry.L("report_list_broken"));
            }
            else if (_list.IsBroken)
            {
                Debug.LogWarning("[ModGuard] The list from the update cannot be read by the running version; it is used after a restart.");
            }

            foreach (LoadedMod mod in OtherMods())
            {
                if (!Findings.TryGetValue(mod.Manifest.ID, out GateResult result) || !Reportable(result))
                {
                    continue;
                }
                bool active = ModLoader.IsModEnabled(mod.Manifest.ID);
                bool malicious = active && result.Action == GateAction.Block;
                string ack = Gate.AckKey(result, mod.Manifest.ID, mod.WorkshopId, active);
                if (!malicious && acked.Contains(ack))
                {
                    continue;
                }
                newAcks.Add(ack);

                string name = TextSafe.Clean(mod.Manifest.Name);
                string why = WhyText(result);
                if (malicious)
                {
                    // The first active malicious mod matters more than anything else in the report, including a fake guard.
                    if (!activeMalicious)
                    {
                        focus = mod.Manifest.ID;
                    }
                    activeMalicious = true;
                    maliciousNames.Add(name);
                    lines.Insert(maliciousLines++, ModEntry.L("report_active_malicious", name, SourceText(mod), why, result.Entry?.Case ?? "-"));
                }
                else if (active)
                {
                    focus = focus ?? mod.Manifest.ID;
                    lines.Add(ModEntry.L("report_active_warning", name, SourceText(mod), why));
                }
                else
                {
                    lines.Add(ModEntry.L("report_inactive", name, SourceText(mod), why));
                }
            }

            foreach (string id in DuplicateIds)
            {
                // A second item with the guard's own id is the guard being imitated, so it is never remembered as seen.
                if (id == ModEntry.Id)
                {
                    duplicateGuard = true;
                    lines.Insert(maliciousLines, ModEntry.L("report_duplicate_guard"));
                    continue;
                }
                string ack = "duplicate:" + id;
                if (!acked.Contains(ack))
                {
                    newAcks.Add(ack);
                    lines.Add(ModEntry.L("report_duplicate", TextSafe.Clean(id)));
                }
            }

            // The language files are what changed, so each line would come out as the same generic paragraph.
            // Sum them up in built-in words instead; the names come from manifests and are already cleaned.
            if (!SelfCheck.TextTrusted)
            {
                var summary = new List<string>();
                if (maliciousNames.Count > 0)
                {
                    summary.Add(SelfText.Get("self_active_malicious", string.Join(SelfText.Get("list_sep"), maliciousNames)));
                }
                // A copy of the guard itself is the one warning that must not disappear into a count.
                if (duplicateGuard)
                {
                    summary.Add(SelfText.Get("self_duplicate_guard"));
                }
                int others = lines.Count - maliciousNames.Count - (duplicateGuard ? 1 : 0);
                if (others > 0)
                {
                    summary.Add(SelfText.Get("self_more", others));
                }
                lines = summary;
            }

            if (lines.Count == 0 && selfLines.Count == 0)
            {
                return;
            }

            int hidden = lines.Count - MaxReportLines;
            if (hidden > 0)
            {
                lines = lines.Take(MaxReportLines).ToList();
                lines.Add(ModEntry.L("report_more", hidden));
            }
            if (activeMalicious && SelfCheck.TextTrusted)
            {
                lines.Add(ModEntry.L("report_advice"));
            }

            string body = string.Join("\n\n", selfLines.Concat(lines));
            string heading = selfLines.Count > 0 ? SelfText.Get("self_head") : ModEntry.L("report_head");
            string target = focus;
            // In the summary the player never read the individual warnings, so none of them count as seen.
            Action rememberAcks = SelfCheck.TextTrusted ? () => WriteAcks(acked, newAcks) : (Action)null;
            var buttons = new List<(string, Action)>();
            if (MainMenuUIController.Instance != null)
            {
                buttons.Add((ModEntry.L("btn_open_menu"), () =>
                {
                    Dialog.Close();
                    OpenMenuAt(target);
                }));
            }
            buttons.Add(Dialog.CloseButton());
            Dialog.Show(heading, body, activeMalicious || selfLines.Count > 0, rememberAcks, buttons.ToArray());
        }

        /// <summary>What the self-check found, in the built-in wording, since the language files may be what changed.</summary>
        private static List<string> SelfLines()
        {
            var lines = new List<string>();
            SelfReport report = SelfCheck.Report;
            if (report != null && !report.Ok)
            {
                lines.Add(SelfText.Get("self_files", string.Join(", ", report.Problems)));
                if (!report.TextTrusted)
                {
                    lines.Add(SelfText.Get("self_text"));
                }
            }
            if (SelfCheck.UnofficialItem is ulong item)
            {
                string where = item != 0 ? SelfText.Get("source_workshop", item) : SelfText.Get("source_local");
                lines.Add(SelfText.Get("self_identity", where, SelfData.OfficialItem));
            }
            if (lines.Count > 0)
            {
                lines.Add(SelfText.Get("self_advice"));
            }
            return lines;
        }

        private static void OpenMenuAt(string modId)
        {
            try
            {
                MainMenuUIController.Instance?.OpenModPanel();
                if (modId != null && ModUIManager.Instance != null)
                {
                    SelectModMethod.Invoke(ModUIManager.Instance, new object[] { modId });
                }
            }
            catch (Exception ex)
            {
                Debug.LogError("[ModGuard] Could not open the mod menu: " + ex);
            }
        }

        private static HashSet<string> ReadAcks()
        {
            try
            {
                string text = ModHelper.ReadModDataFileText(ModEntry.Id, AckFile);
                if (text != null)
                {
                    return new HashSet<string>(text.Split('\n').Select(s => s.Trim()).Where(s => s.Length > 0), StringComparer.Ordinal);
                }
            }
            catch (Exception ex)
            {
                Debug.LogWarning("[ModGuard] Could not read the seen-warnings file: " + ex.Message);
            }
            return new HashSet<string>(StringComparer.Ordinal);
        }

        private static void WriteAcks(HashSet<string> existing, List<string> added)
        {
            try
            {
                ModHelper.WriteModDataFileText(ModEntry.Id, AckFile, string.Join("\n", existing.Concat(added).Distinct()));
            }
            catch (Exception ex)
            {
                Debug.LogWarning("[ModGuard] Could not save the seen-warnings file: " + ex.Message);
            }
        }

        internal static string IssueFor(LoadedMod mod)
        {
            if (mod?.Manifest == null)
            {
                return null;
            }
            var parts = new List<string>();
            if (Findings.TryGetValue(mod.Manifest.ID, out GateResult result) && Reportable(result))
            {
                parts.Add(WhyText(result));
            }
            if (DuplicateIds.Contains(mod.Manifest.ID))
            {
                parts.Add(ModEntry.L("why_duplicate"));
            }
            return parts.Count == 0 ? null : ModEntry.L("issue_line", string.Join(" ", parts));
        }

        internal static string Describe(LoadedMod mod, GateResult result)
        {
            string name = TextSafe.Clean(mod.Manifest.Name);
            string reason = result.Entry != null ? ReasonText(result.Entry) : TextSafe.Clean(result.Detail, 200);
            string caseId = result.Entry?.Case ?? "-";
            string approved = TextSafe.Clean(mod.TrustRecord?.workshopId);
            return ModEntry.L(result.Key + "_body", name, SourceText(mod), reason, caseId, approved);
        }

        /// <summary>Where the mod comes from, as shown next to its name. A local mod has no Workshop item to name.</summary>
        private static string SourceText(LoadedMod mod)
        {
            ulong item = mod.Source == ModSource.Workshop ? mod.WorkshopId : 0;
            return item != 0 ? ModEntry.L("source_workshop", item) : ModEntry.L("source_local");
        }

        private static string ReasonText(Entry entry)
        {
            return ModEntry.L("reason_" + entry.Reason);
        }

        private static string WhyText(GateResult result)
        {
            if (result.Entry != null)
            {
                return ReasonText(result.Entry);
            }
            return ModEntry.L(result.Key.Replace("gate_", "why_"));
        }
    }
}
