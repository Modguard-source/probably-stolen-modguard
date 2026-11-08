using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.Loader;
using System.Text.RegularExpressions;
using HarmonyLib;
using ModGuard.Core;

// Read as metadata by NativeRules. Nothing uses them and the import never runs.
internal interface IMod
{
}

internal sealed class DirectEntry : IMod
{
}

internal abstract class EntryBase : IMod
{
}

internal sealed class InheritedEntry : EntryBase
{
}

internal abstract class AbstractOnly : IMod
{
}

internal abstract class GenericBase<T> : IMod
{
}

internal sealed class GenericEntry : GenericBase<int>
{
}

internal static class ImportFixture
{
    [System.Runtime.InteropServices.DllImport("urlmon.dll")]
    private static extern int URLDownloadToFileW();
}

// Offline checks. Exit code is the number of failures.
//   CoreTests                    logic and shipped data
//   CoreTests patch <ModGuard.dll>  every [HarmonyPatch] target and argument name, against the game's real assembly
//   CoreTests release [folder]   the folder to upload (default build/content) carries the official identity and
//                                exactly the files its DLL expects (run before every upload, upload only that folder)
internal static class Program
{
    private const string Publisher = "76561198000000001";
    private const string OtherPublisher = "76561198000000002";
    private const string Hash = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    private const string FileHash = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    private static int _failures;
    private static int _passes;

    private static int Main(string[] args)
    {
        if (args.Length == 2 && args[0] == "patch")
        {
            // Has to happen before CheckPatches is compiled, because that method needs Harmony from the game folder.
            string managed = Environment.GetEnvironmentVariable("MODGUARD_MANAGED")
                ?? @"F:\Program Files (x86)\Steam\steamapps\common\Probably Stolen\Probably Stolen_Data\Managed";
            AssemblyLoadContext.Default.Resolving += (context, name) =>
            {
                string path = Path.Combine(managed, name.Name + ".dll");
                bool framework = name.Name == "mscorlib" || name.Name == "netstandard" || name.Name.StartsWith("System", StringComparison.Ordinal);
                return !framework && File.Exists(path) ? context.LoadFromAssemblyPath(path) : null;
            };
            return CheckPatches(args[1], managed);
        }
        if (args.Length == 2 && args[0] == "scan")
        {
            return ScanFolder(args[1]);
        }
        if (args.Length >= 1 && args[0] == "release")
        {
            string folder = args.Skip(1).FirstOrDefault(a => !a.StartsWith("--", StringComparison.Ordinal));
            return ReleaseCheck(Path.GetFullPath(folder ?? Path.Combine(RepoRoot(), "build", "content")), args.Contains("--first-upload"));
        }
        NativeRules();
        ParsingRejectsBadEntries();
        MatchingUsesOnlySteamValues();
        GateDecisions();
        AckKeys();
        TextIsCleaned();
        ImitationNeedsADifferentOwner();
        FakeGuardsAreNamed();
        SelfFilesAreChecked();
        ShippedData();
        Console.WriteLine($"{_passes} passed, {_failures} failed");
        return _failures;
    }

    private static void Check(bool condition, string name)
    {
        if (condition)
        {
            _passes++;
        }
        else
        {
            _failures++;
            Console.WriteLine("FAIL: " + name);
        }
    }

    private static string One(string kind, string value, string level = "confirmed", string reason = "malware_confirmed", string caseId = "2026-0001", string added = "2026-11-08")
    {
        return $"{{\"kind\":\"{kind}\",\"value\":\"{value}\",\"level\":\"{level}\",\"reason\":\"{reason}\",\"case\":\"{caseId}\",\"added\":\"{added}\"}}";
    }

    private static Blocklist List(params string[] entries)
    {
        return Blocklist.Parse("{\"version\":1,\"entries\":[" + string.Join(",", entries) + "]}");
    }

    private static void NativeRules()
    {
        NativeRisk Risk(params (string, string)[] imports) => NativeImports.Assess(imports).Risk;

        Check(Risk() == NativeRisk.None, "no imports");
        Check(Risk(("user32.dll", "GetAsyncKeyState"), ("kernel32.dll", "GetTickCount")) == NativeRisk.None, "ordinary imports stay silent");

        // The combination the malware on this Workshop actually uses.
        Check(Risk(("urlmon.dll", "URLDownloadToFileW"), ("shell32.dll", "ShellExecuteW")) == NativeRisk.Dropper, "download and start");
        Check(Risk(("urlmon", "URLDownloadToFileA"), ("kernel32", "CreateProcessW")) == NativeRisk.Dropper, "other spellings");
        Check(Risk(("WININET.DLL", "InternetOpenW"), ("KERNEL32.dll", "WinExec")) == NativeRisk.Dropper, "case does not matter");
        Check(Risk(("winhttp.dll", "WinHttpOpen"), ("advapi32.dll", "CreateProcessAsUserW")) == NativeRisk.Dropper, "other families");
        Check(Risk(("C:\\Windows\\System32\\urlmon.dll", "URLDownloadToFileW"), ("shell32.dll", "ShellExecuteW")) == NativeRisk.Dropper, "a path does not hide the module");
        Check(Risk(("urlmon.dll", "#7"), ("shell32.dll", "#20")) == NativeRisk.Dropper, "imports by ordinal count");

        Check(Risk(("shell32.dll", "ShellExecuteW")) == NativeRisk.Risky, "start alone only asks");
        Check(Risk(("urlmon.dll", "URLDownloadToFileW")) == NativeRisk.Risky, "download alone only asks");
        Check(Risk(("kernel32.dll", "LoadLibraryW"), ("kernel32.dll", "GetProcAddress")) == NativeRisk.Risky, "run-time lookup only asks");
        Check(Risk(("shell32.dll", "SHGetKnownFolderPath")) == NativeRisk.None, "other shell32 functions stay silent");

        // Cheap ways around the first rule: hiding the function that runs the download.
        Check(Risk(("urlmon.dll", "URLDownloadToFileW"), ("kernel32.dll", "GetProcAddress")) == NativeRisk.Dropper, "download plus run-time lookup");
        Check(Risk(("winhttp.dll", "WinHttpOpen"), ("ole32.dll", "CoCreateInstance")) == NativeRisk.Dropper, "download plus COM");
        Check(Risk(("ole32.dll", "CoCreateInstance")) == NativeRisk.Risky, "COM alone only asks");
        Check(Risk(("oleaut32.dll", "SysAllocString")) == NativeRisk.None, "COM string helpers stay silent");
        Check(Risk(("combase.dll", "WindowsCreateString")) == NativeRisk.None, "WinRT string helpers stay silent");
        Check(Risk(("combase.dll", "RoGetActivationFactory")) == NativeRisk.Risky, "WinRT activation only asks");
        Check(Risk(("winhttp.dll", "WinHttpOpen"), ("combase.dll", "RoGetActivationFactory")) == NativeRisk.Risky, "WinRT beside a network import is not a block");
        Check(Risk(("winhttp.dll", "WinHttpOpen"), ("combase.dll", "WindowsCreateString")) == NativeRisk.Risky, "string helpers beside a network import are not a block");

        // Real metadata, from the fixtures at the end of this file.
        byte[] self = File.ReadAllBytes(typeof(Program).Assembly.Location);
        DllInfo own = NativeImports.ReadDll(self);
        Check(own.EntryPoints == 3, "mod classes are counted through a base class, generic ones too, abstract ones are not: " + own.EntryPoints);
        Check(own.Imports.Any(i => i.module == "urlmon.dll" && i.entry == "URLDownloadToFileW"), "imports are read");
        Check(own.Sha256 == Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(self)).ToLowerInvariant(), "file hash is a sha-256 of the bytes");
        Check(Risk(("kernel32.dll", "CreateRemoteThread")) == NativeRisk.Risky, "injection counts as starting something");
        Check(Risk(("user32.dll", "SetWindowsHookExW"), ("ws2_32.dll", "connect")) == NativeRisk.Dropper, "hook plus network");
        Check(NativeImports.Assess(new[] { ("shell32.dll", "ShellExecuteW") }, declaresNetwork: true).Risk == NativeRisk.Dropper, "managed download plus native start");
        Check(NativeImports.Assess(new[] { ("kernel32.dll", "GetTickCount") }, declaresNetwork: true).Risk == NativeRisk.None, "declaring network alone is fine");

        Blocklist empty = List();
        var dropper = new NativeReport { Risk = NativeRisk.Dropper, Findings = { "urlmon!URLDownloadToFileW" } };
        GateResult blocked = Gate.Decide(new GateInput { Item = 100, Owner = 7, Native = dropper, ModId = "a", ModName = "a" }, empty, null);
        Check(blocked.Action == GateAction.Block && blocked.Key == "gate_native_dropper", "dropper blocks without a list entry");
        Check(blocked.Detail == "urlmon!URLDownloadToFileW", "dropper names the functions");
        // The moment a new upload's publisher is still unknown must not be a way past a publisher block.
        Blocklist byPublisher = List(One("publisher", Publisher));
        var askOnly = new NativeReport { Risk = NativeRisk.Risky, Findings = { "shell32!ShellExecuteW" } };
        Check(Decide(byPublisher, owner: 0, finished: false, native: askOnly).Action == GateAction.Wait, "unknown publisher waits before offering a way through");
        Check(Decide(byPublisher, owner: 0, finished: false, native: new NativeReport { EntryPoints = 2 }).Action == GateAction.Wait, "same for several entry points");
        Check(Decide(List(One("publisher", Publisher), One("item", "100", "suspect", "mass_reupload")), owner: 0, finished: false).Action == GateAction.Wait, "same for a suspect item");
        Check(Decide(byPublisher, owner: 0, finished: true, native: askOnly).Action == GateAction.Prompt, "after Steam has answered it asks");
        Check(Decide(byPublisher, owner: 0, finished: false, native: dropper).Action == GateAction.Block, "a block needs no waiting");
        Check(Decide(empty, owner: 0, finished: false, native: askOnly).Action == GateAction.Prompt, "no publisher entries, nothing to wait for");
        Check(Decide(List(One("file", FileHash)), native: new NativeReport { FileHashes = { FileHash } }).Action == GateAction.Block, "hashes read from the DLLs match file entries");

        var twoEntries = new NativeReport { EntryPoints = 2 };
        GateResult multi = Gate.Decide(new GateInput { Item = 100, Owner = 7, Native = twoEntries, ModId = "a", ModName = "a" }, empty, null);
        Check(multi.Action == GateAction.Prompt && multi.Key == "gate_multi_entry" && multi.Detail == "2", "several entry points only ask");
        Check(Gate.Decide(new GateInput { Item = 100, Owner = 7, Native = new NativeReport { EntryPoints = 1 }, ModId = "a", ModName = "a" }, empty, null).Action == GateAction.Allow, "one entry point stays silent");
        Check(Gate.Decide(new GateInput { Item = 100, Owner = 7, Native = new NativeReport { Risk = NativeRisk.Dropper, EntryPoints = 2 }, ModId = "a", ModName = "a" }, empty, null).Action == GateAction.Block, "several entry points do not soften a block");

        // A softer list verdict must not hide what the files show.
        GateResult suspectDropper = Gate.Decide(new GateInput { Item = 100, Owner = 7, Native = dropper, ModId = "a", ModName = "a" }, List(One("item", "100", "suspect", "mass_reupload")), null);
        Check(suspectDropper.Action == GateAction.Block && suspectDropper.Key == "gate_native_dropper", "a suspect entry does not soften the import rule");
        Check(Gate.Decide(new GateInput { Item = 100, Owner = 7, Native = new NativeReport { Unreadable = true }, ModId = "a", ModName = "a" }, empty, null).Key == "gate_error", "unreadable files are not silent");
        Check(Gate.Decide(new GateInput { Item = 100, Owner = 0, OwnerQueryFinished = false, Native = dropper, ModId = "a", ModName = "a" }, empty, null).Action == GateAction.Block, "no waiting for Steam");
        Check(Gate.Decide(new GateInput { Item = 0, Native = dropper, ModId = "a", ModName = "a" }, empty, null).Action == GateAction.Block, "local mods too");
        var risky = new NativeReport { Risk = NativeRisk.Risky, Findings = { "shell32!ShellExecuteW" } };
        Check(Gate.Decide(new GateInput { Item = 100, Owner = 7, Native = risky, ModId = "a", ModName = "a" }, empty, null).Action == GateAction.Prompt, "risky only asks");
        Check(Gate.Decide(new GateInput { Item = 100, Owner = 7, Native = dropper, ModId = "a", ModName = "a" }, List(One("item", "100")), null).Key == "gate_confirmed", "a list entry gives the more specific reason");
    }

    private static int ScanFolder(string folder)
    {
        int dropper = 0, risky = 0, none = 0, unreadable = 0;
        foreach (string item in Directory.GetDirectories(folder).OrderBy(d => d))
        {
            var imports = new List<(string, string)>();
            bool bad = false;
            int entryPoints = 0;
            foreach (string file in Directory.GetFiles(item, "*", SearchOption.AllDirectories))
            {
                byte[] bytes = File.ReadAllBytes(file);
                if (bytes.Length < 2 || bytes[0] != (byte)'M' || bytes[1] != (byte)'Z')
                {
                    continue;
                }
                try
                {
                    DllInfo info = NativeImports.ReadDll(bytes);
                    imports.AddRange(info.Imports);
                    entryPoints += info.EntryPoints;
                }
                catch (Exception ex)
                {
                    bad = true;
                    Console.WriteLine($"  unreadable {Path.GetFileName(file)}: {ex.GetType().Name}");
                }
            }
            NativeReport report = NativeImports.Assess(imports);
            if (bad)
            {
                unreadable++;
            }
            if (report.Risk == NativeRisk.Dropper) dropper++;
            else if (report.Risk == NativeRisk.Risky) risky++;
            else none++;
            Console.WriteLine($"{Path.GetFileName(item)} {report.Risk} imods={entryPoints} {report.Summary}");
        }
        Console.WriteLine($"{dropper} dropper, {risky} risky, {none} none, {unreadable} with an unreadable file");
        return 0;
    }

    private static void ParsingRejectsBadEntries()
    {
        Check(List(One("item", "123")).Count == 1, "valid item");
        Check(List(One("publisher", Publisher)).Count == 1, "valid publisher");
        Check(List(One("version", Hash)).Count == 1, "valid version");
        Check(List(One("version", Hash)).HasVersionEntries, "version entries noticed");
        Check(List(One("file", FileHash)).Count == 1, "valid file");

        // The widest and the most permanent keys need proof, not suspicion.
        Check(List(One("publisher", Publisher, "suspect", "mass_reupload")).Count == 0, "a publisher cannot be merely suspect");
        Check(List(One("file", FileHash, "suspect", "mass_reupload")).Count == 0, "a file cannot be merely suspect");
        Check(List(One("file", "abc")).Count == 0, "file must be a full hash");
        Check(List(One("file", FileHash.ToUpperInvariant())).Count == 0, "file must be lowercase");

        // Values an uploader controls must not be accepted as keys.
        Check(List(One("author", "someone")).Count == 0, "author is not a key");
        Check(List(One("id", "some_mod")).Count == 0, "manifest id is not a key");
        Check(List(One("title", "Some Mod")).Count == 0, "title is not a key");

        Check(List(One("item", "12a")).Count == 0, "item must be numeric");
        Check(List(One("publisher", "123")).Count == 0, "publisher must be a SteamID64");
        Check(List(One("version", "abc")).Count == 0, "version must be a full hash");
        Check(List(One("version", Hash.ToUpperInvariant())).Count == 0, "version must be lowercase");
        Check(List(One("item", "1", level: "safe")).Count == 0, "there is no safe level");
        Check(List(One("item", "1", reason: "see http://evil.example")).Count == 0, "reason must be a known code");
        Check(List(One("item", "1", caseId: "http://evil.example")).Count == 0, "case cannot carry a link");
        Check(List(One("item", "1", caseId: "<b>x</b>")).Count == 0, "case cannot carry markup");
        Check(List(One("item", "1", added: "yesterday")).Count == 0, "added must be a date");

        Blocklist mixed = List(One("item", "1"), One("item", "bad"), One("item", "2"));
        Check(mixed.Count == 2 && mixed.Errors.Count == 1 && !mixed.IsBroken, "one bad entry does not sink the list");

        Check(Blocklist.Parse("not json").IsBroken, "garbage is broken");
        Check(Blocklist.Parse("").IsBroken, "empty is broken");
        Check(Blocklist.Parse(null).IsBroken, "null is broken");
        Check(Blocklist.Parse("{\"version\":2,\"entries\":[]}").IsBroken, "future version is broken");
        Check(Blocklist.Parse("{\"version\":1}").IsBroken, "no entries is broken");
    }

    private static void MatchingUsesOnlySteamValues()
    {
        Blocklist list = List(One("item", "100", "suspect", "mass_reupload"), One("publisher", Publisher), One("version", Hash), One("file", FileHash));
        Check(list.Match(100, 0, null)?.Kind == KeyKind.Item, "item match");
        Check(list.Match(999, 0, null, new[] { "ff", FileHash })?.Kind == KeyKind.File, "file match");
        Check(list.Match(999, 0, null, new[] { FileHash.ToUpperInvariant() })?.Kind == KeyKind.File, "file match ignores case");
        Check(list.Match(999, 0, null, new[] { Hash })?.Kind == null, "a whole-version hash is not a file hash");
        Check(list.Match(999, 0, FileHash) == null, "a file hash is not a whole-version hash");
        Check(list.Match(999, 0, null, new string[] { null, "" }) == null, "empty file hashes do not match");
        Check(list.HasFileEntries && list.HasPublisherEntries, "file and publisher entries noticed");
        Check(List(One("item", "0100")).Match(100, 0, null) != null, "leading zeros still match");
        Check(List(One("item", "0")).Count == 0, "item zero is refused");
        Check(list.Match(999, ulong.Parse(Publisher), null)?.Kind == KeyKind.Publisher, "publisher match");
        Check(list.Match(999, 0, Hash)?.Kind == KeyKind.Version, "version match");
        Check(list.Match(999, 0, Hash.ToUpperInvariant())?.Kind == KeyKind.Version, "version match ignores case");
        Check(list.Match(999, ulong.Parse(OtherPublisher), null) == null, "no match");
        Check(list.Match(0, 0, null) == null, "nothing known, no match");
        Check(list.Match(100, ulong.Parse(Publisher), null)?.Level == Level.Confirmed, "strongest level wins");
        Check(List(One("item", "5", "suspect", "mass_reupload"), One("item", "5")).Match(5, 0, null)?.Level == Level.Confirmed, "duplicate keeps the stronger");
        Check(List(One("item", "5"), One("item", "5", "suspect", "mass_reupload")).Match(5, 0, null)?.Level == Level.Confirmed, "duplicate order does not matter");
    }

    private static GateResult Decide(Blocklist list, KnownMods known = null, ulong item = 100, ulong owner = 7, bool finished = true, string approved = null, string hash = null, string id = "some_mod", string name = "Some Mod", string author = "Someone", NativeReport native = null)
    {
        return Gate.Decide(new GateInput { Item = item, Owner = owner, OwnerQueryFinished = finished, ApprovedItem = approved, VersionHash = hash, ModId = id, ModName = name, ModAuthor = author, Native = native }, list, known);
    }

    private static void GateDecisions()
    {
        Blocklist empty = List();
        Check(Decide(empty).Action == GateAction.Allow, "unlisted stays silent");

        Blocklist confirmed = List(One("item", "100"));
        Check(Decide(confirmed).Action == GateAction.Block, "confirmed blocks");
        Check(Decide(confirmed).Key == "gate_confirmed", "confirmed key");
        Check(Gate.Decide(new GateInput { Item = 999, Owner = 7, FileHashes = new[] { FileHash }, ModId = "a", ModName = "a" }, List(One("file", FileHash)), null).Action == GateAction.Block, "a known malicious file blocks under a new account");

        // A broken list must not read as a clean result, and must not hide what the files show.
        Check(Decide(Blocklist.Broken("x")).Key == "gate_list_broken", "broken list asks");
        Check(Decide(Blocklist.Broken("x"), item: 0, owner: 0).Key == "gate_list_broken", "broken list asks about local mods too");
        Check(Gate.Decide(new GateInput { Item = 100, Owner = 7, Native = new NativeReport { Risk = NativeRisk.Dropper }, ModId = "a", ModName = "a" }, Blocklist.Broken("x"), null).Action == GateAction.Block, "broken list does not soften the import rule");

        Check(Decide(List(One("item", "100", "suspect", "mass_reupload"))).Action == GateAction.Prompt, "suspect only asks");

        // Publisher lookups still in flight must not read as clean.
        Check(Decide(empty, owner: 0, finished: false).Action == GateAction.Wait, "unknown owner waits");
        Check(Decide(empty, owner: 0, finished: true).Action == GateAction.Prompt, "owner never known asks");
        Check(Decide(empty, owner: 0, finished: true).Key == "gate_unverified", "unverified key");
        Check(Decide(confirmed, owner: 0, finished: false).Action == GateAction.Block, "an item match does not wait for the owner");

        // Local folders have no Steam identity and only the hash can match them.
        Check(Decide(empty, item: 0, owner: 0, finished: true).Action == GateAction.Allow, "local mods are not asked about publishers");
        Check(Decide(List(One("version", Hash)), item: 0, owner: 0, hash: Hash).Action == GateAction.Block, "local mods still match by hash");

        Check(Decide(empty, approved: "200").Key == "gate_hijack", "different item under an approved id");
        Check(Decide(empty, approved: "100").Action == GateAction.Allow, "same item stays silent");
        Check(Decide(confirmed, approved: "200").Action == GateAction.Block, "a list hit outranks the hijack warning");
        Check(Decide(empty, item: 0, owner: 0, approved: "200").Action == GateAction.Allow, "local overrides are not hijacks");

        Check(Decide(null).Action == GateAction.Allow, "no list loaded does not throw");
        Check(!typeof(GateAction).GetEnumNames().Any(n => n.Contains("Safe") || n.Contains("Verified")), "no outcome can claim a mod is safe");
    }

    private static void AckKeys()
    {
        var suspect = new GateResult { Key = "gate_suspect", Entry = new Entry { Case = "c", Level = Level.Suspect } };
        var confirmed = new GateResult { Key = "gate_suspect", Entry = new Entry { Case = "c", Level = Level.Confirmed } };
        var native = new GateResult { Key = "gate_native_dropper" };
        Check(Gate.AckKey(native, "local_a", 0, false) != Gate.AckKey(native, "local_b", 0, false), "two local mods do not share a warning");
        Check(Gate.AckKey(suspect, "a", 1, false) != Gate.AckKey(suspect, "a", 1, true), "activating a mod shows its warning again");
        Check(Gate.AckKey(suspect, "a", 1, false) != Gate.AckKey(confirmed, "a", 1, false), "a stronger verdict shows the warning again");
        Check(Gate.AckKey(suspect, "a", 1, false) == Gate.AckKey(suspect, "a", 1, false), "the same warning stays seen");
        var otherReason = new GateResult { Key = "gate_suspect", Entry = new Entry { Case = "c", Level = Level.Suspect, Reason = "impersonation" } };
        Check(Gate.AckKey(suspect, "a", 1, false) != Gate.AckKey(otherReason, "a", 1, false), "a different reason shows the warning again");
    }

    private static void TextIsCleaned()
    {
        Check(!TextSafe.Clean("<color=green>Verified</color>").Contains('<'), "tags cannot open");
        Check(!TextSafe.Clean("</noparse><b>x").Contains('<'), "tags cannot close");
        Check(!TextSafe.Clean("a\u202Eb").Contains('\u202E'), "bidi override is dropped");
        Check(!TextSafe.Clean("a\u200Bb").Contains('\u200B'), "zero-width is dropped");
        Check(!TextSafe.Clean("a\nb\rc\td").Any(char.IsControl), "control characters are dropped");
        Check(!TextSafe.Clean("a\u2028b").Contains('\u2028'), "line separator is dropped");
        Check(TextSafe.Clean(new string('x', 500), 60).Length == 61, "long text is cut");
        Check(!char.IsHighSurrogate(TextSafe.Clean(new string('x', 59) + "😀😀", 60)[^2]), "cutting does not split an emoji");
        Check(TextSafe.Clean(null) == "?" && TextSafe.Clean("") == "?" && TextSafe.Clean("\u200B") == "?", "nothing left shows a placeholder");
        Check(TextSafe.Clean("模组 Mod 1") == "模组 Mod 1", "normal text is untouched");
        Check(TextSafe.Clean("{0} {99}") == "{0} {99}", "braces survive (only templates are formatted)");
        Check(TextSafe.NameKey("Client  Demand-Highlight!") == "clientdemandhighlight", "name key strips punctuation");
        Check(TextSafe.NameKey("Ｃｌｉｅｎｔ") == "client", "name key folds width");
        Check(TextSafe.NameKey("客户需求高亮") == "客户需求高亮", "name key keeps Chinese");
        Check(TextSafe.NameKey("!!!") == "" && TextSafe.NameKey(null) == "", "empty name key");
    }

    private static void ImitationNeedsADifferentOwner()
    {
        KnownMods known = KnownMods.Parse("{\"mods\":[{\"id\":\"real_mod\",\"name\":\"Real Mod\",\"author\":\"Real Author\",\"idPrefix\":\"real_\",\"item\":\"500\",\"publisher\":\"7\"}]}");
        Check(Decide(List(), known, item: 600, owner: 8, id: "other", name: "Different", author: "real  AUTHOR").Key == "gate_impersonation", "same author name, other publisher");
        Check(Decide(List(), known, item: 600, owner: 7, id: "other", name: "Different", author: "Real Author").Action == GateAction.Allow, "same author name, same publisher");
        Check(Decide(List(), known, item: 600, owner: 8, id: "real_other", name: "Different").Key == "gate_impersonation", "same id prefix, other publisher");
        Check(Decide(List(), known, item: 600, owner: 8, id: "other", name: "Different", author: "").Action == GateAction.Allow, "an empty author matches nothing");
        Check(known.Count == 1 && known.Errors.Count == 0, "known list parses");
        Blocklist empty = List();
        Check(Decide(empty, known, item: 500, owner: 7, id: "real_mod", name: "Real Mod").Action == GateAction.Allow, "the real item is silent");
        Check(Decide(empty, known, item: 600, owner: 8, id: "real_mod", name: "Other").Key == "gate_impersonation", "same id, other publisher");
        Check(Decide(empty, known, item: 600, owner: 8, id: "other", name: "real  MOD!").Key == "gate_impersonation", "same name, other publisher");
        Check(Decide(empty, known, item: 600, owner: 7, id: "other", name: "Real Mod").Action == GateAction.Allow, "same author's other item is silent");
        Check(Decide(empty, known, item: 600, owner: 8, id: "other", name: "Different").Action == GateAction.Allow, "unrelated is silent");
        Check(Decide(empty, known, item: 600, owner: 8, id: "other", name: "!!!").Action == GateAction.Allow, "an empty name key matches nothing");
        Check(KnownMods.Parse("nope").Errors.Count == 1, "bad known list is reported");
        Check(KnownMods.Parse("{\"mods\":[{\"id\":\"x\"}]}").Errors.Count == 1, "incomplete known entry is reported");
    }

    private static void FakeGuardsAreNamed()
    {
        const string GuardId = "modguard.fjwjmmc";
        Blocklist empty = List();
        KnownMods published = KnownMods.Parse("{\"mods\":[]}");
        published.AddGuard(GuardId, 900, 9);

        Check(Decide(empty, published, item: 600, owner: 8, id: "other", name: "模组守卫").Key == "gate_fake_guard", "a Workshop item using the guard's name");
        Check(Decide(empty, published, item: 600, owner: 8, id: "other", name: "模组守卫 汉化增强版").Key == "gate_fake_guard", "the name anywhere in the title");
        Check(Decide(empty, published, item: 600, owner: 8, id: "other", name: "Mod-Guard Plus").Key == "gate_fake_guard", "the English name, punctuated");
        Check(Decide(empty, published, item: 600, owner: 8, id: "other", name: "反投毒 模组卫士").Key == "gate_fake_guard", "the name players use for it");
        Check(Decide(empty, published, item: 600, owner: 8, id: "modguard_fixed", name: "Fixer").Key == "gate_fake_guard", "the guard's id prefix");
        Check(Decide(empty, published, item: 0, owner: 0, id: "other", name: "模组守卫").Key == "gate_fake_guard", "a repack in a local folder is asked about too");
        Check(Decide(empty, published, item: 900, owner: 9, id: GuardId, name: "模组守卫 / Mod Guard").Action == GateAction.Allow, "the official item is silent");
        Check(Decide(empty, published, item: 601, owner: 9, id: "other", name: "模组守卫 测试版").Action == GateAction.Allow, "another item of the official publisher is silent");
        Check(Decide(empty, published, item: 600, owner: 8, id: "other", name: "Lucky Perk", author: "fjwjmmc").Action == GateAction.Allow, "the maintainer's author name alone is not a fake guard");
        Check(Decide(empty, published, item: 600, owner: 8, id: "other", name: "Guard Dog").Action == GateAction.Allow, "an unrelated guard is silent");
        Check(Decide(List(One("item", "600")), published, item: 600, owner: 8, id: "other", name: "模组守卫").Key == "gate_confirmed", "a listed fake is blocked, not just asked about");
        Check(Gate.Decide(new GateInput { Item = 600, Owner = 8, ModId = "other", ModName = "模组守卫", Native = new NativeReport { Risk = NativeRisk.Dropper } }, empty, published).Action == GateAction.Block, "the import rule still blocks a fake");

        // Before the first release the identity is unknown, and unknown must never count as a match.
        KnownMods unpublished = KnownMods.Parse("{\"mods\":[]}");
        unpublished.AddGuard(GuardId, 0, 0);
        Check(Decide(empty, unpublished, item: 600, owner: 8, id: "other", name: "模组守卫").Key == "gate_fake_guard", "unpublished: a Workshop fake");
        Check(Decide(empty, unpublished, item: 0, owner: 0, id: "other", name: "模组守卫").Key == "gate_fake_guard", "unpublished: a local fake is not taken for the real one");
        Check(Decide(empty, unpublished, item: 600, owner: 0, finished: true, id: "other", name: "模组守卫").Key == "gate_fake_guard", "unpublished: unknown publisher is not the official one");

        // The state of the first, private upload: publisher known, item not yet.
        KnownMods firstUpload = KnownMods.Parse("{\"mods\":[]}");
        firstUpload.AddGuard(GuardId, 0, 9);
        Check(Decide(empty, firstUpload, item: 600, owner: 9, id: GuardId, name: "模组守卫 / Mod Guard").Action == GateAction.Allow, "first upload: the maintainer's own item is silent");
        Check(Decide(empty, firstUpload, item: 600, owner: 8, id: "other", name: "模组守卫").Key == "gate_fake_guard", "first upload: another publisher's copy is named");
        Check(Decide(empty, firstUpload, item: 0, owner: 0, id: "other", name: "模组守卫").Key == "gate_fake_guard", "first upload: a local copy is named");

        // A guard entry must not turn into the ordinary imitation check, which also matches author names.
        KnownMods withOthers = KnownMods.Parse("{\"mods\":[{\"id\":\"real_mod\",\"name\":\"Real Mod\",\"author\":\"fjwjmmc\",\"item\":\"500\",\"publisher\":\"9\"}]}");
        withOthers.AddGuard(GuardId, 0, 0);
        Check(Decide(empty, withOthers, item: 700, owner: 9, id: "new_mod", name: "New Mod", author: "fjwjmmc").Action == GateAction.Allow, "the maintainer's new mod is silent");
    }

    private static void SelfFilesAreChecked()
    {
        byte[] manifest = { 1, 2, 3 };
        byte[] list = { 4, 5 };
        byte[] zh = { 6 };
        string Hash(byte[] b) => Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(b));
        var expected = new List<(string, string)>
        {
            ("manifest.xml", Hash(manifest)),
            ("blocklist.json", Hash(list).ToLowerInvariant()),
            ("Localization/zh.csv", Hash(zh)),
        };
        var disk = new Dictionary<string, byte[]> { ["manifest.xml"] = manifest, ["blocklist.json"] = list, ["Localization/zh.csv"] = zh };
        SelfReport Run(IEnumerable<string> languages = null) => SelfFiles.Check(expected, p => disk.TryGetValue(p, out byte[] b) ? b : null, languages ?? new[] { "zh" });

        SelfReport clean = Run();
        Check(clean.Ok && clean.TextTrusted && clean.DataTrusted, "untouched files pass, hash case does not matter");

        disk["blocklist.json"] = new byte[] { 4 };
        SelfReport emptied = Run();
        Check(!emptied.Ok && !emptied.DataTrusted && emptied.TextTrusted && emptied.Changed.SequenceEqual(new[] { "blocklist.json" }), "a changed list is not trusted");
        disk["blocklist.json"] = list;

        disk["Localization/zh.csv"] = new byte[] { 7 };
        SelfReport rewritten = Run();
        Check(!rewritten.TextTrusted && rewritten.DataTrusted, "changed messages are not trusted");
        disk["Localization/zh.csv"] = zh;

        SelfReport added = Run(new[] { "zh", "ja" });
        Check(!added.TextTrusted && added.Extra.SequenceEqual(new[] { "Localization/ja.csv" }), "an added language file is caught, since the game loads every csv");

        disk.Remove("manifest.xml");
        SelfReport missing = Run();
        Check(!missing.DataTrusted && missing.Missing.SequenceEqual(new[] { "manifest.xml" }), "a missing file is caught");
        disk["manifest.xml"] = manifest;

        SelfReport throwing = SelfFiles.Check(expected, p => throw new IOException("locked"), new[] { "zh" });
        Check(!throwing.DataTrusted && !throwing.TextTrusted && throwing.Missing.Count == 3, "an unreadable file counts as missing");

        SelfReport odd = Run(new[] { "zh", "<b>x</b>" });
        Check(odd.Extra.All(p => !p.Contains('<')), "an added file name is cleaned before it is shown");

        // Telling a Steam update during the session from a repack.
        byte[] dll = { 9, 9, 9 };
        string loaded = Hash(dll).ToLowerInvariant();
        Check(!SelfFiles.ReplacedSinceLoad(loaded, () => dll), "the DLL the game loaded is still on disk: a repack, not an update");
        Check(SelfFiles.ReplacedSinceLoad(loaded, () => new byte[] { 1 }), "a different DLL on disk: Steam updated it");
        Check(SelfFiles.ReplacedSinceLoad(loaded, () => throw new IOException("in use")), "a DLL being written: Steam is updating it");
        Check(SelfFiles.ReplacedSinceLoad(loaded, () => null), "a DLL gone from disk: being replaced");
        Check(!SelfFiles.ReplacedSinceLoad(null, () => new byte[] { 1 }), "no load-time hash: stay strict");
        Check(!SelfFiles.ReplacedSinceLoad("missing", () => new byte[] { 1 }), "the game found no DLL at load: stay strict");
    }

    /// <summary>
    /// Checks the folder that is about to be uploaded, not the sources: the DLL in it must carry the official identity
    /// from the csproj, and every file beside it must be exactly what that DLL expects. A file touched after the build,
    /// or a build that predates a change, would otherwise show every player the "altered" warning and switch the list off.
    /// Upload this folder and nothing else, and do not touch it after this passes.
    /// </summary>
    private static int ReleaseCheck(string content, bool firstUpload)
    {
        string root = RepoRoot();
        string project = File.ReadAllText(Path.Combine(root, "src", "ModGuard", "ModGuard.csproj"));
        ulong Declared(string name)
        {
            Match match = Regex.Match(project, "<" + name + @" Condition=""'\$\(" + name + @"\)' == ''"">(\d+)</" + name + ">");
            return match.Success ? ulong.Parse(match.Groups[1].Value) : 0;
        }
        ulong item = Declared("OfficialItem");
        ulong publisher = Declared("OfficialPublisher");
        // The first upload creates the item, so its number cannot be known yet. That build has no identity check
        // and must stay private; everything else is checked the same.
        if (firstUpload)
        {
            Check(item == 0, "--first-upload is only for a build without an item number");
            Console.WriteLine("First upload: OfficialItem is 0. Upload as PRIVATE, then fill it in and run again without --first-upload.");
        }
        else
        {
            Check(item != 0, "OfficialItem is filled in in the csproj");
            Check(item == 0 || File.ReadAllText(Path.Combine(root, "README.md")).Contains(item.ToString()), "the README names the official item");
        }
        Check(publisher != 0, "OfficialPublisher is filled in in the csproj");

        string dll = Path.Combine(content, "ModGuard.dll");
        if (!File.Exists(dll))
        {
            Check(false, "the release folder has ModGuard.dll: " + dll);
            Console.WriteLine($"{_passes} passed, {_failures} failed");
            return _failures;
        }

        // The guard's own DLL, loaded from bytes so the file is not locked. Only SelfData is touched, and it uses
        // nothing but strings and numbers. Reading it runs that DLL's SelfData initializer, so use this only on a
        // DLL just built from these sources, never on one downloaded from somewhere.
        var context = new AssemblyLoadContext("release-check", isCollectible: true);
        string[][] files;
        try
        {
            Assembly built = context.LoadFromStream(new MemoryStream(File.ReadAllBytes(dll)));
            Type selfData = built.GetType("ModGuard.SelfData", throwOnError: true);
            const BindingFlags Field = BindingFlags.Static | BindingFlags.NonPublic | BindingFlags.Public;
            ulong builtItem = (ulong)selfData.GetField("OfficialItem", Field).GetValue(null);
            ulong builtPublisher = (ulong)selfData.GetField("OfficialPublisher", Field).GetValue(null);
            files = (string[][])selfData.GetField("Files", Field).GetValue(null);
            Check(builtItem == item && (item != 0 || firstUpload), $"the DLL carries the official item from the csproj (DLL {builtItem}, csproj {item}); rebuild after changing it");
            Check(builtPublisher == publisher && publisher != 0, $"the DLL carries the official publisher from the csproj (DLL {builtPublisher}, csproj {publisher})");
        }
        finally
        {
            context.Unload();
        }

        var expected = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "ModGuard.dll" };
        foreach (string[] file in files)
        {
            expected.Add(file[0]);
            string path = Path.Combine(content, file[0]);
            Check(File.Exists(path) && string.Equals(Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(File.ReadAllBytes(path))), file[1], StringComparison.OrdinalIgnoreCase),
                "file matches the hash built into the DLL: " + file[0]);
        }
        // Nothing else may ship: an extra csv would be loaded by the game, and anything else has no business there.
        foreach (string path in Directory.GetFiles(content, "*", SearchOption.AllDirectories))
        {
            string relative = Path.GetRelativePath(content, path).Replace('\\', '/');
            Check(expected.Contains(relative), "nothing unexpected in the release folder: " + relative);
        }
        string manifest = File.ReadAllText(Path.Combine(content, "manifest.xml"));
        List<string> assemblies = Regex.Matches(manifest, @"<Assembly>\s*([^<]+?)\s*</Assembly>").Select(m => m.Groups[1].Value).ToList();
        Check(assemblies.Count == 1 && assemblies[0] == "ModGuard.dll", "the manifest lists ModGuard.dll and nothing else");
        // The manifest hash already ties it to the sources; these catch a slip in the sources themselves.
        Check(Regex.Match(manifest, @"<ID>\s*([^<]+?)\s*</ID>").Groups[1].Value == "modguard.fjwjmmc", "the manifest has the guard's own mod id");
        Check(!Regex.IsMatch(manifest, @"<Capability>"), "the manifest declares no capabilities");

        Console.WriteLine("ModGuard.dll SHA-256 (for the release notes): " + Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(File.ReadAllBytes(dll))).ToLowerInvariant());
        Console.WriteLine($"{_passes} passed, {_failures} failed");
        return _failures;
    }

    private static string RepoRoot()
    {
        for (DirectoryInfo dir = new DirectoryInfo(AppContext.BaseDirectory); dir != null; dir = dir.Parent)
        {
            if (File.Exists(Path.Combine(dir.FullName, "src", "ModGuard", "manifest.xml")))
            {
                return dir.FullName;
            }
        }
        throw new DirectoryNotFoundException("repository root not found");
    }

    private static Dictionary<string, string> ReadCsv(string path)
    {
        var map = new Dictionary<string, string>();
        foreach (string line in File.ReadAllLines(path))
        {
            if (string.IsNullOrWhiteSpace(line) || line.TrimStart().StartsWith("#"))
            {
                continue;
            }
            int comma = line.IndexOf(',');
            string key = line.Substring(0, comma).Trim();
            Check(!map.ContainsKey(key), "duplicate key " + key + " in " + Path.GetFileName(path));
            map[key] = line.Substring(comma + 1).Trim();
        }
        return map;
    }

    private static void ShippedData()
    {
        string mod = Path.Combine(RepoRoot(), "src", "ModGuard");
        Blocklist list = Blocklist.Parse(File.ReadAllText(Path.Combine(mod, "blocklist.json")));
        Check(!list.IsBroken && list.Errors.Count == 0, "shipped blocklist is clean: " + string.Join("; ", list.Errors));
        KnownMods known = KnownMods.Parse(File.ReadAllText(Path.Combine(mod, "known_mods.json")));
        Check(known.Errors.Count == 0, "shipped known list is clean: " + string.Join("; ", known.Errors));

        // The policy gives a suspect entry 30 days to be confirmed or removed. This fails on purpose once one is overdue.
        foreach (Entry entry in list.Entries.Where(e => e.Level == Level.Suspect))
        {
            Check((DateTime.UtcNow - DateTime.Parse(entry.Added)).TotalDays <= 30, "suspect entry is overdue: " + entry.Value);
        }

        // Each case lists the items it puts on the list in one marked line, and that line and the list must agree both
        // ways. Every item needs its own entry, since a publisher entry is useless while Steam has not answered.
        // Other numbers in a case, such as the item of an author who was imitated, are not read: a test that pushed
        // every number in a case onto the list would push victims onto it.
        string cases = Path.Combine(RepoRoot(), "cases");
        Dictionary<string, HashSet<string>> listedByCase = list.Entries
            .Where(e => e.Kind == KeyKind.Item)
            .GroupBy(e => e.Case)
            .ToDictionary(g => g.Key, g => g.Select(e => e.Value).ToHashSet());
        foreach (string caseId in listedByCase.Keys)
        {
            Check(File.Exists(Path.Combine(cases, caseId + ".md")), "every case on the list has a record: " + caseId);
        }
        foreach (string file in Directory.GetFiles(cases, "*.md"))
        {
            string caseId = Path.GetFileNameWithoutExtension(file);
            Match line = Regex.Match(File.ReadAllText(file), @"^- \*\*收录的条目：\*\*(.*)$", RegexOptions.Multiline);
            Check(line.Success, "case names the items it lists, in one marked line: " + caseId);
            HashSet<string> named = Regex.Matches(line.Groups[1].Value, @"\d{6,}").Select(m => m.Value).ToHashSet();
            HashSet<string> listed = listedByCase.TryGetValue(caseId, out HashSet<string> set) ? set : new HashSet<string>();
            Check(named.SetEquals(listed), "case and list name the same items: " + caseId
                + " (only in case: " + string.Join(",", named.Except(listed)) + "; only in list: " + string.Join(",", listed.Except(named)) + ")");
        }

        string[] sources = Directory.GetFiles(mod, "*.cs", SearchOption.AllDirectories);
        string allCode = string.Join("\n", sources.Select(File.ReadAllText));
        // SelfText holds built-in copies of some keys. The csv checks below are about what the code asks the csv for.
        string code = string.Join("\n", sources.Where(p => Path.GetFileName(p) != "SelfText.cs").Select(File.ReadAllText));

        // The built-in messages: every key the code asks for exists, and so does every key a dialog still needs once
        // the language files cannot be trusted. A typo would silently fall back to the generic text.
        string selfText = File.ReadAllText(Path.Combine(mod, "SelfText.cs"));
        Check(!Regex.IsMatch(selfText, @"https?:|www\.|\.exe|\.zip", RegexOptions.IgnoreCase), "no links or downloads in built-in text");
        HashSet<string> builtIn = Regex.Matches(selfText, "\\[\"([a-z_]+)\"\\] =").Select(m => m.Groups[1].Value).ToHashSet();
        foreach (Match match in Regex.Matches(code, "SelfText\\.Get\\(\"([a-z_]+)\""))
        {
            Check(builtIn.Contains(match.Groups[1].Value), "built-in text exists: " + match.Groups[1].Value);
        }
        foreach (string key in new[] { "window_title", "footer", "footer_official", "btn_close", "btn_cancel", "btn_continue", "btn_open_menu",
            "source_workshop", "source_local", "generic_head", "generic_body",
            "gate_confirmed_head", "gate_confirmed_body", "gate_native_dropper_head", "gate_native_dropper_body" })
        {
            Check(builtIn.Contains(key), "built-in text a dialog needs exists: " + key);
        }

        // English is the reference. Every other language file, including ones added later for translations, must have
        // exactly its keys and placeholders, and none may contain a link: the game loads every csv in the folder.
        Dictionary<string, string> en = ReadCsv(Path.Combine(mod, "Localization", "en.csv"));
        Check(File.Exists(Path.Combine(mod, "Localization", "zh.csv")), "the Chinese file exists");
        string Holes(string text) => string.Join(",", Regex.Matches(text, @"\{\d+\}").Select(m => m.Value).Distinct().OrderBy(s => s));
        foreach (string file in Directory.GetFiles(Path.Combine(mod, "Localization"), "*.csv"))
        {
            string language = Path.GetFileNameWithoutExtension(file);
            Dictionary<string, string> texts = ReadCsv(file);
            Check(en.Keys.ToHashSet().SetEquals(texts.Keys), language + " has the same keys as en: "
                + string.Join(", ", en.Keys.Except(texts.Keys).Concat(texts.Keys.Except(en.Keys))));
            foreach (KeyValuePair<string, string> pair in texts)
            {
                Check(!Regex.IsMatch(pair.Value, @"https?:|www\.|\.exe|\.zip", RegexOptions.IgnoreCase), "no links or downloads in text: " + language + "/" + pair.Key);
                // The game renders rich text. A tag in a translation could shrink the "third-party mod" footer to
                // nothing or paint a fake label, so no message may contain one.
                Check(pair.Value.IndexOfAny(new[] { '<', '>' }) < 0, "no rich-text tags in text: " + language + "/" + pair.Key);
                // {1} in dialog and report text is already "Workshop item N" or "local mod", so a local mod never shows "item 0".
                Check(!Regex.IsMatch(pair.Value, @"(Workshop item|工坊条目) \{1\}"), "source is passed in, not built in the text: " + language + "/" + pair.Key);
                Check(!en.TryGetValue(pair.Key, out string reference) || Holes(reference) == Holes(pair.Value), language + " uses the same placeholders as en: " + pair.Key);
            }
        }
        foreach (string reason in Blocklist.Reasons)
        {
            Check(en.ContainsKey("reason_" + reason), "reason text exists: " + reason);
        }

        foreach (Match match in Regex.Matches(code, "\"(gate_[a-z_]*[a-z])\""))
        {
            string key = match.Groups[1].Value;
            Check(en.ContainsKey(key + "_head") && en.ContainsKey(key + "_body"), "dialog text exists: " + key);
        }
        foreach (string key in new[] { "hijack", "impersonation", "native_dropper", "native_risky", "multi_entry", "fake_guard" })
        {
            Check(en.ContainsKey("why_" + key), "row text exists: " + key);
        }
        // A literal ending in '_' is the front half of a key built at run time; the reason and gate checks above cover those.
        foreach (Match match in Regex.Matches(code, "\\bL\\(\"([a-z_]*[a-z])\""))
        {
            Check(en.ContainsKey(match.Groups[1].Value), "text exists: " + match.Groups[1].Value);
        }
        foreach (Match match in Regex.Matches(code, "CloseButton\\(\"([a-z_]+)\""))
        {
            Check(en.ContainsKey(match.Groups[1].Value), "button text exists: " + match.Groups[1].Value);
        }

        // v1 only holds back the player's click. Writing to the loader would depend on what the scanner lets through today.
        string withoutComments = Regex.Replace(allCode, "//.*", "");
        foreach (string forbidden in new[] { "SetModEnabled", "EnabledMods", "ApproveAndEnable", "ForgetMod", "ModTrust.", "Unsubscribe(", "UnpatchAll", "Unpatch(", "ES3.", "File.", "Directory.", "FileStream", "System.Net", "Process.", "ProcessStartInfo", "DllImport" })
        {
            Check(!withoutComments.Contains(forbidden), "v1 does not use " + forbidden);
        }
    }

    private static int CheckPatches(string dll, string managed)
    {
        Assembly game = AssemblyLoadContext.Default.LoadFromAssemblyPath(Path.Combine(managed, "Assembly-CSharp.dll"));
        Assembly mod =AssemblyLoadContext.Default.LoadFromAssemblyPath(Path.GetFullPath(dll));

        const BindingFlags Any = BindingFlags.NonPublic | BindingFlags.Public | BindingFlags.Static | BindingFlags.Instance;
        int problems = 0;
        int patches = 0;
        foreach (Type type in mod.GetTypes())
        {
            HarmonyPatch attribute = type.GetCustomAttributes(typeof(HarmonyPatch), false).Cast<HarmonyPatch>().FirstOrDefault();
            if (attribute?.info?.declaringType == null)
            {
                continue;
            }
            patches++;
            MethodBase target = AccessTools.Method(attribute.info.declaringType, attribute.info.methodName, attribute.info.argumentTypes);
            if (target == null)
            {
                problems++;
                Console.WriteLine("MISSING target: " + attribute.info.declaringType.Name + "." + attribute.info.methodName);
                continue;
            }
            Console.WriteLine("target ok: " + target.DeclaringType.Name + "." + target.Name);
            HashSet<string> names = target.GetParameters().Select(p => p.Name).ToHashSet();
            foreach (MethodInfo patch in type.GetMethods(Any).Where(m => m.Name is "Prefix" or "Postfix" or "Finalizer"))
            {
                foreach (ParameterInfo parameter in patch.GetParameters())
                {
                    if (!parameter.Name.StartsWith("__", StringComparison.Ordinal) && !names.Contains(parameter.Name))
                    {
                        problems++;
                        Console.WriteLine("BAD argument: " + parameter.Name + " on " + type.Name + "." + patch.Name);
                    }
                }
            }
        }

        // Private members the guard reaches by name must still exist after a game update.
        Type menu = game.GetType("ModUIManager", throwOnError: true);
        foreach (string name in new[] { "SelectMod", "RefreshRowIssues", "BeginEnable", "GetModIssue" })
        {
            if (AccessTools.Method(menu, name) == null)
            {
                problems++;
                Console.WriteLine("MISSING member: ModUIManager." + name);
            }
        }
        Console.WriteLine($"{patches} patches checked, {problems} problems");
        return problems;
    }
}
