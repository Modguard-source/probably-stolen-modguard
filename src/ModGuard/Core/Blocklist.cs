using System;
using System.Collections.Generic;
using System.Linq;
using Newtonsoft.Json.Linq;

namespace ModGuard.Core
{
    public enum Level
    {
        Suspect = 1,
        Confirmed = 2,
    }

    public enum KeyKind
    {
        Item,
        Publisher,
        Version,
        File,
    }

    public sealed class Entry
    {
        public KeyKind Kind;
        public string Value;
        public Level Level;
        public string Reason;
        public string Case;
        public string Added;
    }

    /// <summary>
    /// The list ships with the mod. It may only match on values Steam issues (item and publisher ids), on a
    /// whole-version hash, or on the hash of a file that is itself the malicious component (the one key that survives
    /// a re-upload from a new account). Manifest ids, author names and titles are chosen by the uploader, so matching
    /// on them would let anyone frame someone else. Text shown to players comes from reason codes, never from the
    /// list, so a bad entry cannot put a link or an accusation on screen.
    /// </summary>
    public sealed class Blocklist
    {
        public static readonly string[] Reasons =
        {
            "malware_confirmed",
            "download_execute",
            "publisher_confirmed",
            "credential_theft",
            "hidden_program",
            "compromised_version",
            "mass_reupload",
            "impersonation",
        };

        private readonly Dictionary<string, Entry> _entries = new Dictionary<string, Entry>(StringComparer.Ordinal);

        public List<string> Errors { get; } = new List<string>();

        /// <summary>True when the file itself could not be used. Single bad entries only land in Errors.</summary>
        public bool IsBroken { get; private set; }

        public int Count => _entries.Count;

        public bool HasVersionEntries { get; private set; }

        public bool HasFileEntries { get; private set; }

        public bool HasPublisherEntries { get; private set; }

        public IEnumerable<Entry> Entries => _entries.Values;

        public static Blocklist Broken(string reason)
        {
            var list = new Blocklist { IsBroken = true };
            list.Errors.Add(reason);
            return list;
        }

        public static Blocklist Parse(string json)
        {
            JObject root;
            try
            {
                root = JObject.Parse(json ?? "");
            }
            catch (Exception ex)
            {
                return Broken("not JSON: " + ex.Message);
            }

            if (root["version"]?.Type != JTokenType.Integer || (int)root["version"] != 1)
            {
                return Broken("unsupported version");
            }
            if (!(root["entries"] is JArray entries))
            {
                return Broken("no entries array");
            }

            var list = new Blocklist();
            for (int i = 0; i < entries.Count; i++)
            {
                if (TryReadEntry(entries[i] as JObject, out Entry entry, out string problem))
                {
                    list.Add(entry);
                }
                else
                {
                    list.Errors.Add("entry " + i + ": " + problem);
                }
            }
            return list;
        }

        public Entry Match(ulong item, ulong publisher, string versionHash, IEnumerable<string> fileHashes = null)
        {
            Entry best = null;
            if (item != 0)
            {
                best = Better(best, Find(KeyKind.Item, item.ToString()));
            }
            if (publisher != 0)
            {
                best = Better(best, Find(KeyKind.Publisher, publisher.ToString()));
            }
            if (!string.IsNullOrEmpty(versionHash))
            {
                best = Better(best, Find(KeyKind.Version, versionHash.ToLowerInvariant()));
            }
            if (fileHashes != null)
            {
                foreach (string hash in fileHashes)
                {
                    if (!string.IsNullOrEmpty(hash))
                    {
                        best = Better(best, Find(KeyKind.File, hash.ToLowerInvariant()));
                    }
                }
            }
            return best;
        }

        private void Add(Entry entry)
        {
            string key = Key(entry.Kind, entry.Value);
            if (!_entries.TryGetValue(key, out Entry existing) || entry.Level > existing.Level)
            {
                _entries[key] = entry;
            }
            HasVersionEntries |= entry.Kind == KeyKind.Version;
            HasFileEntries |= entry.Kind == KeyKind.File;
            HasPublisherEntries |= entry.Kind == KeyKind.Publisher;
        }

        private Entry Find(KeyKind kind, string value)
        {
            return _entries.TryGetValue(Key(kind, value), out Entry entry) ? entry : null;
        }

        private static Entry Better(Entry a, Entry b)
        {
            if (a == null)
            {
                return b;
            }
            return b != null && b.Level > a.Level ? b : a;
        }

        private static string Key(KeyKind kind, string value)
        {
            return kind + ":" + value;
        }

        private static bool TryReadEntry(JObject o, out Entry entry, out string problem)
        {
            entry = null;
            problem = null;
            if (o == null)
            {
                problem = "not an object";
                return false;
            }

            string kindText = (string)o["kind"];
            string value = (string)o["value"];
            string levelText = (string)o["level"];
            string reason = (string)o["reason"];
            string caseId = (string)o["case"];
            string added = (string)o["added"];

            KeyKind kind;
            switch (kindText)
            {
                case "item":
                    kind = KeyKind.Item;
                    if (!ulong.TryParse(value, out ulong itemId) || itemId == 0 || !IsDigits(value, 1, 20))
                    {
                        problem = "item must be a numeric id";
                        return false;
                    }
                    // Lookups use the number's plain form, so "0100" must become "100" or it would never match.
                    value = itemId.ToString();
                    break;
                case "publisher":
                    kind = KeyKind.Publisher;
                    if (!IsDigits(value, 17, 17) || !value.StartsWith("7656", StringComparison.Ordinal))
                    {
                        problem = "publisher must be a SteamID64";
                        return false;
                    }
                    // Covering a whole account is the widest thing the list can do, so suspicion alone is not enough.
                    if (levelText != "confirmed")
                    {
                        problem = "a publisher entry must be confirmed";
                        return false;
                    }
                    break;
                case "version":
                    kind = KeyKind.Version;
                    if (!IsLowerHex(value, 64))
                    {
                        problem = "version must be a lowercase sha-256";
                        return false;
                    }
                    break;
                case "file":
                    kind = KeyKind.File;
                    if (!IsLowerHex(value, 64))
                    {
                        problem = "file must be a lowercase sha-256";
                        return false;
                    }
                    // Only the malicious component's own hash belongs here, never a file from a normal mod.
                    if (levelText != "confirmed")
                    {
                        problem = "a file entry must be confirmed";
                        return false;
                    }
                    break;
                default:
                    problem = "unknown kind";
                    return false;
            }

            Level level;
            switch (levelText)
            {
                case "confirmed":
                    level = Level.Confirmed;
                    break;
                case "suspect":
                    level = Level.Suspect;
                    break;
                default:
                    problem = "unknown level";
                    return false;
            }

            if (!Reasons.Contains(reason))
            {
                problem = "unknown reason code";
                return false;
            }
            if (!IsCaseId(caseId))
            {
                problem = "case must be letters, digits and '-'";
                return false;
            }
            if (!DateTime.TryParseExact(added, "yyyy-MM-dd", System.Globalization.CultureInfo.InvariantCulture, System.Globalization.DateTimeStyles.None, out _))
            {
                problem = "added must be yyyy-MM-dd";
                return false;
            }

            entry = new Entry { Kind = kind, Value = value, Level = level, Reason = reason, Case = caseId, Added = added };
            return true;
        }

        private static bool IsDigits(string s, int min, int max)
        {
            return s != null && s.Length >= min && s.Length <= max && s.All(c => c >= '0' && c <= '9');
        }

        private static bool IsLowerHex(string s, int length)
        {
            return s != null && s.Length == length && s.All(c => (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'));
        }

        private static bool IsCaseId(string s)
        {
            return s != null && s.Length >= 1 && s.Length <= 24
                && s.All(c => (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '-');
        }
    }
}
