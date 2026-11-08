using System;
using System.Collections.Generic;
using System.Linq;
using Newtonsoft.Json.Linq;

namespace ModGuard.Core
{
    public sealed class KnownMod
    {
        public string Id;
        public string NameKey;
        public string AuthorKey;
        public string IdPrefix;
        public ulong Item;
        public ulong Publisher;
        /// <summary>This entry is Mod Guard itself. A fake guard is the most valuable thing to imitate, since players trust it.</summary>
        public bool IsGuard;
        /// <summary>Name keys that count as claiming this mod's name anywhere in the title.</summary>
        public string[] NameFragments;
    }

    /// <summary>
    /// Well-known mods with the item and publisher that really own them. A different publisher claiming the same
    /// manifest id, display name, author name or id prefix is worth a warning, and only a warning: forks and
    /// translations are normal, and two people can share a name.
    /// </summary>
    public sealed class KnownMods
    {
        private readonly List<KnownMod> _mods = new List<KnownMod>();

        public List<string> Errors { get; } = new List<string>();

        public int Count => _mods.Count;

        public static KnownMods Parse(string json)
        {
            var known = new KnownMods();
            JObject root;
            try
            {
                root = JObject.Parse(json ?? "");
            }
            catch (Exception ex)
            {
                known.Errors.Add("not JSON: " + ex.Message);
                return known;
            }
            if (!(root["mods"] is JArray mods))
            {
                known.Errors.Add("no mods array");
                return known;
            }
            for (int i = 0; i < mods.Count; i++)
            {
                var o = mods[i] as JObject;
                if (o == null
                    || string.IsNullOrEmpty((string)o["id"])
                    || !ulong.TryParse((string)o["item"], out ulong item)
                    || !ulong.TryParse((string)o["publisher"], out ulong publisher))
                {
                    known.Errors.Add("mod " + i + ": needs id, item and publisher");
                    continue;
                }
                known._mods.Add(new KnownMod
                {
                    Id = (string)o["id"],
                    NameKey = TextSafe.NameKey((string)o["name"]),
                    AuthorKey = TextSafe.NameKey((string)o["author"]),
                    IdPrefix = (string)o["idPrefix"],
                    Item = item,
                    Publisher = publisher,
                });
            }
            return known;
        }

        /// <summary>Names a copy of Mod Guard would use, as name keys. Two of them are what players actually call it.</summary>
        public static readonly string[] GuardNames = { "模组守卫", "模组卫士", "modguard" };

        /// <summary>
        /// Adds Mod Guard itself. Its identity comes from the DLL, not from a file beside it. It never matches on the
        /// author name, because the maintainer's other mods share it. Before the first release item and publisher are 0,
        /// which means unknown, so every other mod using the name is reported.
        /// </summary>
        public void AddGuard(string id, ulong item, ulong publisher)
        {
            _mods.Add(new KnownMod
            {
                Id = id,
                IdPrefix = "modguard",
                NameFragments = GuardNames,
                Item = item,
                Publisher = publisher,
                IsGuard = true,
            });
        }

        /// <summary>0 means not known, never "the same".</summary>
        private static bool OwnedBy(KnownMod known, ulong item, ulong owner)
        {
            return (known.Item != 0 && known.Item == item) || (known.Publisher != 0 && known.Publisher == owner);
        }

        /// <summary>Mod Guard, if this item claims to be it without coming from its item or publisher. Local mods count too.</summary>
        public KnownMod FindGuardImitation(string modId, string modName, ulong item, ulong owner)
        {
            string nameKey = TextSafe.NameKey(modName);
            foreach (KnownMod known in _mods)
            {
                if (!known.IsGuard || OwnedBy(known, item, owner))
                {
                    continue;
                }
                bool sameId = string.Equals(known.Id, modId, StringComparison.OrdinalIgnoreCase);
                bool samePrefix = modId != null && modId.StartsWith(known.IdPrefix, StringComparison.OrdinalIgnoreCase);
                bool claimsName = nameKey.Length > 0 && known.NameFragments.Any(f => nameKey.Contains(f));
                if (sameId || samePrefix || claimsName)
                {
                    return known;
                }
            }
            return null;
        }

        /// <summary>The known mod this item seems to imitate, or null. Mod Guard itself is handled by FindGuardImitation.</summary>
        public KnownMod FindImitated(string modId, string modName, string modAuthor, ulong item, ulong owner)
        {
            string nameKey = TextSafe.NameKey(modName);
            string authorKey = TextSafe.NameKey(modAuthor);
            foreach (KnownMod known in _mods)
            {
                if (known.IsGuard || OwnedBy(known, item, owner))
                {
                    continue;
                }
                bool sameId = string.Equals(known.Id, modId, StringComparison.OrdinalIgnoreCase);
                bool sameName = nameKey.Length > 0 && known.NameKey == nameKey;
                bool sameAuthor = authorKey.Length > 0 && known.AuthorKey == authorKey;
                bool samePrefix = !string.IsNullOrEmpty(known.IdPrefix) && modId != null
                    && modId.StartsWith(known.IdPrefix, StringComparison.OrdinalIgnoreCase);
                if (sameId || sameName || sameAuthor || samePrefix)
                {
                    return known;
                }
            }
            return null;
        }
    }
}
