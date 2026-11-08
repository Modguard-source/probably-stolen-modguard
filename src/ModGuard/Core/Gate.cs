using System.Collections.Generic;
using System.Linq;

namespace ModGuard.Core
{
    public enum GateAction
    {
        /// <summary>Stay silent. This never means the mod is safe, and nothing may ever present it that way.</summary>
        Allow,
        /// <summary>Asks Steam for the publisher; the player tries again in a moment.</summary>
        Wait,
        /// <summary>The player may go on after reading the warning.</summary>
        Prompt,
        /// <summary>Refused while the guard is active.</summary>
        Block,
    }

    public sealed class GateInput
    {
        public ulong Item;
        public ulong Owner;
        public bool OwnerQueryFinished;
        public string VersionHash;
        public IEnumerable<string> FileHashes;
        public string ModId;
        public string ModName;
        public string ModAuthor;
        /// <summary>Workshop item the player approved under this mod id, when the game has a record of one.</summary>
        public string ApprovedItem;
        public NativeReport Native;
    }

    public sealed class GateResult
    {
        public GateAction Action;
        public string Key;
        public Entry Entry;
        /// <summary>The imported functions behind a native-rule result. They come from the DLL, so clean them before showing.</summary>
        public string Detail;

        public static readonly GateResult Silent = new GateResult { Action = GateAction.Allow };
    }

    public static class Gate
    {
        /// <summary>
        /// The strictest verdict wins, so a softer list entry can never hide what the files themselves show.
        /// There is deliberately no automatic softening of a block: anything a mod author could trigger on purpose
        /// (say, by getting players to subscribe to several listed items) would be a switch for turning the guard off.
        /// A wrong entry is fixed by correcting the list.
        /// </summary>
        public static GateResult Decide(GateInput input, Blocklist list, KnownMods known)
        {
            NativeReport native = input.Native;
            IEnumerable<string> fileHashes = (input.FileHashes ?? Enumerable.Empty<string>()).Concat(native?.FileHashes ?? Enumerable.Empty<string>());
            Entry entry = list?.Match(input.Item, input.Owner, input.VersionHash, fileHashes);

            if (entry?.Level == Level.Confirmed)
            {
                return new GateResult { Action = GateAction.Block, Key = "gate_confirmed", Entry = entry, Detail = native?.Summary };
            }
            if (native?.Risk == NativeRisk.Dropper)
            {
                return new GateResult { Action = GateAction.Block, Key = "gate_native_dropper", Detail = native.Summary };
            }

            // Anything below can be clicked through, and the publisher may turn out to be listed. Steam answers within
            // seconds, so wait for it rather than offer a way past a block during exactly the moment a new upload is unknown.
            if (input.Item != 0 && input.Owner == 0 && !input.OwnerQueryFinished && list?.HasPublisherEntries == true)
            {
                return new GateResult { Action = GateAction.Wait, Key = "gate_wait" };
            }

            if (entry != null)
            {
                return new GateResult { Action = GateAction.Prompt, Key = "gate_suspect", Entry = entry, Detail = native?.Summary };
            }
            if (native?.Risk == NativeRisk.Risky)
            {
                return new GateResult { Action = GateAction.Prompt, Key = "gate_native_risky", Detail = native.Summary };
            }
            // Every malicious item found so far looks like this, and none of 236 others did. Legitimate multi-part mods
            // can too, so it only ever asks.
            if (native?.EntryPoints > 1)
            {
                return new GateResult { Action = GateAction.Prompt, Key = "gate_multi_entry", Detail = native.EntryPoints.ToString() };
            }

            // The checks could not do their job. Silence here would read as "nothing wrong".
            if (native?.Unreadable == true)
            {
                return new GateResult { Action = GateAction.Prompt, Key = "gate_error" };
            }
            if (list?.IsBroken == true)
            {
                return new GateResult { Action = GateAction.Prompt, Key = "gate_list_broken" };
            }

            // Before the local-mod exit: a repacked guard passed around outside the Workshop installs as a local mod.
            // Only a warning, like every check on a self-chosen name: forks and translations are allowed by the licence.
            if (known?.FindGuardImitation(input.ModId, input.ModName, input.Item, input.Owner) != null)
            {
                return new GateResult { Action = GateAction.Prompt, Key = "gate_fake_guard" };
            }

            if (input.Item == 0)
            {
                return GateResult.Silent;
            }

            // A second item using the id of one the player approved: the game offers "Review and enable" here,
            // and approving moves the trust to the newcomer.
            if (!string.IsNullOrEmpty(input.ApprovedItem) && input.ApprovedItem != input.Item.ToString())
            {
                return new GateResult { Action = GateAction.Prompt, Key = "gate_hijack" };
            }

            if (input.Owner == 0)
            {
                return input.OwnerQueryFinished
                    ? new GateResult { Action = GateAction.Prompt, Key = "gate_unverified" }
                    : new GateResult { Action = GateAction.Wait, Key = "gate_wait" };
            }

            if (known?.FindImitated(input.ModId, input.ModName, input.ModAuthor, input.Item, input.Owner) != null)
            {
                return new GateResult { Action = GateAction.Prompt, Key = "gate_impersonation" };
            }
            return GateResult.Silent;
        }

        /// <summary>
        /// Identifies one warning the player has already seen. It changes when the mod, the verdict or the mod's state
        /// changes, so a warning read while a mod was inactive does not silence it once the mod is active.
        /// </summary>
        public static string AckKey(GateResult result, string modId, ulong item, bool active)
        {
            return string.Join("|", result.Key, modId, item, result.Entry?.Case ?? "", result.Entry?.Level.ToString() ?? "", result.Entry?.Reason ?? "", active ? "active" : "inactive");
        }
    }
}
