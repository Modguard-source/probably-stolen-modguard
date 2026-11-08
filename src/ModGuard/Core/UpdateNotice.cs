using System;
using System.Collections.Generic;
using System.Linq;

namespace ModGuard.Core
{
    public sealed class UpdateInput
    {
        /// <summary>The game found the files changed since the player approved them, and loaded them without asking.</summary>
        public bool UpdatedThisLaunch;
        public bool Active;
        /// <summary>The startup report already has a line for this mod, which says more than this notice would.</summary>
        public bool AlreadyReported;
        /// <summary>What the game's scanner found the new version using, all within what the player approved.</summary>
        public IEnumerable<string> Capabilities;
    }

    /// <summary>
    /// The game loads an approved mod's update without asking when it needs no new capabilities, and its code has run
    /// by the time the guard can say anything. Telling the player is all that is left, and only worth it where the
    /// approved capabilities would let an update do real harm: naming every update would teach players to skip the report.
    /// </summary>
    public static class UpdateNotice
    {
        /// <summary>The capabilities to name, in the order given; none means no notice.</summary>
        public static List<string> CapabilitiesToName(UpdateInput input, Func<string, bool> highRisk)
        {
            if (!input.UpdatedThisLaunch || !input.Active || input.AlreadyReported || input.Capabilities == null)
            {
                return new List<string>();
            }
            return input.Capabilities.Where(c => !string.IsNullOrEmpty(c)).Distinct(StringComparer.Ordinal).Where(highRisk).ToList();
        }

        /// <summary>One notice per version of a mod: the next update is news again.</summary>
        public static string AckKey(string modId, ulong item, string versionHash)
        {
            return string.Join("|", "updated", modId, item, versionHash ?? "");
        }
    }
}
