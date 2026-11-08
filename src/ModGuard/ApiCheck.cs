using System;
using System.Collections.Generic;
using System.Linq;
using UnityEngine;

namespace ModGuard
{
    /// <summary>
    /// The game changes without a new version number, and Mod Guard calls into it. A game method that was removed or
    /// given another signature only fails when the code calling it first runs, and the guard catches such failures so
    /// that one broken check cannot take the others with it. That is how 0.2.0 stopped warning about new
    /// subscriptions on game Rev13 with nothing but a line in the log. So the startup report first runs each check
    /// once on the guard's own files, which shows nothing and writes nothing, and names every check that failed, on
    /// every launch, until an update of the guard fixes it.
    /// </summary>
    internal static class ApiCheck
    {
        /// <summary>The checks in the order the report lists them. Each is the key of its name in SelfText.</summary>
        internal static readonly string[] Features = { "api_activate", "api_installed", "api_rows", "api_startup" };

        private static readonly HashSet<string> Failed = new HashSet<string>(StringComparer.Ordinal);

        internal static bool AnyFailed => Failed.Count > 0;

        /// <summary>Runs one check. It fails when it throws, or when it returns false because the result shows the check did not do its job.</summary>
        internal static void Try(string feature, Func<bool> check)
        {
            try
            {
                if (check())
                {
                    return;
                }
                Debug.LogError("[ModGuard] Self-test at startup: " + feature + " gave a result that means it does not work.");
            }
            catch (Exception ex)
            {
                Debug.LogError("[ModGuard] Self-test at startup: " + feature + " failed: " + ex);
            }
            Failed.Add(feature);
        }

        internal static void Fail(string feature)
        {
            Failed.Add(feature);
        }

        internal static void FailAll()
        {
            Failed.UnionWith(Features);
        }

        /// <summary>
        /// In the built-in wording, like the self-check: the cause is the guard, not a mod the player picked, and the
        /// language files are read through the same game functions that may be what broke.
        /// </summary>
        internal static List<string> Lines()
        {
            if (Failed.Count == 0)
            {
                return new List<string>();
            }
            string names = string.Join("\n", Features.Where(Failed.Contains).Select(f => "- " + SelfText.Get(f)));
            return new List<string> { SelfText.Get("api_body", names) };
        }
    }
}
