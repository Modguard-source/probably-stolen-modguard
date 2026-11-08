using System;
using System.Reflection;
using HarmonyLib;
using ModGuard.Core;
using UnityEngine;

namespace ModGuard
{
    /// <summary>
    /// Both menu routes to approving a mod ("Activate" and "Review and enable") go through BeginEnable, and approval
    /// happens a launch before the mod's code first runs, so this check does not depend on load order. The guard only
    /// holds back the player's click: it never writes to the loader or to the player's approvals.
    /// </summary>
    [HarmonyPatch(typeof(ModUIManager), "BeginEnable")]
    internal static class Patch_BeginEnable
    {
        internal static readonly MethodInfo Target = AccessTools.Method(typeof(ModUIManager), "BeginEnable");

        private static string _continuing;

        [HarmonyPriority(Priority.First)]
        private static bool Prefix(ModUIManager __instance, LoadedMod mod, Action onApproved)
        {
            if (mod?.Manifest == null)
            {
                return true;
            }
            if (_continuing == mod.Manifest.ID)
            {
                _continuing = null;
                return true;
            }

            GateResult result;
            try
            {
                result = Guard.InspectForEnable(mod);
            }
            catch (Exception ex)
            {
                // Never fail open: a mod that manages to break the check still has to get past the player.
                Debug.LogError("[ModGuard] Could not check '" + mod.Manifest.ID + "': " + ex);
                result = new GateResult { Action = GateAction.Prompt, Key = "gate_error" };
            }

            if (result.Action == GateAction.Allow)
            {
                return true;
            }

            try
            {
                string heading = ModEntry.L(Guard.DialogKey(result) + "_head");
                string body = Guard.Describe(mod, result);
                switch (result.Action)
                {
                    case GateAction.Prompt:
                        Dialog.Show(heading, body, danger: false,
                            Dialog.CloseButton("btn_cancel"),
                            (ModEntry.L("btn_continue"), () => Continue(__instance, mod, onApproved)));
                        break;
                    default:
                        Dialog.Show(heading, body, danger: result.Action == GateAction.Block, Dialog.CloseButton());
                        break;
                }
            }
            catch (Exception ex)
            {
                // Still refuse the click. A broken dialog must not turn into an approval.
                Debug.LogError("[ModGuard] Could not show the warning for '" + mod.Manifest.ID + "' (" + result.Key + "): " + ex);
            }
            return false;
        }

        private static void Continue(ModUIManager instance, LoadedMod mod, Action onApproved)
        {
            Dialog.Close();
            _continuing = mod.Manifest.ID;
            try
            {
                Target.Invoke(instance, new object[] { mod, onApproved });
            }
            catch (Exception ex)
            {
                Debug.LogError("[ModGuard] Could not continue activating '" + mod.Manifest.ID + "': " + ex);
            }
            finally
            {
                _continuing = null;
            }
        }
    }

    /// <summary>Adds the guard's finding to the warning icon on the mod's row in the menu.</summary>
    [HarmonyPatch(typeof(ModUIManager), "GetModIssue")]
    internal static class Patch_GetModIssue
    {
        private static void Postfix(LoadedMod mod, ref string __result)
        {
            try
            {
                string line = Guard.IssueFor(mod);
                if (line != null)
                {
                    __result = string.IsNullOrEmpty(__result) ? line : __result + "\n" + line;
                }
            }
            catch (Exception ex)
            {
                Debug.LogError("[ModGuard] Could not add the row warning: " + ex);
            }
        }
    }
}
