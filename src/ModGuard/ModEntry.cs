using System.Linq;
using HarmonyLib;
using UnityEngine;

namespace ModGuard
{
    public sealed class ModEntry : IMod
    {
        public const string Id = "modguard.fjwjmmc";

        private GameObject _runner;

        /// <summary>A message from the language files, or the built-in one once those files turn out to have been changed.</summary>
        internal static string L(string key, params object[] args)
        {
            try
            {
                SelfCheck.Run();
                if (SelfCheck.TextTrusted)
                {
                    return ModHelper.GetLocalized(Id, key, args);
                }
            }
            catch (System.Exception)
            {
                // A game update broke the self-check or the game's text lookup. The startup report says so; the
                // built-in text keeps every dialog, that one included, able to show.
            }
            return SelfText.Get(key, args);
        }

        public void Init(ModManifest manifest)
        {
            // This mod is not in ModLoader.Mods yet, so its files cannot be read here. Guard loads them on first use.
        }

        public void OnEnable()
        {
            ModWorkshop.OnItemInstalled -= Guard.OnItemInstalled;
            ModWorkshop.OnItemInstalled += Guard.OnItemInstalled;
            ModWorkshop.OnDetailsUpdated -= Guard.OnDetailsUpdated;
            ModWorkshop.OnDetailsUpdated += Guard.OnDetailsUpdated;
            _runner = new GameObject("ModGuardRunner");
            Object.DontDestroyOnLoad(_runner);
            _runner.AddComponent<GuardRunner>();
        }

        public void OnDisable()
        {
            ModWorkshop.OnItemInstalled -= Guard.OnItemInstalled;
            ModWorkshop.OnDetailsUpdated -= Guard.OnDetailsUpdated;
            if (_runner != null)
            {
                Object.Destroy(_runner);
                _runner = null;
            }
        }
    }

    /// <summary>Waits for the main menu to show the startup report, then watches that the activation check stays in place.</summary>
    internal sealed class GuardRunner : MonoBehaviour
    {
        private const float MinWait = 1.5f;
        private const float MaxWaitForSteam = 10f;
        private const float CheckEvery = 10f;

        private float _started;
        private float _nextCheck;
        private bool _reported;
        private bool _tamperWarned;
        private bool _selfChecked;

        private void Start()
        {
            _started = Time.unscaledTime;
            _nextCheck = _started + CheckEvery;
            // As early as the guard can read its own files, so a Steam update arriving during the first seconds of a
            // session finds the check already done against the files the game loaded with.
            // The list is read right after, so what gets used is what was just checked.
            _selfChecked = TryLoad();
        }

        private void Update()
        {
            if (!_selfChecked)
            {
                _selfChecked = TryLoad();
            }
            float now = Time.unscaledTime;
            if (!_reported && MenuReady(now - _started))
            {
                _reported = true;
                Guard.RunStartupReport();
            }
            if (now >= _nextCheck)
            {
                _nextCheck = now + CheckEvery;
                CheckPatch();
            }
        }

        /// <summary>
        /// False while the game has not registered the guard yet. An exception here would end this Update every frame
        /// before the startup report, so it counts as done: the report loads again and tells the player what broke.
        /// </summary>
        private static bool TryLoad()
        {
            try
            {
                return Guard.EnsureLoaded();
            }
            catch (System.Exception)
            {
                return true;
            }
        }

        private static bool MenuReady(float waited)
        {
            if (waited < MinWait || CustomUIManager.Instance == null || MainMenuUIController.Instance == null)
            {
                return false;
            }
            return waited >= MaxWaitForSteam
                || !ModLoader.Mods.Any(m => m.WorkshopId != 0 && ModWorkshop.IsDetailsPending(m.WorkshopId));
        }

        /// <summary>
        /// A mod running with the same rights can remove this check. Noticing that is the most this mod can do:
        /// the game's own guard re-installs itself, but a removal here means something hostile is already running.
        /// </summary>
        private void CheckPatch()
        {
            if (_tamperWarned)
            {
                return;
            }
            Patches info = Harmony.GetPatchInfo(Patch_BeginEnable.Target);
            if (info != null && info.Prefixes.Any(p => p.owner == "mod." + ModEntry.Id))
            {
                return;
            }
            _tamperWarned = true;
            Debug.LogError("[ModGuard] The check on mod activation was removed while the game was running.");
            Dialog.Show(ModEntry.L("tamper_head"), ModEntry.L("tamper_body"), danger: true, Dialog.CloseButton());
        }
    }
}
