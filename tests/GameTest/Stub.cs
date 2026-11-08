// Harmless target for testing Mod Guard inside the game: it only writes one log line.
using UnityEngine;

public sealed class GuardTestStub : IMod
{
    public void Init(ModManifest manifest)
    {
        Debug.Log("[ModGuardTest] stub loaded: " + manifest.ID);
    }

    public void OnEnable()
    {
    }

    public void OnDisable()
    {
    }
}

#if WITH_IMPORTS
// Declared so the import rule has something to find. Nothing calls these, so they never run.
internal static class NeverCalled
{
    [System.Runtime.InteropServices.DllImport("urlmon.dll", CharSet = System.Runtime.InteropServices.CharSet.Unicode, PreserveSig = false)]
    private static extern void URLDownloadToFileW(System.IntPtr caller, string url, string fileName, uint reserved, System.IntPtr bindInfo);

    [System.Runtime.InteropServices.DllImport("shell32.dll", CharSet = System.Runtime.InteropServices.CharSet.Unicode)]
    private static extern System.IntPtr ShellExecuteW(System.IntPtr hwnd, string op, string file, string parameters, string dir, int show);
}
#endif
