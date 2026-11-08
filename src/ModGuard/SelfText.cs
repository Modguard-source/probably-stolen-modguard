using System;
using System.Collections.Generic;
using UnityEngine.Localization;

namespace ModGuard
{
    /// <summary>
    /// Messages built into the DLL. The self-check messages always come from here, and every message does once the
    /// guard's language files have been changed: a repackaged copy must not be able to put its own words, a link
    /// for instance, into the guard's mouth. Only the DLL itself is trusted, which is why this is code and not a csv.
    /// </summary>
    internal static class SelfText
    {
        private static readonly Dictionary<string, (string zh, string en)> Texts = new Dictionary<string, (string zh, string en)>(StringComparer.Ordinal)
        {
            ["window_title"] = ("模组守卫", "Mod Guard"),
            ["footer"] = ("这条提示来自第三方模组「模组守卫」，不是游戏或开发者发出的。没有警告不代表安全。",
                "This notice comes from the third-party mod Mod Guard, not from the game or its developers. No warning does not mean a mod is safe."),
            ["footer_official"] = ("官方工坊条目编号：{0}。", "Official Workshop item: {0}."),
            ["btn_close"] = ("关闭", "Close"),
            ["btn_cancel"] = ("取消", "Cancel"),
            ["btn_continue"] = ("仍要启用", "Activate anyway"),
            ["btn_open_menu"] = ("打开模组菜单", "Open the mod menu"),
            ["source_workshop"] = ("工坊条目 {0}", "Workshop item {0}"),
            ["source_local"] = ("本地模组", "local mod"),

            ["self_head"] = ("这份模组守卫可能被改过", "This copy of Mod Guard may have been altered"),
            ["self_files"] = ("模组守卫自己的文件和发布时不一致：{0}。有人改过后重新打包，或者下载不完整，都会这样。改过的名单不会被使用。如果它来自官方工坊条目，请在 Steam 里取消订阅后重新订阅。",
                "Mod Guard's own files differ from the release: {0}. A repackaged copy looks like this, and so does an incomplete download. A changed list is not used. If it comes from the official Workshop item, unsubscribe and subscribe again in Steam."),
            ["self_text"] = ("它的提示文字被改过，所以现在只显示内置的简短提示。",
                "Its messages were changed, so only the built-in short messages are shown."),
            ["self_identity"] = ("这份模组守卫来自{0}，不是官方工坊条目（编号 {1}）。有人重新上传或打包它时，可能夹带了别的东西。",
                "This copy of Mod Guard comes from {0}, not from the official Workshop item ({1}). Someone re-uploading or repackaging it may have added something."),
            ["self_advice"] = ("请在模组菜单里停用它，取消订阅或删除它，只使用官方条目。如果这是你自己从源码构建的，可以忽略这条提示。",
                "Deactivate it in the mod menu, unsubscribe from it or delete it, and use only the official item. If you built it yourself from source, you can ignore this."),

            ["self_active_malicious"] = ("已启用且被判定为恶意：{0}。请在模组菜单里停用它，重启游戏后取消订阅，用杀毒软件扫描，并修改 Steam 密码。",
                "Active and judged malicious: {0}. Deactivate it in the mod menu, restart the game, unsubscribe, run a virus scan and change your Steam password."),
            ["self_more"] = ("另有 {0} 条警告。提示文字被改过，没法逐条说明，请看模组菜单里的警告图标。",
                "{0} more warnings. The messages were changed, so they cannot be shown one by one. See the warning icons in the mod menu."),
            ["list_sep"] = ("、", ", "),
            ["self_duplicate_guard"] = ("另一个已订阅的工坊条目也用了模组守卫的模组 ID，可能是仿冒品。请取消订阅不是官方的那个。",
                "Another subscribed Workshop item uses Mod Guard's mod ID and may be a fake. Unsubscribe from the one that is not official."),

            // What the guard does must stay clear even when its messages cannot be trusted: a block must not read as
            // "could not check". Only the cleaned mod name {0} and its source {1} go in.
            ["gate_confirmed_head"] = ("已阻止启用", "Activation blocked"),
            ["gate_confirmed_body"] = ("{0}（{1}）在模组守卫的名单上，已阻止启用。模组守卫自己的提示文字被改过，所以不显示详细原因。",
                "{0} ({1}) is on Mod Guard's list, so activating it was blocked. Mod Guard's own messages were changed, so the details are not shown."),
            ["gate_native_dropper_head"] = ("已阻止启用：这个模组能下载并运行程序", "Activation blocked: this mod can download and run programs"),
            ["gate_native_dropper_body"] = ("{0}（{1}）既能联网，又能启动程序，已阻止启用。模组守卫自己的提示文字被改过，所以不显示详细内容。",
                "{0} ({1}) can both reach the internet and start programs, so activating it was blocked. Mod Guard's own messages were changed, so the details are not shown."),
            ["gate_suspect_head"] = ("启用前请想一想", "Think before activating this"),
            ["gate_suspect_body"] = ("{0}（{1}）被标记为可疑。模组守卫自己的提示文字被改过，所以不显示原因。只有信任作者时才启用它。",
                "{0} ({1}) is flagged as suspicious. Mod Guard's own messages were changed, so the reason is not shown. Activate it only if you trust its author."),
            ["gate_list_broken_head"] = ("模组守卫无法比对名单", "Mod Guard cannot check its list"),
            ["gate_list_broken_body"] = ("模组守卫的名单不可用，没能检查 {0}（{1}）。请只使用官方工坊条目里的模组守卫。只有信任作者时才启用它。",
                "Mod Guard's list is not usable, so it could not check {0} ({1}). Use Mod Guard only from its official Workshop item. Activate this mod only if you trust its author."),
            ["gate_fake_guard_head"] = ("这可能是仿冒的模组守卫", "This may be a fake Mod Guard"),
            ["gate_fake_guard_body"] = ("{0}（{1}）自称模组守卫，但不是官方条目。只有确定它的来源时才启用它。",
                "{0} ({1}) calls itself Mod Guard but is not the official item. Activate it only if you are sure where it comes from."),

            ["generic_head"] =("模组守卫无法可靠地检查", "Mod Guard cannot check reliably"),
            ["generic_body"] = ("模组守卫自己的文件被改过，这条提示的原文不可信，所以不显示。请只使用官方工坊条目里的模组守卫。",
                "Mod Guard's own files were changed, so the original text of this message cannot be trusted and is not shown. Use Mod Guard only from its official Workshop item."),
        };

        internal static string Get(string key, params object[] args)
        {
            if (!Texts.TryGetValue(key, out (string zh, string en) pair))
            {
                pair = Texts[key.EndsWith("_head", StringComparison.Ordinal) ? "generic_head" : "generic_body"];
            }
            string text = Chinese() ? pair.zh : pair.en;
            if (args == null || args.Length == 0)
            {
                return text;
            }
            try
            {
                return string.Format(text, args);
            }
            catch (FormatException)
            {
                return text;
            }
        }

        private static bool Chinese()
        {
            try
            {
                Locale locale = ModHelper.GetCurrentLocale();
                return locale != null && locale.Identifier.Code.StartsWith("zh", StringComparison.OrdinalIgnoreCase);
            }
            catch (Exception)
            {
                return false;
            }
        }
    }
}
