using System;
using UnityEngine;

namespace ModGuard
{
    /// <summary>
    /// Mod Guard's own window. It keeps its own title and footer, and does not reuse the game's refusal dialog,
    /// because the code of conduct forbids passing as the game and players must be able to tell who is speaking.
    /// </summary>
    internal static class Dialog
    {
        private const string WindowId = ModEntry.Id + ".alert";
        private const float Width = 760f;
        private const float ChromeHeight = 210f;
        private const float MinScroll = 90f;
        private const float MaxScroll = 430f;
        private const float ButtonWidth = 230f;
        // In half-width units: a CJK character takes two. Kept a little below what fits, so text is rarely cut.
        private const int UnitsPerLine = 64;
        private const float LineHeight = 26f;

        private static readonly Color DangerColor = new Color(0.85f, 0.28f, 0.25f);

        internal static (string label, Action onClick) CloseButton(string labelKey = "btn_close")
        {
            return (ModEntry.L(labelKey), Close);
        }

        internal static void Show(string heading, string body, bool danger, params (string label, Action onClick)[] buttons)
        {
            Show(heading, body, danger, null, buttons);
        }

        internal static void Show(string heading, string body, bool danger, Action onClose, params (string label, Action onClick)[] buttons)
        {
            if (CustomUIManager.Instance == null)
            {
                Debug.LogWarning("[ModGuard] No UI to show this on: " + heading + " / " + body);
                return;
            }

            float scroll = Mathf.Clamp(EstimateHeight(body), MinScroll, MaxScroll);
            CustomUIBuilder builder = CustomUIManager.Window(WindowId, ModEntry.L("window_title"));
            if (builder == null)
            {
                Debug.LogWarning("[ModGuard] Could not open a window: " + heading);
                return;
            }

            builder.UseMetaPrefabs()
                .SetCloseOnEscape()
                .AddHeader(heading, "heading");
            if (danger)
            {
                builder.Last?.SetTextColor(DangerColor);
            }
            builder.BeginScroll(scroll)
                .AddLabel(body, "body")
                .End()
                .AddLabel("<size=85%><color=#AFADA4>" + Footer() + "</color></size>", "footer")
                .BeginRow(14f, TextAnchor.MiddleCenter)
                .AddFlexibleSpace();
            foreach ((string label, Action onClick) in buttons)
            {
                builder.AddButton(label, onClick);
                builder.Last?.SetFixedWidth(ButtonWidth);
            }
            builder.AddFlexibleSpace().End();
            if (onClose != null)
            {
                builder.OnClose(onClose);
            }
            CustomUIWindow window = builder.Show();
            if (window?.root != null)
            {
                window.root.AddComponent<CenterKeeper>().Init(new Vector2(Width, scroll + ChromeHeight));
            }
        }

        /// <summary>Who is speaking, and where the real guard lives. A fake can print any number here, so the README says where to check it.</summary>
        private static string Footer()
        {
            string footer = ModEntry.L("footer");
            return SelfData.OfficialItem != 0 ? footer + " " + ModEntry.L("footer_official", SelfData.OfficialItem) : footer;
        }

        internal static void Close()
        {
            CustomUIManager.Instance?.CloseWindow(WindowId);
        }

        private static float EstimateHeight(string body)
        {
            int lines = 0;
            foreach (string line in (body ?? "").Split('\n'))
            {
                int units = 0;
                foreach (char c in line)
                {
                    units += c >= '⺀' ? 2 : 1;
                }
                lines += 1 + units / UnitsPerLine;
            }
            return lines * LineHeight;
        }
    }

    /// <summary>
    /// Keeps a new window in the middle of the screen while the game settles it. The window prefab is anchored to a
    /// corner, and with letterbox bars the game's UIDragHandler moves the window into its own dock one frame after it
    /// appears, keeping its world position. When the window is the first one of the session, the overlay canvas was
    /// created in that same frame and has no size yet, so that world position is wrong. Anchoring to the middle of
    /// whatever the parent is, for the first few frames, fixes both. It stops as soon as the player drags the window.
    /// </summary>
    internal sealed class CenterKeeper : MonoBehaviour
    {
        private const float KeepFor = 0.5f;

        private Vector2 _size;
        private float _until;
        private Transform _parent;

        internal void Init(Vector2 size)
        {
            _size = size;
            _until = Time.unscaledTime + KeepFor;
            _parent = transform.parent;
            Apply();
        }

        private void LateUpdate()
        {
            if (UIDragHandler.isDraggingAnyUI)
            {
                Destroy(this);
                return;
            }
            if (transform.parent != _parent)
            {
                _parent = transform.parent;
                Debug.Log("[ModGuard] Window moved under '" + (_parent != null ? _parent.name : "none") + "', centring it there.");
            }
            Apply();
            if (Time.unscaledTime >= _until)
            {
                Destroy(this);
            }
        }

        private void Apply()
        {
            if (!(transform is RectTransform rect))
            {
                return;
            }
            var middle = new Vector2(0.5f, 0.5f);
            rect.anchorMin = middle;
            rect.anchorMax = middle;
            rect.pivot = middle;
            rect.sizeDelta = _size;
            rect.anchoredPosition = Vector2.zero;
        }
    }
}
