using System.Globalization;
using System.Text;

namespace ModGuard.Core
{
    /// <summary>Manifest text is written by the uploader, so it must not be able to restyle our dialogs.</summary>
    public static class TextSafe
    {
        /// <summary>
        /// Makes uploader text safe to show: angle brackets become full-width so TextMeshPro cannot read them
        /// as rich-text tags, and control and format characters (bidi overrides, zero-width marks) are dropped.
        /// </summary>
        public static string Clean(string text, int maxLength = 60)
        {
            if (string.IsNullOrEmpty(text))
            {
                return "?";
            }
            var sb = new StringBuilder(System.Math.Min(text.Length, maxLength + 1));
            foreach (char c in text)
            {
                UnicodeCategory category = char.GetUnicodeCategory(c);
                if (category == UnicodeCategory.Control || category == UnicodeCategory.Format
                    || category == UnicodeCategory.LineSeparator || category == UnicodeCategory.ParagraphSeparator)
                {
                    continue;
                }
                if (sb.Length >= maxLength)
                {
                    // Do not leave half of an emoji behind.
                    if (char.IsHighSurrogate(sb[sb.Length - 1]))
                    {
                        sb.Length--;
                    }
                    sb.Append('…');
                    break;
                }
                sb.Append(c == '<' ? '＜' : c == '>' ? '＞' : c);
            }
            return sb.Length == 0 ? "?" : sb.ToString();
        }

        /// <summary>Key for comparing display names: width-folded, lowercase, letters and digits only.</summary>
        public static string NameKey(string name)
        {
            if (string.IsNullOrEmpty(name))
            {
                return "";
            }
            string folded;
            try
            {
                folded = name.Normalize(NormalizationForm.FormKC);
            }
            catch (System.ArgumentException)
            {
                folded = name;
            }
            var sb = new StringBuilder(folded.Length);
            foreach (char c in folded)
            {
                if (char.IsLetterOrDigit(c))
                {
                    sb.Append(char.ToLowerInvariant(c));
                }
            }
            return sb.ToString();
        }
    }
}
