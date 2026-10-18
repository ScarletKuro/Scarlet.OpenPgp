using System.Globalization;
using System.Text;

namespace Scarlet.OpenPgp.Internal
{
    /// <summary>Makes text taken from the input safe to put in an error message.</summary>
    internal static class InputText
    {
        /// <summary>How much of the input text a message quotes.</summary>
        private const int MaxQuotedLength = 80;

        /// <summary>
        /// <paramref name="text"/> with control and formatting characters written as \uXXXX, cut
        /// to <see cref="MaxQuotedLength"/> characters. Messages end up in terminals and logs:
        /// quoted raw, an escape sequence in a hostile armor line could rewrite what the terminal
        /// shows - erase the error and print "signature verified." in its place - and a bidi
        /// override could reorder it.
        /// </summary>
        public static string Quote(string text)
        {
            var builder = new StringBuilder(System.Math.Min(text.Length, MaxQuotedLength) + 8);
            for (int i = 0; i < text.Length; i++)
            {
                if (i == MaxQuotedLength)
                {
                    builder.Append("...");
                    break;
                }

                char c = text[i];
                if (char.IsControl(c) || char.IsSurrogate(c) || CharUnicodeInfo.GetUnicodeCategory(c) == UnicodeCategory.Format)
                {
                    builder.Append("\\u").Append(((int)c).ToString("X4", CultureInfo.InvariantCulture));
                }
                else
                {
                    builder.Append(c);
                }
            }

            return builder.ToString();
        }
    }
}
