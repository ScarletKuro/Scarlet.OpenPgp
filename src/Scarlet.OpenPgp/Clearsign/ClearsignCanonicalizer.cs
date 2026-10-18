using System;
using System.Text;
using Scarlet.OpenPgp.Internal;

namespace Scarlet.OpenPgp.Clearsign
{
    /// <summary>
    /// Canonicalizes clearsigned message text before hashing (RFC 4880 §7.1, §5.2.1): each line is
    /// dash-unescaped (a leading "- " marks a line that originally started with "-", added purely to
    /// keep it from being mistaken for the signature armor boundary), then has its trailing
    /// whitespace stripped, then the lines are rejoined with CRLF *between* them only - no trailing
    /// CRLF after the final line. The wire format always shows a line break before
    /// "-----BEGIN PGP SIGNATURE-----" (the armor boundary must start its own line), but that break
    /// is a framing artifact, not signed content: confirmed empirically against a real production
    /// signature (Bun's SHASUMS256.txt.asc) whose own source file has no trailing newline, and whose
    /// hash only matches when no CRLF is added after the last line.
    /// </summary>
    internal static class ClearsignCanonicalizer
    {
        // Strict: the default Encoding.UTF8 silently turns a lone surrogate into U+FFFD's bytes, so
        // two different strings could canonicalize to the same signed bytes.
        private static readonly UTF8Encoding StrictUtf8 = new UTF8Encoding(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true);

        /// <summary>The canonical signed text as a string: exactly the text the signature covers.</summary>
        public static string CanonicalizeText(string[] dashEscapedLines)
        {
            // Each line is appended as a range: unescaping and trimming only move its start and end.
            // The builder is deliberately not pre-sized - for a large message that would be one
            // large-object-heap buffer per call, which measured worse than its default small chunks.
            var builder = new StringBuilder();
            for (int i = 0; i < dashEscapedLines.Length; i++)
            {
                if (i > 0)
                {
                    builder.Append("\r\n");
                }

                string line = dashEscapedLines[i];
                int start = line.StartsWith("- ", StringComparison.Ordinal) ? 2 : 0;
                int end = line.Length;
                while (end > start && (line[end - 1] == ' ' || line[end - 1] == '\t'))
                {
                    end--;
                }

                builder.Append(line, start, end - start);
            }

            return builder.ToString();
        }

        public static byte[] Encode(string canonicalText)
        {
            try
            {
                return StrictUtf8.GetBytes(canonicalText);
            }
            catch (EncoderFallbackException ex)
            {
                throw new FailClosedException("Clearsigned text is not valid Unicode (unpaired surrogate).", ex);
            }
        }
    }
}
