using System;
using System.Collections.Generic;
using System.Text;
using Scarlet.OpenPgp.Internal;

namespace Scarlet.OpenPgp.Armor
{
    /// <summary>
    /// Parses a single OpenPGP ASCII armor block (RFC 4880 §6.2): the "-----BEGIN PGP ...-----" /
    /// "-----END PGP ...-----" envelope, its headers, and its base64 body, then verifies the
    /// trailing CRC24 checksum line against the decoded bytes.
    /// </summary>
    internal static class AsciiArmorReader
    {
        private const string BeginPrefix = "-----BEGIN PGP ";
        private const string EndPrefix = "-----END PGP ";
        private const string TailMarker = "-----";

        /// <summary>
        /// Reads the first armor block found in <paramref name="armorText"/>. Any framing problem
        /// within that block (missing BEGIN/END, malformed base64, missing or mismatched CRC24)
        /// fails closed via <see cref="FailClosedException"/> rather than returning a partial
        /// result. Content before the BEGIN line or after the matching END line - a mail/commentary
        /// preamble, unrelated trailing text, even a second concatenated block - is intentionally
        /// ignored: confirmed against real GnuPG 2.4.9, which tolerates exactly this (leading text
        /// before the armor, trailing text after it, and even multiple detached-signature packets
        /// concatenated in the same file) for both detached and clearsigned verification. This
        /// library's single-bool API only ever reports on the *first* block found, matching "take
        /// the first match" rather than gpg's fuller multi-signature handling - see SPEC.md.
        /// </summary>
        public static AsciiArmorBlock Read(string armorText)
        {
            string[] lines = SplitLines(armorText);

            int i = 0;
            while (i < lines.Length && !lines[i].StartsWith(BeginPrefix, StringComparison.Ordinal))
            {
                i++;
            }

            if (i == lines.Length)
            {
                throw new FailClosedException("No ASCII armor BEGIN line found.");
            }

            string label = ExtractLabel(lines[i], BeginPrefix);
            i++;

            var headers = new List<KeyValuePair<string, string>>();
            while (i < lines.Length && lines[i].Length > 0)
            {
                int colon = lines[i].IndexOf(':');
                if (colon < 0)
                {
                    throw new FailClosedException("Malformed armor header line: " + lines[i]);
                }

                string key = lines[i].Substring(0, colon).Trim();
                string value = lines[i].Substring(colon + 1).Trim();
                headers.Add(new KeyValuePair<string, string>(key, value));
                i++;
            }

            // Skip the single blank line separating headers from the body. Its absence (body
            // starting immediately) is tolerated for robustness, but headers must be terminated
            // by *something* recognizable - we already stopped at the first non-header-shaped line.
            if (i < lines.Length && lines[i].Length == 0)
            {
                i++;
            }

            var bodyBuilder = new StringBuilder();
            string? crcLine = null;
            while (i < lines.Length && !lines[i].StartsWith(EndPrefix, StringComparison.Ordinal))
            {
                if (lines[i].StartsWith("=", StringComparison.Ordinal) && lines[i].Length == 5)
                {
                    crcLine = lines[i];
                    i++;
                    continue;
                }

                bodyBuilder.Append(lines[i]);
                i++;
            }

            if (i == lines.Length)
            {
                throw new FailClosedException("No ASCII armor END line found for label \"" + label + "\".");
            }

            string endLabel = ExtractLabel(lines[i], EndPrefix);
            if (!string.Equals(endLabel, label, StringComparison.Ordinal))
            {
                throw new FailClosedException(
                    "ASCII armor END label \"" + endLabel + "\" does not match BEGIN label \"" + label + "\".");
            }

            if (crcLine is null)
            {
                throw new FailClosedException("ASCII armor block is missing its CRC24 checksum line.");
            }

            byte[] body;
            try
            {
                body = Convert.FromBase64String(bodyBuilder.ToString());
            }
            catch (FormatException ex)
            {
                throw new FailClosedException("ASCII armor body is not valid base64.", ex);
            }

            int expectedCrc = DecodeCrcLine(crcLine);
            int actualCrc = Crc24.Compute(body);
            if (expectedCrc != actualCrc)
            {
                throw new FailClosedException("ASCII armor CRC24 checksum does not match the decoded body.");
            }

            // Anything after this point (more text, a second armor block) is deliberately not
            // inspected - see this method's doc comment.
            return new AsciiArmorBlock(label, headers, body);
        }

        private static string ExtractLabel(string line, string prefix)
        {
            if (!line.EndsWith(TailMarker, StringComparison.Ordinal) || line.Length < prefix.Length + TailMarker.Length)
            {
                throw new FailClosedException("Malformed armor boundary line: " + line);
            }

            return line.Substring(prefix.Length, line.Length - prefix.Length - TailMarker.Length);
        }

        private static int DecodeCrcLine(string crcLine)
        {
            // "=XXXX" where XXXX is the base64 encoding of the 3-byte (24-bit) CRC.
            byte[] crcBytes;
            try
            {
                crcBytes = Convert.FromBase64String(crcLine.Substring(1));
            }
            catch (FormatException ex)
            {
                throw new FailClosedException("ASCII armor CRC24 line is not valid base64.", ex);
            }

            if (crcBytes.Length != 3)
            {
                throw new FailClosedException("ASCII armor CRC24 line did not decode to 3 bytes.");
            }

            return (crcBytes[0] << 16) | (crcBytes[1] << 8) | crcBytes[2];
        }

        private static string[] SplitLines(string text)
        {
            return text.Replace("\r\n", "\n").Replace("\r", "\n").Split('\n');
        }
    }
}
