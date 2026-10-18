using System;
using System.Collections.Generic;
using System.Text;
using Scarlet.OpenPgp.Internal;

namespace Scarlet.OpenPgp.Armor
{
    /// <summary>
    /// Parses OpenPGP ASCII armor blocks (RFC 9580 §6.2): the "-----BEGIN PGP ...-----" /
    /// "-----END PGP ...-----" envelope, its headers, and its base64 body.
    /// </summary>
    /// <remarks>
    /// The CRC24 checksum line is optional and is not checked: RFC 9580 §6.1 says an implementation
    /// MUST NOT reject armor whose checksum is missing, malformed, or wrong. It only ever guarded
    /// against transmission damage, never tampering - the signature check covers that.
    /// </remarks>
    internal static class AsciiArmorReader
    {
        private const string BeginPrefix = "-----BEGIN PGP ";
        private const string EndPrefix = "-----END PGP ";
        private const string TailMarker = "-----";

        /// <summary>
        /// Reads the first armor block found in <paramref name="armorText"/>. Any framing problem
        /// within that block (missing BEGIN/END, mismatched labels, malformed base64) fails closed via
        /// <see cref="FailClosedException"/> rather than returning a partial result. Content before
        /// the BEGIN line or after the matching END line is not inspected; callers that must reject
        /// it (clearsigned messages) check for it themselves.
        /// </summary>
        public static AsciiArmorBlock Read(string armorText)
        {
            string[] lines = SplitLines(armorText);
            int i = 0;
            AsciiArmorBlock? block = ReadNext(lines, ref i);
            if (block is null)
            {
                throw new FailClosedException("No ASCII armor BEGIN line found.");
            }

            return block;
        }

        /// <summary>
        /// Reads every armor block in <paramref name="armorText"/>, in order - e.g. several key
        /// blocks concatenated into one file. Text between and around blocks is ignored. Fails
        /// closed if there is no block at all or any block is malformed.
        /// </summary>
        public static List<AsciiArmorBlock> ReadAll(string armorText)
        {
            string[] lines = SplitLines(armorText);
            var blocks = new List<AsciiArmorBlock>();
            int i = 0;
            while (ReadNext(lines, ref i) is { } block)
            {
                blocks.Add(block);
            }

            if (blocks.Count == 0)
            {
                throw new FailClosedException("No ASCII armor BEGIN line found.");
            }

            return blocks;
        }

        /// <summary>Reads the next block at or after line <paramref name="i"/>, leaving <paramref name="i"/> just past its END line; <c>null</c> when there are no more BEGIN lines.</summary>
        private static AsciiArmorBlock? ReadNext(string[] lines, ref int i)
        {
            while (i < lines.Length && !lines[i].StartsWith(BeginPrefix, StringComparison.Ordinal))
            {
                i++;
            }

            if (i == lines.Length)
            {
                return null;
            }

            string label = ExtractLabel(lines[i], BeginPrefix);
            i++;

            var headers = new List<KeyValuePair<string, string>>();
            while (i < lines.Length && lines[i].Length > 0)
            {
                int colon = lines[i].IndexOf(':');
                if (colon < 0)
                {
                    // No header block: the body starts right away (tolerated for robustness).
                    break;
                }

                string key = lines[i].Substring(0, colon).Trim();
                string value = lines[i].Substring(colon + 1).Trim();
                headers.Add(new KeyValuePair<string, string>(key, value));
                i++;
            }

            // Skip the blank line separating headers from the body.
            if (i < lines.Length && lines[i].Length == 0)
            {
                i++;
            }

            var bodyBuilder = new StringBuilder();
            while (i < lines.Length && !lines[i].StartsWith(EndPrefix, StringComparison.Ordinal))
            {
                // A line starting with '=' is the optional CRC24 checksum - base64 data lines can
                // only end with '=' padding, never start with it.
                if (!lines[i].StartsWith("=", StringComparison.Ordinal))
                {
                    bodyBuilder.Append(lines[i]);
                }

                i++;
            }

            if (i == lines.Length)
            {
                throw new FailClosedException("No ASCII armor END line found for label \"" + InputText.Quote(label) + "\".");
            }

            string endLabel = ExtractLabel(lines[i], EndPrefix);
            if (!string.Equals(endLabel, label, StringComparison.Ordinal))
            {
                throw new FailClosedException(
                    "ASCII armor END label \"" + InputText.Quote(endLabel) + "\" does not match BEGIN label \"" + InputText.Quote(label) + "\".");
            }

            i++;

            byte[] body;
            try
            {
                body = Convert.FromBase64String(bodyBuilder.ToString());
            }
            catch (FormatException ex)
            {
                throw new FailClosedException("ASCII armor body is not valid base64.", ex);
            }

            return new AsciiArmorBlock(label, headers, body);
        }

        private static string ExtractLabel(string line, string prefix)
        {
            string trimmed = line.TrimEnd(' ', '\t');
            if (!trimmed.EndsWith(TailMarker, StringComparison.Ordinal) || trimmed.Length < prefix.Length + TailMarker.Length)
            {
                throw new FailClosedException("Malformed armor boundary line: " + InputText.Quote(line));
            }

            return trimmed.Substring(prefix.Length, trimmed.Length - prefix.Length - TailMarker.Length);
        }

        private static string[] SplitLines(string text)
        {
            return text.Replace("\r\n", "\n").Replace("\r", "\n").Split('\n');
        }
    }
}
