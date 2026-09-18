using System;
using Scarlet.OpenPgp.Armor;
using Scarlet.OpenPgp.Internal;

namespace Scarlet.OpenPgp.Clearsign
{
    /// <summary>Splits a clearsigned message (RFC 4880 §7) into its dash-escaped body lines and its trailing signature armor block.</summary>
    internal static class ClearsignParser
    {
        private const string BeginSignedMessage = "-----BEGIN PGP SIGNED MESSAGE-----";
        private const string BeginSignature = "-----BEGIN PGP SIGNATURE-----";

        public static ClearsignMessage Parse(string clearsignedMessage)
        {
            string[] lines = SplitLines(clearsignedMessage);

            int i = 0;
            while (i < lines.Length && !string.Equals(lines[i], BeginSignedMessage, StringComparison.Ordinal))
            {
                i++;
            }

            if (i == lines.Length)
            {
                throw new FailClosedException("No \"" + BeginSignedMessage + "\" line found.");
            }

            i++; // past the BEGIN line

            // Armor headers (e.g. "Hash: SHA256") until the blank line separating them from the body.
            while (i < lines.Length && lines[i].Length > 0)
            {
                i++;
            }

            if (i < lines.Length && lines[i].Length == 0)
            {
                i++;
            }

            int bodyStart = i;
            while (i < lines.Length && !string.Equals(lines[i], BeginSignature, StringComparison.Ordinal))
            {
                i++;
            }

            if (i == lines.Length)
            {
                throw new FailClosedException("No \"" + BeginSignature + "\" line found after the message body.");
            }

            var bodyLines = new string[i - bodyStart];
            Array.Copy(lines, bodyStart, bodyLines, 0, bodyLines.Length);

            string signatureArmorText = string.Join("\n", lines, i, lines.Length - i);
            AsciiArmorBlock signatureArmor = AsciiArmorReader.Read(signatureArmorText);

            if (!string.Equals(signatureArmor.Label, "SIGNATURE", StringComparison.Ordinal))
            {
                throw new FailClosedException("Expected a SIGNATURE armor block, found \"" + signatureArmor.Label + "\".");
            }

            return new ClearsignMessage(bodyLines, signatureArmor);
        }

        private static string[] SplitLines(string text)
        {
            return text.Replace("\r\n", "\n").Replace("\r", "\n").Split('\n');
        }
    }
}
