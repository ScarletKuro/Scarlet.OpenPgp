using System;
using System.Collections.Generic;
using Scarlet.OpenPgp.Armor;
using Scarlet.OpenPgp.Hashing;
using Scarlet.OpenPgp.Internal;

namespace Scarlet.OpenPgp.Clearsign
{
    /// <summary>
    /// Splits a clearsigned message (RFC 9580 §7) into its dash-escaped body lines, its "Hash"
    /// armor headers, and its trailing signature armor block.
    /// </summary>
    /// <remarks>
    /// Unlike a detached signature or a key block, a clearsigned message carries its signed content
    /// in the same text as everything else, so any text the parser tolerates but doesn't sign is
    /// text a caller can mistake for signed content. The parser is therefore strict about
    /// everything outside the signed lines: only blank lines may precede the BEGIN line or follow
    /// the END line, only well-formed "Hash" armor headers are accepted (RFC 9580 §7.1 requires
    /// declining anything else; their contents are otherwise ignored, §6.2.2.3), every body line
    /// starting with '-' must be dash-escaped, and a bare CR is rejected rather than being guessed
    /// at as a line break.
    /// </remarks>
    internal static class ClearsignParser
    {
        private const string BeginSignedMessage = "-----BEGIN PGP SIGNED MESSAGE-----";
        private const string BeginSignature = "-----BEGIN PGP SIGNATURE-----";
        private const string EndSignature = "-----END PGP SIGNATURE-----";
        private const string HashHeaderKey = "Hash";

        public static ClearsignMessage Parse(string clearsignedMessage)
        {
            string[] lines = SplitLines(clearsignedMessage);

            int i = 0;
            while (i < lines.Length && IsBlank(lines[i]))
            {
                i++;
            }

            if (i == lines.Length || !string.Equals(lines[i], BeginSignedMessage, StringComparison.Ordinal))
            {
                throw new FailClosedException("Expected \"" + BeginSignedMessage + "\" as the first non-blank line; unsigned text before it is not allowed.");
            }

            i++; // past the BEGIN line

            // Armor headers until the blank line separating them from the body. Only "Hash" is
            // meaningful here, and anything else is unsigned text sitting right above the signed body.
            var hashHeaderAlgorithms = new List<HashAlgorithmId>();
            while (i < lines.Length && lines[i].Length > 0)
            {
                ParseHashHeader(lines[i], hashHeaderAlgorithms);
                i++;
            }

            if (i == lines.Length)
            {
                throw new FailClosedException("Clearsigned message has no blank line after its armor headers.");
            }

            i++; // past the blank separator line

            int bodyStart = i;
            while (i < lines.Length && !string.Equals(lines[i], BeginSignature, StringComparison.Ordinal))
            {
                // RFC 4880 §7.1: every line starting with '-' is dash-escaped as "- ". An unescaped
                // one is malformed, and could be an attempt to smuggle in a second armor boundary.
                if (lines[i].StartsWith("-", StringComparison.Ordinal) && !lines[i].StartsWith("- ", StringComparison.Ordinal))
                {
                    throw new FailClosedException("Clearsigned body line starts with '-' but is not dash-escaped.");
                }

                i++;
            }

            if (i == lines.Length)
            {
                throw new FailClosedException("No \"" + BeginSignature + "\" line found after the message body.");
            }

            var bodyLines = new string[i - bodyStart];
            Array.Copy(lines, bodyStart, bodyLines, 0, bodyLines.Length);

            int signatureStart = i;
            while (i < lines.Length && !string.Equals(lines[i], EndSignature, StringComparison.Ordinal))
            {
                i++;
            }

            if (i == lines.Length)
            {
                throw new FailClosedException("No \"" + EndSignature + "\" line found.");
            }

            for (int j = i + 1; j < lines.Length; j++)
            {
                if (!IsBlank(lines[j]))
                {
                    throw new FailClosedException("Unsigned text after \"" + EndSignature + "\" is not allowed.");
                }
            }

            string signatureArmorText = string.Join("\n", lines, signatureStart, i - signatureStart + 1);
            AsciiArmorBlock signatureArmor = AsciiArmorReader.Read(signatureArmorText);

            return new ClearsignMessage(bodyLines, hashHeaderAlgorithms, signatureArmor);
        }

        private static void ParseHashHeader(string line, List<HashAlgorithmId> algorithms)
        {
            int colon = line.IndexOf(':');
            if (colon < 0 || !string.Equals(line.Substring(0, colon), HashHeaderKey, StringComparison.Ordinal))
            {
                throw new FailClosedException("Only \"Hash\" armor headers are allowed in a clearsigned message.");
            }

            foreach (string name in line.Substring(colon + 1).Split(','))
            {
                algorithms.Add(ParseHashName(name.Trim()));
            }
        }

        private static HashAlgorithmId ParseHashName(string name)
        {
            switch (name)
            {
                case "MD5":
                    return HashAlgorithmId.Md5;
                case "SHA1":
                    return HashAlgorithmId.Sha1;
                case "RIPEMD160":
                    return HashAlgorithmId.Ripemd160;
                case "SHA224":
                    return HashAlgorithmId.Sha224;
                case "SHA256":
                    return HashAlgorithmId.Sha256;
                case "SHA384":
                    return HashAlgorithmId.Sha384;
                case "SHA512":
                    return HashAlgorithmId.Sha512;
                case "SHA3-256":
                    return HashAlgorithmId.Sha3_256;
                case "SHA3-512":
                    return HashAlgorithmId.Sha3_512;
                default:
                    throw new FailClosedException("Unrecognized hash algorithm name in clearsign \"Hash\" header.");
            }
        }

        private static bool IsBlank(string line) => line.TrimEnd(' ', '\t').Length == 0;

        private static string[] SplitLines(string text)
        {
            // A leading byte-order mark is an encoding artifact, not content.
            if (text.Length > 0 && text[0] == '﻿')
            {
                text = text.Substring(1);
            }

            string normalized = text.Replace("\r\n", "\n");
            if (normalized.IndexOf('\r') >= 0)
            {
                throw new FailClosedException("Clearsigned message contains a bare CR; only LF and CRLF line endings are accepted.");
            }

            return normalized.Split('\n');
        }
    }
}
