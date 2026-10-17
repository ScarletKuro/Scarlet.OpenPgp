using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using Scarlet.OpenPgp.Internal;

namespace Scarlet.OpenPgp.Armor
{
    /// <summary>
    /// Turns caller-supplied signature or key input into raw packet bytes, accepting both encodings
    /// GnuPG produces: ASCII armor (.asc) and binary packets (.sig, .gpg). Armor is recognized by its
    /// "-----BEGIN PGP " line; binary input can never start that way, because every packet's first
    /// octet has its high bit set.
    /// </summary>
    internal static class PacketInput
    {
        private const string BeginMarker = "-----BEGIN PGP ";

        private static readonly UTF8Encoding StrictUtf8 = new UTF8Encoding(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true);

        /// <summary>
        /// Returns the packet bytes of <paramref name="input"/>. Armored input may hold several
        /// blocks (e.g. concatenated key files); every block must carry <paramref name="expectedLabel"/>
        /// and their bodies are concatenated.
        /// </summary>
        public static byte[] Decode(ReadOnlySpan<byte> input, string expectedLabel)
        {
            if (!LooksArmored(input))
            {
                if (input.IsEmpty)
                {
                    throw new FailClosedException("Input is empty.");
                }

                return input.ToArray();
            }

            string text;
            try
            {
                text = StrictUtf8.GetString(input.ToArray());
            }
            catch (DecoderFallbackException ex)
            {
                throw new FailClosedException("ASCII-armored input is not valid UTF-8.", ex);
            }

            return Decode(text, expectedLabel);
        }

        /// <summary>Returns the packet bytes of armored <paramref name="armorText"/> (see <see cref="Decode(ReadOnlySpan{byte}, string)"/>).</summary>
        public static byte[] Decode(string armorText, string expectedLabel)
        {
            List<AsciiArmorBlock> blocks = AsciiArmorReader.ReadAll(armorText);
            using var packets = new MemoryStream();
            foreach (AsciiArmorBlock block in blocks)
            {
                if (!string.Equals(block.Label, expectedLabel, StringComparison.Ordinal))
                {
                    throw new FailClosedException("Expected a \"" + expectedLabel + "\" armor block, found \"" + block.Label + "\".");
                }

                packets.Write(block.Body, 0, block.Body.Length);
            }

            return packets.ToArray();
        }

        private static bool LooksArmored(ReadOnlySpan<byte> input)
        {
            int i = 0;
            if (input.Length >= 3 && input[0] == 0xEF && input[1] == 0xBB && input[2] == 0xBF)
            {
                i = 3; // UTF-8 byte-order mark
            }

            // Armor may be preceded by blank lines or other text (a mail preamble, say); binary
            // packets can't contain a "-----BEGIN PGP " line at the start, so look for the marker at
            // the start of any line within leading ASCII text.
            while (i < input.Length)
            {
                byte b = input[i];
                if (b >= 0x80)
                {
                    return false; // binary packet data (or non-ASCII text, which armor never starts with)
                }

                if (MatchesAt(input, i, BeginMarker))
                {
                    return true;
                }

                // Skip to the next line.
                while (i < input.Length && input[i] != (byte)'\n')
                {
                    if (input[i] >= 0x80)
                    {
                        return false;
                    }

                    i++;
                }

                i++;
            }

            return false;
        }

        private static bool MatchesAt(ReadOnlySpan<byte> input, int offset, string marker)
        {
            if (input.Length - offset < marker.Length)
            {
                return false;
            }

            for (int i = 0; i < marker.Length; i++)
            {
                if (input[offset + i] != (byte)marker[i])
                {
                    return false;
                }
            }

            return true;
        }
    }
}
