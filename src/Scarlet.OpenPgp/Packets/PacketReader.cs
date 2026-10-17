using System.Collections.Generic;
using System;
using Scarlet.OpenPgp.Internal;

namespace Scarlet.OpenPgp.Packets
{
    /// <summary>A single parsed OpenPGP packet: its tag and fully-assembled body.</summary>
    internal sealed class Packet(PacketHeader header, byte[] body)
    {
        public PacketHeader Header { get; } = header;

        public byte[] Body { get; } = body;
    }

    /// <summary>
    /// Reads a flat sequence of OpenPGP packets (RFC 4880 §4.2) from a byte buffer. Understands both
    /// old-format and new-format packet headers, including new-format partial-body-length framing
    /// (§4.2.2.4), which it transparently concatenates into a single logical body per packet. Any
    /// truncation or malformed length encoding fails closed.
    /// </summary>
    internal static class PacketReader
    {
        public static List<Packet> ReadAll(byte[] data)
        {
            var packets = new List<Packet>();
            int position = 0;
            while (position < data.Length)
            {
                packets.Add(ReadOne(data, ref position));
            }

            return packets;
        }

        private static Packet ReadOne(byte[] data, ref int position)
        {
            byte tagByte = ReadByte(data, ref position, "packet tag");
            if ((tagByte & 0x80) == 0)
            {
                throw new FailClosedException("Packet tag byte does not have the mandatory high bit set.");
            }

            bool newFormat = (tagByte & 0x40) != 0;
            byte rawTag;

            // Where the body lies in the input: one segment, or several for partial-length framing.
            // Located first and copied once at its final size - no growing buffer, no second copy.
            var body = new List<Segment>(1);

            if (newFormat)
            {
                rawTag = (byte)(tagByte & 0x3F);
                ReadNewFormatBody(data, ref position, rawTag, body);
            }
            else
            {
                rawTag = (byte)((tagByte & 0x3C) >> 2);
                int lengthType = tagByte & 0x03;
                ReadOldFormatBody(data, ref position, lengthType, body);
            }

            var header = new PacketHeader((PacketTag)rawTag, rawTag);
            return new Packet(header, IsBodyIgnored(header.Tag) ? [] : Materialize(data, body));
        }

        /// <summary>
        /// Packet types whose bodies no consumer reads: Marker and Padding are defined to be ignored
        /// (RFC 9580 §5.8, §5.15), and Trust packets are local keyring data with no meaning here.
        /// Their bodies are skipped without being copied - a padding packet can be arbitrarily large.
        /// </summary>
        private static bool IsBodyIgnored(PacketTag tag) => tag == PacketTag.Marker || tag == PacketTag.Padding || tag == PacketTag.Trust;

        private static byte[] Materialize(byte[] data, List<Segment> segments)
        {
            if (segments.Count == 1)
            {
                return data.AsSpan(segments[0].Offset, segments[0].Length).ToArray();
            }

            // Partial-length chunks all lie within the input, so their total fits in an array.
            long total = 0;
            foreach (Segment segment in segments)
            {
                total += segment.Length;
            }

            var body = new byte[total];
            int offset = 0;
            foreach (Segment segment in segments)
            {
                Array.Copy(data, segment.Offset, body, offset, segment.Length);
                offset += segment.Length;
            }

            return body;
        }

        private readonly struct Segment(int offset, int length)
        {
            public int Offset { get; } = offset;

            public int Length { get; } = length;
        }

        private static void ReadOldFormatBody(byte[] data, ref int position, int lengthType, List<Segment> body)
        {
            int length;
            switch (lengthType)
            {
                case 0:
                    length = ReadByte(data, ref position, "old-format 1-byte length");
                    break;
                case 1:
                    length = (ReadByte(data, ref position, "old-format 2-byte length") << 8)
                             | ReadByte(data, ref position, "old-format 2-byte length");
                    break;
                case 2:
                    length = (ReadByte(data, ref position, "old-format 4-byte length") << 24)
                             | (ReadByte(data, ref position, "old-format 4-byte length") << 16)
                             | (ReadByte(data, ref position, "old-format 4-byte length") << 8)
                             | ReadByte(data, ref position, "old-format 4-byte length");
                    break;
                case 3:
                    // Indeterminate length: the body runs to the end of the buffer. Only sound when
                    // this packet is the last one in the stream, which we don't otherwise enforce -
                    // if more packets were expected after it, they'd simply be swallowed into this
                    // body and later fail to parse, which is an acceptable fail-closed outcome.
                    length = data.Length - position;
                    break;
                default:
                    throw new FailClosedException("Unreachable old-format length type.");
            }

            AppendBytes(data, ref position, length, body);
        }

        private static void ReadNewFormatBody(byte[] data, ref int position, byte rawTag, List<Segment> body)
        {
            bool firstChunk = true;
            while (true)
            {
                int first = ReadByte(data, ref position, "new-format length");
                if (first < 192)
                {
                    AppendBytes(data, ref position, first, body);
                    return;
                }

                if (first < 224)
                {
                    int second = ReadByte(data, ref position, "new-format 2-byte length");
                    int length = ((first - 192) << 8) + second + 192;
                    AppendBytes(data, ref position, length, body);
                    return;
                }

                if (first == 255)
                {
                    int length = (ReadByte(data, ref position, "new-format 5-byte length") << 24)
                                 | (ReadByte(data, ref position, "new-format 5-byte length") << 16)
                                 | (ReadByte(data, ref position, "new-format 5-byte length") << 8)
                                 | ReadByte(data, ref position, "new-format 5-byte length");
                    AppendBytes(data, ref position, length, body);
                    return;
                }

                // 224..254: partial body length, a power of two. RFC 4880 §4.2.2.4 only allows this
                // framing on data packets (Literal, Compressed, encrypted data) and requires the
                // first chunk to be at least 512 octets. Signature and key packets never use it, so
                // accepting it there would only add another way to encode the same packet.
                if (!AllowsPartialBodyLength(rawTag))
                {
                    throw new FailClosedException("Partial body lengths are not permitted for packet tag " + rawTag + ".");
                }

                int partialLength = 1 << (first & 0x1F);
                if (firstChunk && partialLength < 512)
                {
                    throw new FailClosedException("The first partial body chunk must be at least 512 octets.");
                }

                // Append this chunk and loop to read the next chunk's own length header, continuing
                // until a non-partial form is hit.
                AppendBytes(data, ref position, partialLength, body);
                firstChunk = false;
            }
        }

        private static bool AllowsPartialBodyLength(byte rawTag)
        {
            switch ((PacketTag)rawTag)
            {
                case PacketTag.CompressedData:
                case PacketTag.SymmetricallyEncryptedData:
                case PacketTag.LiteralData:
                case PacketTag.SymmetricallyEncryptedIntegrityProtectedData:
                    return true;
                default:
                    return false;
            }
        }

        private static void AppendBytes(byte[] data, ref int position, int length, List<Segment> body)
        {
            // Widen to long before adding: a maliciously large 4/5-byte length (e.g. 0x7FFFFFFF)
            // plus a nonzero position can overflow int, wrapping the sum negative and slipping
            // past a plain "position + length > data.Length" check.
            if (length < 0 || (long)position + length > data.Length)
            {
                throw new FailClosedException("Packet body length extends past the end of the input (truncated packet).");
            }

            body.Add(new Segment(position, length));
            position += length;
        }

        private static byte ReadByte(byte[] data, ref int position, string what)
        {
            if (position >= data.Length)
            {
                throw new FailClosedException("Unexpected end of input while reading " + what + ".");
            }

            return data[position++];
        }
    }
}
