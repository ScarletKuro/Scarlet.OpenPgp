using System.Collections.Generic;
using System.IO;
using Scarlet.OpenPgp.Internal;

namespace Scarlet.OpenPgp.Packets
{
    /// <summary>A single parsed OpenPGP packet: its tag and fully-assembled body.</summary>
    internal sealed class Packet
    {
        public Packet(PacketHeader header, byte[] body)
        {
            Header = header;
            Body = body;
        }

        public PacketHeader Header { get; }

        public byte[] Body { get; }
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
            var body = new MemoryStream();

            if (newFormat)
            {
                rawTag = (byte)(tagByte & 0x3F);
                ReadNewFormatBody(data, ref position, body);
            }
            else
            {
                rawTag = (byte)((tagByte & 0x3C) >> 2);
                int lengthType = tagByte & 0x03;
                ReadOldFormatBody(data, ref position, lengthType, body);
            }

            var header = new PacketHeader((PacketTag)rawTag, rawTag);
            return new Packet(header, body.ToArray());
        }

        private static void ReadOldFormatBody(byte[] data, ref int position, int lengthType, MemoryStream body)
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

        private static void ReadNewFormatBody(byte[] data, ref int position, MemoryStream body)
        {
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

                // 224..254: partial body length, a power of two. Append this chunk and loop to read
                // the next chunk's own length header, continuing until a non-partial form is hit.
                int partialLength = 1 << (first & 0x1F);
                AppendBytes(data, ref position, partialLength, body);
            }
        }

        private static void AppendBytes(byte[] data, ref int position, int length, MemoryStream body)
        {
            // Widen to long before adding: a maliciously large 4/5-byte length (e.g. 0x7FFFFFFF)
            // plus a nonzero position can overflow int, wrapping the sum negative and slipping
            // past a plain "position + length > data.Length" check.
            if (length < 0 || (long)position + length > data.Length)
            {
                throw new FailClosedException("Packet body length extends past the end of the input (truncated packet).");
            }

            body.Write(data, position, length);
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
