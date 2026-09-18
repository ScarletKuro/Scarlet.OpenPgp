using System.Collections.Generic;
using Scarlet.OpenPgp.Internal;

namespace Scarlet.OpenPgp.Packets
{
    /// <summary>
    /// Parses a signature subpacket array (RFC 4880 §5.2.3.1) - the hashed or unhashed region of a
    /// v4 signature packet. Subpacket lengths use their own encoding, distinct from (but similar to)
    /// packet body lengths: no partial-length concept, and the 2-octet length range is 192-254
    /// rather than 192-223.
    /// </summary>
    internal static class SubpacketReader
    {
        public static List<SignatureSubpacket> ReadAll(byte[] data)
        {
            var subpackets = new List<SignatureSubpacket>();
            int position = 0;
            while (position < data.Length)
            {
                subpackets.Add(ReadOne(data, ref position));
            }

            return subpackets;
        }

        private static SignatureSubpacket ReadOne(byte[] data, ref int position)
        {
            int length = ReadLength(data, ref position);
            if (length < 1)
            {
                throw new FailClosedException("Signature subpacket length must include at least the type octet.");
            }

            // Widen to long before adding: a maliciously large 5-octet length (e.g. 0x7FFFFFFF)
            // plus a nonzero position can overflow int, wrapping the sum negative and slipping
            // past a plain "position + length > data.Length" check (mirrors the same fix in
            // PacketReader.AppendBytes).
            if ((long)position + length > data.Length)
            {
                throw new FailClosedException("Signature subpacket extends past the end of its subpacket array (truncated).");
            }

            byte typeByte = data[position];
            bool critical = (typeByte & 0x80) != 0;
            byte rawType = (byte)(typeByte & 0x7F);

            int dataLength = length - 1;
            var subpacketData = new byte[dataLength];
            System.Array.Copy(data, position + 1, subpacketData, 0, dataLength);

            position += length;

            return new SignatureSubpacket(rawType, critical, subpacketData);
        }

        private static int ReadLength(byte[] data, ref int position)
        {
            if (position >= data.Length)
            {
                throw new FailClosedException("Unexpected end of input while reading a signature subpacket length.");
            }

            int first = data[position++];

            if (first < 192)
            {
                return first;
            }

            if (first < 255)
            {
                if (position >= data.Length)
                {
                    throw new FailClosedException("Unexpected end of input while reading a 2-octet signature subpacket length.");
                }

                int second = data[position++];
                return ((first - 192) << 8) + second + 192;
            }

            if (position + 4 > data.Length)
            {
                throw new FailClosedException("Unexpected end of input while reading a 5-octet signature subpacket length.");
            }

            int length = (data[position] << 24) | (data[position + 1] << 16) | (data[position + 2] << 8) | data[position + 3];
            position += 4;
            return length;
        }
    }
}
