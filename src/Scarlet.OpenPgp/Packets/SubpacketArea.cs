using System.Collections;
using System.Collections.Generic;
using Scarlet.OpenPgp.Internal;

namespace Scarlet.OpenPgp.Packets
{
    /// <summary>
    /// A signature subpacket area (RFC 9580 §5.2.3.7) - the hashed or unhashed region of a v4/v6
    /// signature - read in place. Subpacket lengths use their own encoding, distinct from (but
    /// similar to) packet body lengths: no partial lengths, and the 2-octet range is 192-254 rather
    /// than 192-223.
    /// </summary>
    /// <remarks>
    /// The framing is checked once, when the area is read; after that, enumerating walks the same
    /// octets again and yields views into them. Materializing every subpacket as its own object and
    /// array cost about 40 times the input: a 2-octet subpacket became some 60 bytes of heap.
    /// </remarks>
    internal sealed class SubpacketArea : IEnumerable<SignatureSubpacket>
    {
        public static readonly SubpacketArea Empty = new([], 0, 0);

        private readonly byte[] _buffer;
        private readonly int _start;
        private readonly int _length;

        private SubpacketArea(byte[] buffer, int start, int length)
        {
            _buffer = buffer;
            _start = start;
            _length = length;
        }

        public static SubpacketArea Read(byte[] buffer) => Read(buffer, 0, buffer.Length);

        /// <summary>The area of <paramref name="length"/> octets at <paramref name="start"/> in <paramref name="buffer"/>, which must lie within it.</summary>
        /// <exception cref="FailClosedException">The subpackets' framing is broken.</exception>
        public static SubpacketArea Read(byte[] buffer, int start, int length)
        {
            int position = start;
            int end = start + length;
            while (position < end)
            {
                ReadOne(buffer, ref position, end);
            }

            return new SubpacketArea(buffer, start, length);
        }

        public Enumerator GetEnumerator() => new(_buffer, _start, _start + _length);

        IEnumerator<SignatureSubpacket> IEnumerable<SignatureSubpacket>.GetEnumerator() => GetEnumerator();

        IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();

        private static SignatureSubpacket ReadOne(byte[] buffer, ref int position, int end)
        {
            int length = ReadLength(buffer, ref position, end);
            if (length < 1)
            {
                throw new FailClosedException("Signature subpacket length must include at least the type octet.");
            }

            // Widen to long before adding: a maliciously large 5-octet length (e.g. 0x7FFFFFFF)
            // plus a nonzero position can overflow int, wrapping the sum negative and slipping
            // past a plain "position + length > end" check.
            if ((long)position + length > end)
            {
                throw new FailClosedException("Signature subpacket extends past the end of its subpacket array (truncated).");
            }

            byte typeByte = buffer[position];
            var subpacket = new SignatureSubpacket(buffer, position + 1, length - 1, (byte)(typeByte & 0x7F), (typeByte & 0x80) != 0);
            position += length;
            return subpacket;
        }

        private static int ReadLength(byte[] buffer, ref int position, int end)
        {
            if (position >= end)
            {
                throw new FailClosedException("Unexpected end of input while reading a signature subpacket length.");
            }

            int first = buffer[position++];

            if (first < 192)
            {
                return first;
            }

            if (first < 255)
            {
                if (position >= end)
                {
                    throw new FailClosedException("Unexpected end of input while reading a 2-octet signature subpacket length.");
                }

                int second = buffer[position++];
                return ((first - 192) << 8) + second + 192;
            }

            if (position + 4 > end)
            {
                throw new FailClosedException("Unexpected end of input while reading a 5-octet signature subpacket length.");
            }

            int length = (buffer[position] << 24) | (buffer[position + 1] << 16) | (buffer[position + 2] << 8) | buffer[position + 3];
            position += 4;
            return length;
        }

        /// <summary>Walks an area whose framing <see cref="Read(byte[], int, int)"/> already checked, so it can't throw.</summary>
        public struct Enumerator : IEnumerator<SignatureSubpacket>
        {
            private readonly byte[] _buffer;
            private readonly int _start;
            private readonly int _end;
            private int _position;

            internal Enumerator(byte[] buffer, int start, int end)
            {
                _buffer = buffer;
                _start = start;
                _end = end;
                _position = start;
                Current = default;
            }

            public SignatureSubpacket Current { get; private set; }

            readonly object IEnumerator.Current => Current;

            public bool MoveNext()
            {
                if (_position >= _end)
                {
                    return false;
                }

                Current = ReadOne(_buffer, ref _position, _end);
                return true;
            }

            public void Reset() => _position = _start;

            public readonly void Dispose()
            {
            }
        }
    }
}
