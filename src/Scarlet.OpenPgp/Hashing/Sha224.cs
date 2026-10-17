using System;
using System.Buffers.Binary;
using System.Numerics;

namespace Scarlet.OpenPgp.Hashing
{
    /// <summary>
    /// SHA2-224 (FIPS 180-4 §6.3): the SHA-256 compression function with different initial values,
    /// truncated to 224 bits. RFC 9580 lists it as a valid signature hash, and neither netstandard2.0
    /// nor .NET provides it.
    /// </summary>
    internal sealed class Sha224
    {
        private const int BlockSize = 64;

        /// <summary>
        /// The 64 round constants: the first 32 bits of the fractional parts of the cube roots of the
        /// first 64 primes (FIPS 180-4 §4.2.2), derived exactly with integer arithmetic rather than
        /// copied, so they can't carry a transcription error.
        /// </summary>
        internal static readonly uint[] K = DeriveRoundConstants();

        /// <summary>
        /// SHA-224's initial hash value (FIPS 180-4 §5.3.2): the *second* 32 bits of the fractional
        /// parts of the square roots of the 9th through 16th primes. Checked by the known-answer tests.
        /// </summary>
        private static readonly uint[] InitialState =
        [
            0xC1059ED8, 0x367CD507, 0x3070DD17, 0xF70E5939, 0xFFC00B31, 0x68581511, 0x64F98FA7, 0xBEFA4FA4,
        ];

        private readonly uint[] _state = (uint[])InitialState.Clone();
        private readonly byte[] _buffer = new byte[BlockSize];
        private readonly uint[] _schedule = new uint[64];
        private readonly bool _useHardware;
        private int _bufferLength;
        private long _totalLength;
        private bool _finished;

        /// <param name="allowHardware">
        /// Use the CPU's SHA-256 instructions where .NET exposes them (ARM64); <c>false</c> forces the
        /// portable implementation, so tests can compare the two on the same machine.
        /// </param>
        public Sha224(bool allowHardware = true)
        {
            _useHardware = allowHardware && Sha256Hardware.IsSupported;
        }

        public void Update(byte[] data, int offset, int count)
        {
            if (_finished)
            {
                throw new InvalidOperationException("The hash has already been finished.");
            }

            _totalLength += count;

            // Top up a partially filled block first; whole blocks after that are compressed straight
            // from the input, and only the tail is buffered.
            if (_bufferLength > 0)
            {
                int take = Math.Min(count, BlockSize - _bufferLength);
                Array.Copy(data, offset, _buffer, _bufferLength, take);
                _bufferLength += take;
                offset += take;
                count -= take;
                if (_bufferLength < BlockSize)
                {
                    return;
                }

                Compress(_buffer, 0, 1);
                _bufferLength = 0;
            }

            int blocks = count / BlockSize;
            if (blocks > 0)
            {
                Compress(data, offset, blocks);
                offset += blocks * BlockSize;
                count -= blocks * BlockSize;
            }

            Array.Copy(data, offset, _buffer, 0, count);
            _bufferLength = count;
        }

        public byte[] Finish()
        {
            if (_finished)
            {
                throw new InvalidOperationException("The hash has already been finished.");
            }

            // Padding (FIPS 180-4 §5.1.1): a 1 bit, zeros, then the message length in bits as a
            // 64-bit big-endian number, filling out a whole number of blocks.
            long bitLength = _totalLength * 8;
            var padding = new byte[(_bufferLength < 56 ? 56 : 120) - _bufferLength + 8];
            padding[0] = 0x80;
            for (int i = 0; i < 8; i++)
            {
                padding[padding.Length - 1 - i] = (byte)(bitLength >> (8 * i));
            }

            Update(padding, 0, padding.Length);
            _finished = true;

            var digest = new byte[28];
            for (int i = 0; i < 7; i++)
            {
                digest[(4 * i) + 0] = (byte)(_state[i] >> 24);
                digest[(4 * i) + 1] = (byte)(_state[i] >> 16);
                digest[(4 * i) + 2] = (byte)(_state[i] >> 8);
                digest[(4 * i) + 3] = (byte)_state[i];
            }

            return digest;
        }

        private void Compress(byte[] data, int offset, int blocks)
        {
            if (_useHardware)
            {
                Sha256Hardware.Compress(_state, data, offset, blocks);
                return;
            }

            for (int i = 0; i < blocks; i++)
            {
                CompressBlock(data.AsSpan(offset + (i * BlockSize), BlockSize));
            }
        }

        private void CompressBlock(ReadOnlySpan<byte> block)
        {
            uint[] w = _schedule;
            for (int t = 0; t < 16; t++)
            {
                w[t] = BinaryPrimitives.ReadUInt32BigEndian(block.Slice(4 * t));
            }

            for (int t = 16; t < 64; t++)
            {
                uint s0 = RotateRight(w[t - 15], 7) ^ RotateRight(w[t - 15], 18) ^ (w[t - 15] >> 3);
                uint s1 = RotateRight(w[t - 2], 17) ^ RotateRight(w[t - 2], 19) ^ (w[t - 2] >> 10);
                w[t] = unchecked(w[t - 16] + s0 + w[t - 7] + s1);
            }

            uint a = _state[0], b = _state[1], c = _state[2], d = _state[3];
            uint e = _state[4], f = _state[5], g = _state[6], h = _state[7];
            for (int t = 0; t < 64; t++)
            {
                uint sum1 = RotateRight(e, 6) ^ RotateRight(e, 11) ^ RotateRight(e, 25);
                uint choose = (e & f) ^ (~e & g);
                uint temp1 = unchecked(h + sum1 + choose + K[t] + w[t]);
                uint sum0 = RotateRight(a, 2) ^ RotateRight(a, 13) ^ RotateRight(a, 22);
                uint majority = (a & b) ^ (a & c) ^ (b & c);
                uint temp2 = unchecked(sum0 + majority);
                h = g;
                g = f;
                f = e;
                e = unchecked(d + temp1);
                d = c;
                c = b;
                b = a;
                a = unchecked(temp1 + temp2);
            }

            unchecked
            {
                _state[0] += a;
                _state[1] += b;
                _state[2] += c;
                _state[3] += d;
                _state[4] += e;
                _state[5] += f;
                _state[6] += g;
                _state[7] += h;
            }
        }

        private static uint RotateRight(uint value, int bits) => (value >> bits) | (value << (32 - bits));

        private static uint[] DeriveRoundConstants()
        {
            var constants = new uint[64];
            int found = 0;
            for (int candidate = 2; found < 64; candidate++)
            {
                if (!IsPrime(candidate))
                {
                    continue;
                }

                // floor(cbrt(p) * 2^32) = floor(cbrt(p * 2^96)); its low 32 bits are the fraction's.
                BigInteger scaledRoot = IntegerCubeRoot(new BigInteger(candidate) << 96);
                constants[found++] = (uint)(scaledRoot & uint.MaxValue);
            }

            return constants;
        }

        private static bool IsPrime(int n)
        {
            for (int d = 2; d * d <= n; d++)
            {
                if (n % d == 0)
                {
                    return false;
                }
            }

            return true;
        }

        /// <summary>floor(cbrt(n)) for n &gt; 0, by Newton's method from an upper bound.</summary>
        private static BigInteger IntegerCubeRoot(BigInteger n)
        {
            BigInteger x = BigInteger.One << (((int)Math.Ceiling(BigInteger.Log(n, 2)) / 3) + 1);
            while (true)
            {
                BigInteger next = ((2 * x) + (n / (x * x))) / 3;
                if (next >= x)
                {
                    return x;
                }

                x = next;
            }
        }
    }
}
