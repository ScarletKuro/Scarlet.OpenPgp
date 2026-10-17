using System;

namespace Scarlet.OpenPgp.Hashing
{
    /// <summary>
    /// The Keccak-f[1600] sponge (FIPS 202), instantiated as SHA3-256, SHA3-512 and SHAKE256.
    /// Implemented in-library because netstandard2.0 has no SHA-3 at all and even net10.0 only
    /// exposes it where the OS crypto provider supports it - and Ed448 (RFC 8032 §5.2) cannot be
    /// verified without SHAKE256. Correctness over speed, per SPEC.md: a straightforward lane-wise
    /// permutation with no unrolling; there is no secret input anywhere in this verify-only library.
    /// </summary>
    internal sealed class KeccakHash
    {
        /// <summary>Keccak-f[1600] state is 25 lanes of 64 bits (b = 1600, w = 64, FIPS 202 §3.1).</summary>
        private const int LaneCount = 25;

        /// <summary>Keccak-f[1600] has 12 + 2*l rounds with l = log2(w) = 6, i.e. 24 (FIPS 202 §3.4).</summary>
        private const int RoundCount = 24;

        /// <summary>
        /// Domain-separation suffix for SHA-3: the two message bits "01" (FIPS 202 §6.1) followed by the
        /// first bit of pad10*1, packed LSB-first into one byte: 0b110 = 0x06.
        /// </summary>
        private const byte Sha3DomainSuffix = 0x06;

        /// <summary>Domain-separation suffix for SHAKE: the four bits "1111" (FIPS 202 §6.2) plus the first pad10*1 bit: 0b11111 = 0x1F.</summary>
        private const byte ShakeDomainSuffix = 0x1F;

        /// <summary>The final bit of pad10*1, which always lands in the last byte of the rate.</summary>
        private const byte FinalPadBit = 0x80;

        /// <summary>Round constants for the iota step, derived from the rc(t) LFSR of FIPS 202 Algorithm 5 rather than hardcoded so they are auditable against the standard.</summary>
        private static readonly ulong[] RoundConstants = CreateRoundConstants();

        /// <summary>Rotation offsets for the rho step, derived per FIPS 202 Algorithm 2, indexed by lane x + 5y.</summary>
        private static readonly int[] RhoOffsets = CreateRhoOffsets();

        private readonly ulong[] _state = new ulong[LaneCount];
        private readonly ulong[] _scratch = new ulong[LaneCount];
        private readonly ulong[] _columnParity = new ulong[5];
        private readonly int _rateBytes;
        private readonly byte _domainSuffix;
        private readonly int _outputLength;
        private int _position;
        private bool _finished;

        private KeccakHash(int rateBytes, byte domainSuffix, int outputLength)
        {
            _rateBytes = rateBytes;
            _domainSuffix = domainSuffix;
            _outputLength = outputLength;
        }

        /// <summary>SHA3-256: capacity 512 bits, so rate = (1600 - 512) / 8 = 136 bytes (FIPS 202 §6.1).</summary>
        public static KeccakHash CreateSha3_256() => new KeccakHash(136, Sha3DomainSuffix, 32);

        /// <summary>SHA3-512: capacity 1024 bits, so rate = (1600 - 1024) / 8 = 72 bytes (FIPS 202 §6.1).</summary>
        public static KeccakHash CreateSha3_512() => new KeccakHash(72, Sha3DomainSuffix, 64);

        /// <summary>SHAKE256 with a caller-chosen output length in bytes: capacity 512 bits, rate 136 bytes (FIPS 202 §6.2).</summary>
        public static KeccakHash CreateShake256(int outputLength)
        {
            if (outputLength < 0)
            {
                throw new ArgumentOutOfRangeException(nameof(outputLength), "SHAKE256 output length must not be negative.");
            }

            return new KeccakHash(136, ShakeDomainSuffix, outputLength);
        }

        public static byte[] Sha3_256(byte[] data) => OneShot(CreateSha3_256(), data);

        public static byte[] Sha3_512(byte[] data) => OneShot(CreateSha3_512(), data);

        public static byte[] Shake256(byte[] data, int outputLength) => OneShot(CreateShake256(outputLength), data);

        /// <summary>Absorbs <paramref name="count"/> bytes of <paramref name="data"/> starting at <paramref name="offset"/>. May be called any number of times before <see cref="Finish"/>.</summary>
        public void Update(byte[] data, int offset, int count)
        {
            if (data == null)
            {
                throw new ArgumentNullException(nameof(data));
            }

            if (offset < 0 || count < 0 || offset > data.Length - count)
            {
                throw new ArgumentOutOfRangeException(nameof(count), "Offset and count must describe a range within the data array.");
            }

            ThrowIfFinished();

            int end = offset + count;
            int i = offset;
            while (i < end)
            {
                // Fast path: a whole rate-sized block at a block boundary is XORed in lane by lane.
                if (_position == 0 && end - i >= _rateBytes)
                {
                    for (int lane = 0; lane < _rateBytes / 8; lane++)
                    {
                        _state[lane] ^= ReadUInt64LittleEndian(data, i + (lane * 8));
                    }

                    i += _rateBytes;
                    Permute();
                    continue;
                }

                XorByteIntoState(_position, data[i]);
                i++;
                _position++;
                if (_position == _rateBytes)
                {
                    Permute();
                    _position = 0;
                }
            }
        }

        /// <summary>Pads, finishes absorbing, and squeezes the output. Single use: the instance cannot be updated or finished again afterwards.</summary>
        public byte[] Finish()
        {
            ThrowIfFinished();
            _finished = true;

            // pad10*1 combined with the domain suffix (FIPS 202 §5.1, Appendix B.2). If the suffix
            // and the final bit fall into the same byte (position == rate - 1) the XORs simply
            // combine, which is exactly what the bit-level definition requires.
            XorByteIntoState(_position, _domainSuffix);
            XorByteIntoState(_rateBytes - 1, FinalPadBit);
            Permute();

            // Squeeze: emit up to one rate's worth per permutation; outputs longer than the rate
            // (only reachable for SHAKE) need further permutations between blocks.
            var output = new byte[_outputLength];
            int written = 0;
            while (true)
            {
                int take = Math.Min(_rateBytes, _outputLength - written);
                for (int j = 0; j < take; j++)
                {
                    output[written + j] = (byte)(_state[j / 8] >> (8 * (j % 8)));
                }

                written += take;
                if (written == _outputLength)
                {
                    return output;
                }

                Permute();
            }
        }

        private static byte[] OneShot(KeccakHash hash, byte[] data)
        {
            if (data == null)
            {
                throw new ArgumentNullException(nameof(data));
            }

            hash.Update(data, 0, data.Length);
            return hash.Finish();
        }

        private void ThrowIfFinished()
        {
            if (_finished)
            {
                throw new InvalidOperationException("This Keccak instance has already been finished and cannot be reused.");
            }
        }

        /// <summary>Bytes map onto lanes little-endian: byte i of the rate is bits 8*(i mod 8).. of lane i / 8 (FIPS 202 §3.1.2, Appendix B.1).</summary>
        private void XorByteIntoState(int index, byte value)
        {
            _state[index / 8] ^= (ulong)value << (8 * (index % 8));
        }

        private static ulong ReadUInt64LittleEndian(byte[] data, int offset)
        {
            ulong value = 0;
            for (int b = 7; b >= 0; b--)
            {
                value = (value << 8) | data[offset + b];
            }

            return value;
        }

        private static ulong RotateLeft(ulong value, int count) => count == 0 ? value : (value << count) | (value >> (64 - count));

        /// <summary>Keccak-p[1600, 24] = Keccak-f[1600] (FIPS 202 §3.3, §3.4). Lane A[x, y] lives at index x + 5y.</summary>
        private void Permute()
        {
            ulong[] a = _state;
            ulong[] b = _scratch;
            ulong[] c = _columnParity;

            for (int round = 0; round < RoundCount; round++)
            {
                // theta (§3.2.1): XOR each lane with the parities of two neighbouring columns.
                for (int x = 0; x < 5; x++)
                {
                    c[x] = a[x] ^ a[x + 5] ^ a[x + 10] ^ a[x + 15] ^ a[x + 20];
                }

                for (int x = 0; x < 5; x++)
                {
                    ulong d = c[(x + 4) % 5] ^ RotateLeft(c[(x + 1) % 5], 1);
                    for (int y = 0; y < 25; y += 5)
                    {
                        a[x + y] ^= d;
                    }
                }

                // rho (§3.2.2) and pi (§3.2.3) combined: pi maps A[x, y] to position
                // (y, 2x + 3y), i.e. A'[x, y] = A[(x + 3y) mod 5, x].
                for (int x = 0; x < 5; x++)
                {
                    for (int y = 0; y < 5; y++)
                    {
                        b[y + (5 * (((2 * x) + (3 * y)) % 5))] = RotateLeft(a[x + (5 * y)], RhoOffsets[x + (5 * y)]);
                    }
                }

                // chi (§3.2.4): the only non-linear step, row by row.
                for (int y = 0; y < 25; y += 5)
                {
                    for (int x = 0; x < 5; x++)
                    {
                        a[x + y] = b[x + y] ^ (~b[((x + 1) % 5) + y] & b[((x + 2) % 5) + y]);
                    }
                }

                // iota (§3.2.5).
                a[0] ^= RoundConstants[round];
            }
        }

        /// <summary>FIPS 202 Algorithm 5: rc(t), one output bit of a degree-8 LFSR with feedback polynomial x^8 + x^6 + x^5 + x^4 + 1.</summary>
        private static bool RoundConstantBit(int t)
        {
            int steps = t % 255;
            int r = 0x01; // R = 10000000, with R[0] as the least significant bit
            for (int i = 0; i < steps; i++)
            {
                r <<= 1; // R = 0 || R
                if ((r & 0x100) != 0)
                {
                    r ^= 0x171; // R[0], R[4], R[5], R[6] ^= R[8], then truncate to 8 bits
                }
            }

            return (r & 1) != 0;
        }

        /// <summary>FIPS 202 Algorithm 6: RC[2^j - 1] = rc(j + 7 * round) for j = 0..6, all other bits zero.</summary>
        private static ulong[] CreateRoundConstants()
        {
            var constants = new ulong[RoundCount];
            for (int round = 0; round < RoundCount; round++)
            {
                ulong rc = 0;
                for (int j = 0; j <= 6; j++)
                {
                    if (RoundConstantBit(j + (7 * round)))
                    {
                        rc |= 1UL << ((1 << j) - 1);
                    }
                }

                constants[round] = rc;
            }

            return constants;
        }

        /// <summary>FIPS 202 Algorithm 2: walking (x, y) from (1, 0) via (y, (2x + 3y) mod 5), lane t gets offset (t + 1)(t + 2) / 2 mod 64; A[0, 0] is never rotated.</summary>
        private static int[] CreateRhoOffsets()
        {
            var offsets = new int[LaneCount];
            int x = 1;
            int y = 0;
            for (int t = 0; t < 24; t++)
            {
                offsets[x + (5 * y)] = ((t + 1) * (t + 2) / 2) % 64;
                int nextY = ((2 * x) + (3 * y)) % 5;
                x = y;
                y = nextY;
            }

            return offsets;
        }
    }
}
