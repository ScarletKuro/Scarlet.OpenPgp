using System;
using System.Buffers.Binary;

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

        private readonly ulong[] _state = new ulong[LaneCount];
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

        private static ulong ReadUInt64LittleEndian(byte[] data, int offset) => BinaryPrimitives.ReadUInt64LittleEndian(data.AsSpan(offset, 8));

        /// <summary>Only ever called with a constant 1 &lt;= count &lt;= 63, which the JIT turns into a single rotate instruction.</summary>
        private static ulong RotateLeft(ulong value, int count) => (value << count) | (value >> (64 - count));

        /// <summary>
        /// Keccak-p[1600, 24] = Keccak-f[1600] (FIPS 202 §3.3, §3.4). Lane A[x, y] is local a(x + 5y).
        /// Fully unrolled over the lanes, so the state lives in locals rather than arrays indexed
        /// with modulo arithmetic: theta's column parities (§3.2.1), then rho's rotations (§3.2.2,
        /// offsets from FIPS 202 Table 2) fused with pi's lane permutation (§3.2.3, A[x, y] moves to
        /// (y, 2x + 3y)), then chi (§3.2.4) row by row and iota (§3.2.5). The known-answer and
        /// BouncyCastle cross-check tests cover every lane and offset.
        /// </summary>
        private void Permute()
        {
            ulong[] s = _state;
            ulong a0 = s[0], a1 = s[1], a2 = s[2], a3 = s[3], a4 = s[4];
            ulong a5 = s[5], a6 = s[6], a7 = s[7], a8 = s[8], a9 = s[9];
            ulong a10 = s[10], a11 = s[11], a12 = s[12], a13 = s[13], a14 = s[14];
            ulong a15 = s[15], a16 = s[16], a17 = s[17], a18 = s[18], a19 = s[19];
            ulong a20 = s[20], a21 = s[21], a22 = s[22], a23 = s[23], a24 = s[24];

            for (int round = 0; round < RoundCount; round++)
            {
                ulong c0 = a0 ^ a5 ^ a10 ^ a15 ^ a20;
                ulong c1 = a1 ^ a6 ^ a11 ^ a16 ^ a21;
                ulong c2 = a2 ^ a7 ^ a12 ^ a17 ^ a22;
                ulong c3 = a3 ^ a8 ^ a13 ^ a18 ^ a23;
                ulong c4 = a4 ^ a9 ^ a14 ^ a19 ^ a24;
                ulong d0 = c4 ^ RotateLeft(c1, 1);
                ulong d1 = c0 ^ RotateLeft(c2, 1);
                ulong d2 = c1 ^ RotateLeft(c3, 1);
                ulong d3 = c2 ^ RotateLeft(c4, 1);
                ulong d4 = c3 ^ RotateLeft(c0, 1);

                ulong b0 = a0 ^ d0;
                ulong b16 = RotateLeft(a5 ^ d0, 36);
                ulong b7 = RotateLeft(a10 ^ d0, 3);
                ulong b23 = RotateLeft(a15 ^ d0, 41);
                ulong b14 = RotateLeft(a20 ^ d0, 18);
                ulong b10 = RotateLeft(a1 ^ d1, 1);
                ulong b1 = RotateLeft(a6 ^ d1, 44);
                ulong b17 = RotateLeft(a11 ^ d1, 10);
                ulong b8 = RotateLeft(a16 ^ d1, 45);
                ulong b24 = RotateLeft(a21 ^ d1, 2);
                ulong b20 = RotateLeft(a2 ^ d2, 62);
                ulong b11 = RotateLeft(a7 ^ d2, 6);
                ulong b2 = RotateLeft(a12 ^ d2, 43);
                ulong b18 = RotateLeft(a17 ^ d2, 15);
                ulong b9 = RotateLeft(a22 ^ d2, 61);
                ulong b5 = RotateLeft(a3 ^ d3, 28);
                ulong b21 = RotateLeft(a8 ^ d3, 55);
                ulong b12 = RotateLeft(a13 ^ d3, 25);
                ulong b3 = RotateLeft(a18 ^ d3, 21);
                ulong b19 = RotateLeft(a23 ^ d3, 56);
                ulong b15 = RotateLeft(a4 ^ d4, 27);
                ulong b6 = RotateLeft(a9 ^ d4, 20);
                ulong b22 = RotateLeft(a14 ^ d4, 39);
                ulong b13 = RotateLeft(a19 ^ d4, 8);
                ulong b4 = RotateLeft(a24 ^ d4, 14);

                a0 = b0 ^ (~b1 & b2);
                a1 = b1 ^ (~b2 & b3);
                a2 = b2 ^ (~b3 & b4);
                a3 = b3 ^ (~b4 & b0);
                a4 = b4 ^ (~b0 & b1);
                a5 = b5 ^ (~b6 & b7);
                a6 = b6 ^ (~b7 & b8);
                a7 = b7 ^ (~b8 & b9);
                a8 = b8 ^ (~b9 & b5);
                a9 = b9 ^ (~b5 & b6);
                a10 = b10 ^ (~b11 & b12);
                a11 = b11 ^ (~b12 & b13);
                a12 = b12 ^ (~b13 & b14);
                a13 = b13 ^ (~b14 & b10);
                a14 = b14 ^ (~b10 & b11);
                a15 = b15 ^ (~b16 & b17);
                a16 = b16 ^ (~b17 & b18);
                a17 = b17 ^ (~b18 & b19);
                a18 = b18 ^ (~b19 & b15);
                a19 = b19 ^ (~b15 & b16);
                a20 = b20 ^ (~b21 & b22);
                a21 = b21 ^ (~b22 & b23);
                a22 = b22 ^ (~b23 & b24);
                a23 = b23 ^ (~b24 & b20);
                a24 = b24 ^ (~b20 & b21);

                a0 ^= RoundConstants[round];
            }

            s[0] = a0; s[1] = a1; s[2] = a2; s[3] = a3; s[4] = a4;
            s[5] = a5; s[6] = a6; s[7] = a7; s[8] = a8; s[9] = a9;
            s[10] = a10; s[11] = a11; s[12] = a12; s[13] = a13; s[14] = a14;
            s[15] = a15; s[16] = a16; s[17] = a17; s[18] = a18; s[19] = a19;
            s[20] = a20; s[21] = a21; s[22] = a22; s[23] = a23; s[24] = a24;
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
    }
}
