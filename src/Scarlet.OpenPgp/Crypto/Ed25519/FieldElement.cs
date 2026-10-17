using System;
using System.Numerics;

namespace Scarlet.OpenPgp.Crypto.Ed25519
{
    /// <summary>
    /// An element of the finite field GF(p) where p = 2^255 - 19, held as ten signed limbs in radix
    /// 2^25.5: limb i has weight 2^ceil(25.5 i), so even limbs are 26 bits wide and odd limbs 25
    /// (the representation of the ref10 reference implementation).
    /// </summary>
    /// <remarks>
    /// <para>
    /// Fixed-width arithmetic instead of <see cref="BigInteger"/>: a verification does thousands of
    /// field multiplications, and BigInteger's per-operation allocation and division made Ed25519
    /// the slowest common algorithm. Limbs are signed and only loosely reduced: every operation
    /// ends with <see cref="Carry"/>, which leaves each limb within about half its width of zero,
    /// so a product column (ten terms of at most 2^25 * 38 * 2^25) stays below 2^61 - inside a
    /// long. <see cref="Pack(byte*)"/> produces the unique canonical encoding, which equality,
    /// parity and <see cref="Value"/> all go through.
    /// </para>
    /// <para>
    /// The <c>fixed</c> buffer keeps an element a plain 80-byte value with no heap allocation. Every
    /// index into it is a loop counter over the constant limb count, so nothing reads or writes
    /// outside it. Nothing here is constant-time: this library only verifies, so every value is public.
    /// </para>
    /// </remarks>
    internal unsafe struct FieldElement : IEquatable<FieldElement>
    {
        public static readonly BigInteger P = BigInteger.Pow(2, 255) - 19;

        /// <summary>Zero: all limbs zero, which is also the default value.</summary>
        public static readonly FieldElement Zero;
        public static readonly FieldElement One = new FieldElement(BigInteger.One);

        private const int LimbCount = 10;
        private const int EncodedLength = 32;

        /// <summary>p - 2, the exponent for inversion by Fermat's little theorem.</summary>
        private static readonly BigInteger InversionExponent = P - 2;

        private fixed long _limbs[LimbCount];

        public FieldElement(BigInteger value)
        {
            BigInteger reduced = value % P;
            if (reduced.Sign < 0)
            {
                reduced += P;
            }

            byte[] littleEndian = reduced.ToByteArray(); // at most 33 bytes: 32 plus a sign byte
            int position = 0;
            for (int i = 0; i < LimbCount; i++)
            {
                int width = Width(i);
                long limb = 0;
                for (int bit = 0; bit < width; bit++)
                {
                    int index = (position + bit) >> 3;
                    if (index < littleEndian.Length && ((littleEndian[index] >> ((position + bit) & 7)) & 1) != 0)
                    {
                        limb |= 1L << bit;
                    }
                }

                _limbs[i] = limb;
                position += width;
            }
        }

        /// <summary>The canonical value in [0, p).</summary>
        public BigInteger Value
        {
            get
            {
                var littleEndian = new byte[EncodedLength + 1]; // the extra zero byte keeps it non-negative
                fixed (byte* output = littleEndian)
                {
                    Pack(output);
                }

                return new BigInteger(littleEndian);
            }
        }

        public bool IsZero
        {
            get
            {
                byte* encoded = stackalloc byte[EncodedLength];
                Pack(encoded);
                for (int i = 0; i < EncodedLength; i++)
                {
                    if (encoded[i] != 0)
                    {
                        return false;
                    }
                }

                return true;
            }
        }

        public bool IsOdd
        {
            get
            {
                byte* encoded = stackalloc byte[EncodedLength];
                Pack(encoded);
                return (encoded[0] & 1) != 0;
            }
        }

        public static FieldElement operator +(in FieldElement a, in FieldElement b)
        {
            var result = default(FieldElement);
            for (int i = 0; i < LimbCount; i++)
            {
                result._limbs[i] = a._limbs[i] + b._limbs[i];
            }

            Carry(ref result);
            return result;
        }

        public static FieldElement operator -(in FieldElement a, in FieldElement b)
        {
            var result = default(FieldElement);
            for (int i = 0; i < LimbCount; i++)
            {
                result._limbs[i] = a._limbs[i] - b._limbs[i];
            }

            Carry(ref result);
            return result;
        }

        public static FieldElement operator -(in FieldElement a) => Zero - a;

        /// <summary>
        /// Schoolbook product, folding the high half into the low half as it is summed (ref10's
        /// fe_mul). f_i * g_j has weight 2^(w_i + w_j), which is 2^w_(i+j) - except when i and j are
        /// both odd, where the half bits add up to one more, so the term counts twice (fiX2). A term
        /// with i + j &gt;= 10 wraps to limb i + j - 10 times 19 (gjX19), since w_(k+10) = w_k + 255 and
        /// 2^255 = 19 (mod p). Unrolled so the limbs stay in registers; the terms were generated from
        /// exactly that rule, and the differential test against BigInteger covers them.
        /// </summary>
        public static FieldElement operator *(in FieldElement a, in FieldElement b)
        {
            long f0 = a._limbs[0], f1 = a._limbs[1], f2 = a._limbs[2], f3 = a._limbs[3], f4 = a._limbs[4];
            long f5 = a._limbs[5], f6 = a._limbs[6], f7 = a._limbs[7], f8 = a._limbs[8], f9 = a._limbs[9];
            long g0 = b._limbs[0], g1 = b._limbs[1], g2 = b._limbs[2], g3 = b._limbs[3], g4 = b._limbs[4];
            long g5 = b._limbs[5], g6 = b._limbs[6], g7 = b._limbs[7], g8 = b._limbs[8], g9 = b._limbs[9];
            long f1x2 = 2 * f1, f3x2 = 2 * f3, f5x2 = 2 * f5, f7x2 = 2 * f7, f9x2 = 2 * f9;
            long g1x19 = 19 * g1, g2x19 = 19 * g2, g3x19 = 19 * g3, g4x19 = 19 * g4, g5x19 = 19 * g5;
            long g6x19 = 19 * g6, g7x19 = 19 * g7, g8x19 = 19 * g8, g9x19 = 19 * g9;

            long h0 = (f0 * g0) + (f1x2 * g9x19) + (f2 * g8x19) + (f3x2 * g7x19) + (f4 * g6x19) + (f5x2 * g5x19) + (f6 * g4x19) + (f7x2 * g3x19) + (f8 * g2x19) + (f9x2 * g1x19);
            long h1 = (f0 * g1) + (f1 * g0) + (f2 * g9x19) + (f3 * g8x19) + (f4 * g7x19) + (f5 * g6x19) + (f6 * g5x19) + (f7 * g4x19) + (f8 * g3x19) + (f9 * g2x19);
            long h2 = (f0 * g2) + (f1x2 * g1) + (f2 * g0) + (f3x2 * g9x19) + (f4 * g8x19) + (f5x2 * g7x19) + (f6 * g6x19) + (f7x2 * g5x19) + (f8 * g4x19) + (f9x2 * g3x19);
            long h3 = (f0 * g3) + (f1 * g2) + (f2 * g1) + (f3 * g0) + (f4 * g9x19) + (f5 * g8x19) + (f6 * g7x19) + (f7 * g6x19) + (f8 * g5x19) + (f9 * g4x19);
            long h4 = (f0 * g4) + (f1x2 * g3) + (f2 * g2) + (f3x2 * g1) + (f4 * g0) + (f5x2 * g9x19) + (f6 * g8x19) + (f7x2 * g7x19) + (f8 * g6x19) + (f9x2 * g5x19);
            long h5 = (f0 * g5) + (f1 * g4) + (f2 * g3) + (f3 * g2) + (f4 * g1) + (f5 * g0) + (f6 * g9x19) + (f7 * g8x19) + (f8 * g7x19) + (f9 * g6x19);
            long h6 = (f0 * g6) + (f1x2 * g5) + (f2 * g4) + (f3x2 * g3) + (f4 * g2) + (f5x2 * g1) + (f6 * g0) + (f7x2 * g9x19) + (f8 * g8x19) + (f9x2 * g7x19);
            long h7 = (f0 * g7) + (f1 * g6) + (f2 * g5) + (f3 * g4) + (f4 * g3) + (f5 * g2) + (f6 * g1) + (f7 * g0) + (f8 * g9x19) + (f9 * g8x19);
            long h8 = (f0 * g8) + (f1x2 * g7) + (f2 * g6) + (f3x2 * g5) + (f4 * g4) + (f5x2 * g3) + (f6 * g2) + (f7x2 * g1) + (f8 * g0) + (f9x2 * g9x19);
            long h9 = (f0 * g9) + (f1 * g8) + (f2 * g7) + (f3 * g6) + (f4 * g5) + (f5 * g4) + (f6 * g3) + (f7 * g2) + (f8 * g1) + (f9 * g0);

            return Reduce(h0, h1, h2, h3, h4, h5, h6, h7, h8, h9);
        }


        public static bool operator ==(in FieldElement a, in FieldElement b)
        {
            byte* left = stackalloc byte[EncodedLength];
            byte* right = stackalloc byte[EncodedLength];
            a.Pack(left);
            b.Pack(right);
            for (int i = 0; i < EncodedLength; i++)
            {
                if (left[i] != right[i])
                {
                    return false;
                }
            }

            return true;
        }

        public static bool operator !=(in FieldElement a, in FieldElement b) => !(a == b);

        /// <summary>this * this, using the product's symmetry: f_i f_j and f_j f_i are one term counted twice, 55 products instead of 100 (ref10's fe_sq).</summary>
        public FieldElement Square()
        {
            long f0 = _limbs[0], f1 = _limbs[1], f2 = _limbs[2], f3 = _limbs[3], f4 = _limbs[4];
            long f5 = _limbs[5], f6 = _limbs[6], f7 = _limbs[7], f8 = _limbs[8], f9 = _limbs[9];

            long h0 = (f0 * f0) + (f1 * f9 * 76) + (f2 * f8 * 38) + (f3 * f7 * 76) + (f4 * f6 * 38) + (f5 * f5 * 38);
            long h1 = (f0 * f1 * 2) + (f2 * f9 * 38) + (f3 * f8 * 38) + (f4 * f7 * 38) + (f5 * f6 * 38);
            long h2 = (f0 * f2 * 2) + (f1 * f1 * 2) + (f3 * f9 * 76) + (f4 * f8 * 38) + (f5 * f7 * 76) + (f6 * f6 * 19);
            long h3 = (f0 * f3 * 2) + (f1 * f2 * 2) + (f4 * f9 * 38) + (f5 * f8 * 38) + (f6 * f7 * 38);
            long h4 = (f0 * f4 * 2) + (f1 * f3 * 4) + (f2 * f2) + (f5 * f9 * 76) + (f6 * f8 * 38) + (f7 * f7 * 38);
            long h5 = (f0 * f5 * 2) + (f1 * f4 * 2) + (f2 * f3 * 2) + (f6 * f9 * 38) + (f7 * f8 * 38);
            long h6 = (f0 * f6 * 2) + (f1 * f5 * 4) + (f2 * f4 * 2) + (f3 * f3 * 2) + (f7 * f9 * 76) + (f8 * f8 * 19);
            long h7 = (f0 * f7 * 2) + (f1 * f6 * 2) + (f2 * f5 * 2) + (f3 * f4 * 2) + (f8 * f9 * 38);
            long h8 = (f0 * f8 * 2) + (f1 * f7 * 4) + (f2 * f6 * 2) + (f3 * f5 * 4) + (f4 * f4) + (f9 * f9 * 38);
            long h9 = (f0 * f9 * 2) + (f1 * f8 * 2) + (f2 * f7 * 2) + (f3 * f6 * 2) + (f4 * f5 * 2);

            return Reduce(h0, h1, h2, h3, h4, h5, h6, h7, h8, h9);
        }

        private static FieldElement Reduce(long h0, long h1, long h2, long h3, long h4, long h5, long h6, long h7, long h8, long h9)
        {
            var result = default(FieldElement);
            result._limbs[0] = h0;
            result._limbs[1] = h1;
            result._limbs[2] = h2;
            result._limbs[3] = h3;
            result._limbs[4] = h4;
            result._limbs[5] = h5;
            result._limbs[6] = h6;
            result._limbs[7] = h7;
            result._limbs[8] = h8;
            result._limbs[9] = h9;
            Carry(ref result);
            Carry(ref result);
            return result;
        }

        /// <summary>this^exponent by left-to-right square-and-multiply. The exponent must be non-negative.</summary>
        public FieldElement Pow(BigInteger exponent)
        {
            byte[] bits = exponent.ToByteArray(); // little-endian; bit i lives in byte i / 8
            FieldElement result = One;
            for (int bit = (bits.Length * 8) - 1; bit >= 0; bit--)
            {
                result = result.Square();
                if (((bits[bit >> 3] >> (bit & 7)) & 1) != 0)
                {
                    result *= this;
                }
            }

            return result;
        }

        /// <summary>Multiplicative inverse mod p, via Fermat's little theorem (p is prime): a^(p-2) = a^-1 mod p.</summary>
        public FieldElement Invert() => Pow(InversionExponent);

        public bool Equals(FieldElement other) => this == other;

        public override bool Equals(object? obj) => obj is FieldElement other && Equals(other);

        public override int GetHashCode() => Value.GetHashCode();

        public override string ToString() => Value.ToString(System.Globalization.CultureInfo.InvariantCulture);

        /// <summary>Limb i's width in bits: 26 for even i, 25 for odd.</summary>
        private static int Width(int limb) => (limb & 1) == 0 ? 26 : 25;

        /// <summary>
        /// One carry pass with rounding: each limb keeps its value modulo its width, centered on
        /// zero, and passes the rest on to the next; the top limb's carry wraps to limb 0 times 19
        /// (2^255 = 19 mod p). Arithmetic right shifts make this exact for negative limbs too.
        /// Afterwards every limb is within half its width of zero, except limb 0, which can be off
        /// by the wrapped carry - a second pass (as after a product) settles that as well.
        /// </summary>
        private static void Carry(ref FieldElement element)
        {
            long carry;
            for (int i = 0; i < LimbCount - 1; i += 2)
            {
                carry = (element._limbs[i] + (1L << 25)) >> 26;
                element._limbs[i + 1] += carry;
                element._limbs[i] -= carry << 26;

                carry = (element._limbs[i + 1] + (1L << 24)) >> 25;
                if (i + 2 < LimbCount)
                {
                    element._limbs[i + 2] += carry;
                }
                else
                {
                    element._limbs[0] += 19 * carry;
                }

                element._limbs[i + 1] -= carry << 25;
            }
        }

        /// <summary>
        /// The canonical 32-byte little-endian encoding (ref10's fe_tobytes). For a carried value h,
        /// q = floor(h / p) is 0 or 1, and comes from the carries out of h + 19; then h - q p is
        /// h + 19 q with the bit above 2^255 dropped, carried exactly (no rounding) into [0, 2^width).
        /// </summary>
        private void Pack(byte* output)
        {
            FieldElement h = this;
            Carry(ref h);
            Carry(ref h);

            long q = ((19 * h._limbs[9]) + (1L << 24)) >> 25;
            for (int i = 0; i < LimbCount; i++)
            {
                q = (h._limbs[i] + q) >> Width(i);
            }

            h._limbs[0] += 19 * q;
            for (int i = 0; i < LimbCount - 1; i++)
            {
                long carry = h._limbs[i] >> Width(i);
                h._limbs[i + 1] += carry;
                h._limbs[i] -= carry << Width(i);
            }

            h._limbs[LimbCount - 1] &= (1L << 25) - 1; // drops 2^255, completing the subtraction of q p

            // 26 + 25 + ... = 255 bits, emitted little-endian through a small bit accumulator.
            ulong accumulator = 0;
            int bits = 0;
            int written = 0;
            for (int i = 0; i < LimbCount; i++)
            {
                accumulator |= (ulong)h._limbs[i] << bits;
                bits += Width(i);
                while (bits >= 8)
                {
                    output[written++] = (byte)accumulator;
                    accumulator >>= 8;
                    bits -= 8;
                }
            }

            output[written] = (byte)accumulator; // the last 7 bits
        }
    }
}
