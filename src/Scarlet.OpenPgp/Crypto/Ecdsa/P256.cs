using System;
using System.Numerics;

namespace Scarlet.OpenPgp.Crypto.Ecdsa
{
    /// <summary>
    /// The ECDSA verification step R = u1·G + u2·Q on NIST P-256 in fixed-width arithmetic, instead
    /// of <see cref="JacobianPoint"/>'s BigInteger: every field element is eight 32-bit words on the
    /// stack, so a verification allocates nothing here (the BigInteger version allocated about
    /// 900 KB per verification). Only P-256 gets this; the other curves keep the generic code.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Field elements stay fully reduced in [0, p). Products are reduced with the NIST fast
    /// reduction for p = 2^256 - 2^224 + 2^192 + 2^96 - 1 (FIPS 186-4 Appendix D.2.3). Points are
    /// Jacobian with the a = -3 doubling ("dbl-2001-b") and mixed addition of an affine point
    /// ("madd-2007-bl", Explicit-Formulas Database), with the infinity, equal-point and
    /// opposite-point cases handled explicitly.
    /// </para>
    /// <para>
    /// Nothing here is constant-time: a verifier's scalars and points are public. Checked against the
    /// generic BigInteger implementation, Wycheproof's P-256 vectors, and BouncyCastle by
    /// differential fuzzing.
    /// </para>
    /// </remarks>
    internal static class P256
    {
        private static readonly Field P = Field.FromBigInteger(EcCurve.NistP256.P);
        private static readonly Field Gx = Field.FromBigInteger(EcCurve.NistP256.Gx);
        private static readonly Field Gy = Field.FromBigInteger(EcCurve.NistP256.Gy);

        /// <summary>p - 2, the exponent for inversion by Fermat's little theorem.</summary>
        private static readonly byte[] InversionExponent = (EcCurve.NistP256.P - 2).ToByteArray();

        /// <summary>
        /// The affine x of u1·G + u2·Q, or <c>false</c> if the sum is the point at infinity.
        /// <paramref name="qx"/>, <paramref name="qy"/> must be a validated point on the curve and
        /// both scalars non-negative and below 2^256.
        /// </summary>
        public static bool TryLinearCombinationX(BigInteger u1, BigInteger u2, BigInteger qx, BigInteger qy, out BigInteger x)
        {
            x = BigInteger.Zero;
            Field qX = Field.FromBigInteger(qx);
            Field qY = Field.FromBigInteger(qy);

            // G + Q once, normalized to affine so every addition in the loop is a mixed one.
            Point gPlusQ = AddAffine(new Point(Gx, Gy, Field.One), qX, qY);
            bool haveSum = TryToAffine(gPlusQ, out Field sumX, out Field sumY);

            Span<byte> u1Bytes = stackalloc byte[32];
            Span<byte> u2Bytes = stackalloc byte[32];
            ToLittleEndian(u1, u1Bytes);
            ToLittleEndian(u2, u2Bytes);

            // Shamir's trick: one shared doubling chain, adding G, Q or G + Q per bit pair.
            Point result = Point.Infinity;
            for (int bit = 255; bit >= 0; bit--)
            {
                result = Double(result);
                bool bit1 = ((u1Bytes[bit >> 3] >> (bit & 7)) & 1) != 0;
                bool bit2 = ((u2Bytes[bit >> 3] >> (bit & 7)) & 1) != 0;
                if (bit1 && bit2)
                {
                    // G + Q is the point at infinity only when Q = -G; adding it then changes nothing.
                    if (haveSum)
                    {
                        result = AddAffine(result, sumX, sumY);
                    }
                }
                else if (bit1)
                {
                    result = AddAffine(result, Gx, Gy);
                }
                else if (bit2)
                {
                    result = AddAffine(result, qX, qY);
                }
            }

            if (!TryToAffine(result, out Field affineX, out _))
            {
                return false;
            }

            x = affineX.ToBigInteger();
            return true;
        }

        /// <summary>The a = -3 Jacobian doubling, "dbl-2001-b". 2·O = O, and a point with Y = 0 (order 2, impossible on P-256) doubles to O.</summary>
        private static Point Double(in Point p)
        {
            if (p.IsInfinity || p.Y.IsZero)
            {
                return Point.Infinity;
            }

            Field delta = Field.Square(p.Z);
            Field gamma = Field.Square(p.Y);
            Field beta = Field.Multiply(p.X, gamma);
            Field alpha = Field.Multiply(Field.Subtract(p.X, delta), Field.Add(p.X, delta));
            alpha = Field.Add(alpha, Field.Add(alpha, alpha)); // 3 * (X - delta) * (X + delta)

            Field beta4 = Field.Add(Field.Add(beta, beta), Field.Add(beta, beta));
            Field x3 = Field.Subtract(Field.Square(alpha), Field.Add(beta4, beta4));
            Field z3 = Field.Subtract(Field.Subtract(Field.Square(Field.Add(p.Y, p.Z)), gamma), delta);
            Field gamma2 = Field.Square(gamma);
            Field gamma2Times8 = Field.Add(Field.Add(Field.Add(gamma2, gamma2), Field.Add(gamma2, gamma2)), Field.Add(Field.Add(gamma2, gamma2), Field.Add(gamma2, gamma2)));
            Field y3 = Field.Subtract(Field.Multiply(alpha, Field.Subtract(beta4, x3)), gamma2Times8);
            return new Point(x3, y3, z3);
        }

        /// <summary>
        /// p + (x2, y2) for an affine (x2, y2), "madd-2007-bl". The formula breaks down when the two
        /// share an x coordinate (H = 0): then they are equal (double) or opposite (O).
        /// </summary>
        private static Point AddAffine(in Point p, in Field x2, in Field y2)
        {
            if (p.IsInfinity)
            {
                return new Point(x2, y2, Field.One);
            }

            Field z1z1 = Field.Square(p.Z);
            Field u2 = Field.Multiply(x2, z1z1);
            Field s2 = Field.Multiply(y2, Field.Multiply(p.Z, z1z1));
            Field h = Field.Subtract(u2, p.X);
            Field sMinusY = Field.Subtract(s2, p.Y);
            if (h.IsZero)
            {
                return sMinusY.IsZero ? Double(new Point(x2, y2, Field.One)) : Point.Infinity;
            }

            Field hh = Field.Square(h);
            Field i = Field.Add(Field.Add(hh, hh), Field.Add(hh, hh));
            Field j = Field.Multiply(h, i);
            Field r = Field.Add(sMinusY, sMinusY);
            Field v = Field.Multiply(p.X, i);

            Field x3 = Field.Subtract(Field.Subtract(Field.Square(r), j), Field.Add(v, v));
            Field y1j = Field.Multiply(p.Y, j);
            Field y3 = Field.Subtract(Field.Multiply(r, Field.Subtract(v, x3)), Field.Add(y1j, y1j));
            Field z3 = Field.Subtract(Field.Subtract(Field.Square(Field.Add(p.Z, h)), z1z1), hh);
            return new Point(x3, y3, z3);
        }

        /// <summary>(X / Z², Y / Z³), or <c>false</c> for the point at infinity.</summary>
        private static bool TryToAffine(in Point p, out Field x, out Field y)
        {
            if (p.IsInfinity)
            {
                x = default;
                y = default;
                return false;
            }

            Field zInverse = Field.Invert(p.Z);
            Field zInverse2 = Field.Square(zInverse);
            x = Field.Multiply(p.X, zInverse2);
            y = Field.Multiply(p.Y, Field.Multiply(zInverse2, zInverse));
            return true;
        }

        private static void ToLittleEndian(BigInteger value, Span<byte> destination)
        {
            byte[] bytes = value.ToByteArray();
            if (value.Sign < 0 || bytes.Length > 33 || (bytes.Length == 33 && bytes[32] != 0))
            {
                throw new ArgumentOutOfRangeException(nameof(value), "The scalar must be non-negative and below 2^256.");
            }

            destination.Clear();
            bytes.AsSpan(0, Math.Min(bytes.Length, 32)).CopyTo(destination);
        }

        /// <summary>A Jacobian point (X : Y : Z), or the point at infinity.</summary>
        private readonly struct Point(Field x, Field y, Field z, bool isInfinity = false)
        {
            public static Point Infinity => new(Field.One, Field.One, default, isInfinity: true);

            public Field X { get; } = x;

            public Field Y { get; } = y;

            public Field Z { get; } = z;

            public bool IsInfinity { get; } = isInfinity;
        }

        /// <summary>
        /// An element of GF(p) as eight little-endian 32-bit words, always in [0, p). Every index
        /// into the fixed buffer is a loop counter over the constant word count, so nothing reads or
        /// writes outside it.
        /// </summary>
        private unsafe struct Field
        {
            private const int Words = 8;

            private fixed uint _w[Words];

            public static Field One
            {
                get
                {
                    var one = default(Field);
                    one._w[0] = 1;
                    return one;
                }
            }

            public readonly bool IsZero
            {
                get
                {
                    uint any = 0;
                    for (int i = 0; i < Words; i++)
                    {
                        any |= _w[i];
                    }

                    return any == 0;
                }
            }

            public static Field FromBigInteger(BigInteger value)
            {
                byte[] bytes = value.ToByteArray(); // little-endian, non-negative and below p by contract
                var field = default(Field);
                for (int i = 0; i < Words; i++)
                {
                    uint word = 0;
                    for (int b = 3; b >= 0; b--)
                    {
                        int index = (4 * i) + b;
                        word = (word << 8) | (index < bytes.Length ? bytes[index] : 0u);
                    }

                    field._w[i] = word;
                }

                return field;
            }

            public readonly BigInteger ToBigInteger()
            {
                var bytes = new byte[(4 * Words) + 1]; // the extra zero byte keeps it non-negative
                for (int i = 0; i < Words; i++)
                {
                    bytes[4 * i] = (byte)_w[i];
                    bytes[(4 * i) + 1] = (byte)(_w[i] >> 8);
                    bytes[(4 * i) + 2] = (byte)(_w[i] >> 16);
                    bytes[(4 * i) + 3] = (byte)(_w[i] >> 24);
                }

                return new BigInteger(bytes);
            }

            public static Field Add(in Field a, in Field b)
            {
                var sum = default(Field);
                ulong carry = 0;
                for (int i = 0; i < Words; i++)
                {
                    carry += (ulong)a._w[i] + b._w[i];
                    sum._w[i] = (uint)carry;
                    carry >>= 32;
                }

                // a + b < 2p: one subtraction of p brings it back, if it overflowed 2^256 or reached p.
                if (carry != 0 || !LessThanP(sum))
                {
                    SubtractP(ref sum);
                }

                return sum;
            }

            public static Field Subtract(in Field a, in Field b)
            {
                var difference = default(Field);
                long borrow = 0;
                for (int i = 0; i < Words; i++)
                {
                    borrow += (long)a._w[i] - b._w[i];
                    difference._w[i] = (uint)borrow;
                    borrow >>= 32; // arithmetic: -1 when this word borrowed
                }

                if (borrow != 0)
                {
                    AddP(ref difference); // a - b + p, which is in [0, p)
                }

                return difference;
            }

            public static Field Square(in Field a) => Multiply(a, a);

            /// <summary>The schoolbook product into 16 words, then reduced mod p.</summary>
            public static Field Multiply(in Field a, in Field b)
            {
                uint* c = stackalloc uint[2 * Words];
                for (int i = 0; i < 2 * Words; i++)
                {
                    c[i] = 0;
                }

                for (int i = 0; i < Words; i++)
                {
                    ulong carry = 0;
                    ulong ai = a._w[i];
                    for (int j = 0; j < Words; j++)
                    {
                        // At most (2^32-1)^2 + 2(2^32-1) = 2^64 - 1: never overflows.
                        carry += c[i + j] + (ai * b._w[j]);
                        c[i + j] = (uint)carry;
                        carry >>= 32;
                    }

                    c[i + Words] = (uint)carry;
                }

                return Reduce(c);
            }

            /// <summary>this^(p-2) = this^-1 (Fermat; p is prime), by left-to-right square-and-multiply.</summary>
            public static Field Invert(in Field a)
            {
                Field result = One;
                for (int bit = (InversionExponent.Length * 8) - 1; bit >= 0; bit--)
                {
                    result = Square(result);
                    if (((InversionExponent[bit >> 3] >> (bit & 7)) & 1) != 0)
                    {
                        result = Multiply(result, a);
                    }
                }

                return result;
            }

            /// <summary>
            /// FIPS 186-4 D.2.3 fast reduction of a 512-bit c = (c15, ..., c0) modulo p:
            /// s1 + 2s2 + 2s3 + s4 + s5 - d1 - d2 - d3 - d4, each term a 256-bit arrangement of c's
            /// words (written below word 7 first, as in the standard). The signed sum per word is
            /// carried out, the overflow above 2^256 folded back in with
            /// 2^256 = 2^224 - 2^192 - 2^96 + 1 (mod p), and the result brought into [0, p).
            /// </summary>
            private static Field Reduce(uint* c)
            {
                long* t = stackalloc long[Words];

                // s1 = (c7, c6, c5, c4, c3, c2, c1, c0)
                for (int i = 0; i < Words; i++)
                {
                    t[i] = c[i];
                }

                // 2 * s2, s2 = (c15, c14, c13, c12, c11, 0, 0, 0)
                t[3] += 2L * c[11];
                t[4] += 2L * c[12];
                t[5] += 2L * c[13];
                t[6] += 2L * c[14];
                t[7] += 2L * c[15];

                // 2 * s3, s3 = (0, c15, c14, c13, c12, 0, 0, 0)
                t[3] += 2L * c[12];
                t[4] += 2L * c[13];
                t[5] += 2L * c[14];
                t[6] += 2L * c[15];

                // s4 = (c15, c14, 0, 0, 0, c10, c9, c8)
                t[0] += c[8];
                t[1] += c[9];
                t[2] += c[10];
                t[6] += c[14];
                t[7] += c[15];

                // s5 = (c8, c13, c15, c14, c13, c11, c10, c9)
                t[0] += c[9];
                t[1] += c[10];
                t[2] += c[11];
                t[3] += c[13];
                t[4] += c[14];
                t[5] += c[15];
                t[6] += c[13];
                t[7] += c[8];

                // d1 = (c10, c8, 0, 0, 0, c13, c12, c11)
                t[0] -= c[11];
                t[1] -= c[12];
                t[2] -= c[13];
                t[6] -= c[8];
                t[7] -= c[10];

                // d2 = (c11, c9, 0, 0, c15, c14, c13, c12)
                t[0] -= c[12];
                t[1] -= c[13];
                t[2] -= c[14];
                t[3] -= c[15];
                t[6] -= c[9];
                t[7] -= c[11];

                // d3 = (c12, 0, c10, c9, c8, c15, c14, c13)
                t[0] -= c[13];
                t[1] -= c[14];
                t[2] -= c[15];
                t[3] -= c[8];
                t[4] -= c[9];
                t[5] -= c[10];
                t[7] -= c[12];

                // d4 = (c13, 0, c11, c10, c9, 0, c15, c14)
                t[0] -= c[14];
                t[1] -= c[15];
                t[3] -= c[9];
                t[4] -= c[10];
                t[5] -= c[11];
                t[7] -= c[13];

                // Carry out the signed per-word sums, folding whatever lands above 2^256 back in until
                // nothing does. Each fold shrinks the overflow, so this ends after a few rounds.
                long top = CarryWords(t);
                while (top != 0)
                {
                    // top * 2^256 = top * (2^224 - 2^192 - 2^96 + 1) (mod p)
                    t[0] += top;
                    t[3] -= top;
                    t[6] -= top;
                    t[7] += top;
                    top = CarryWords(t);
                }

                var result = default(Field);
                for (int i = 0; i < Words; i++)
                {
                    result._w[i] = (uint)t[i];
                }

                // Now in [0, 2^256), and 2^256 < 2p: at most one subtraction left.
                if (!LessThanP(result))
                {
                    SubtractP(ref result);
                }

                return result;
            }

            /// <summary>Leaves each word in [0, 2^32) and returns the signed carry out of the top word.</summary>
            private static long CarryWords(long* t)
            {
                long carry = 0;
                for (int i = 0; i < Words; i++)
                {
                    long value = t[i] + carry;
                    carry = value >> 32; // floor division, also for negative values
                    t[i] = value - (carry << 32);
                }

                return carry;
            }

            private static bool LessThanP(in Field a)
            {
                for (int i = Words - 1; i >= 0; i--)
                {
                    if (a._w[i] != P._w[i])
                    {
                        return a._w[i] < P._w[i];
                    }
                }

                return false; // equal to p
            }

            private static void SubtractP(ref Field a)
            {
                long borrow = 0;
                for (int i = 0; i < Words; i++)
                {
                    borrow += (long)a._w[i] - P._w[i];
                    a._w[i] = (uint)borrow;
                    borrow >>= 32;
                }
            }

            private static void AddP(ref Field a)
            {
                ulong carry = 0;
                for (int i = 0; i < Words; i++)
                {
                    carry += (ulong)a._w[i] + P._w[i];
                    a._w[i] = (uint)carry;
                    carry >>= 32;
                }
            }
        }
    }
}
