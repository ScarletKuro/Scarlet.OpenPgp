using System.Numerics;

namespace Scarlet.OpenPgp.Crypto.Ed448
{
    /// <summary>
    /// A point on edwards448, the untwisted Edwards curve x^2 + y^2 = 1 + d*x^2*y^2 with d = -39081
    /// (RFC 8032 §5.2), in projective coordinates (X : Y : Z) with x = X/Z, y = Y/Z.
    /// Projective coordinates because affine addition needs two field inversions per step, and
    /// with a 448-bit field and ~450-bit scalars that pushes a single verification well past a
    /// second; projective formulas need no inversion at all until the final comparison, which is
    /// itself done by cross-multiplying.
    /// </summary>
    internal readonly struct Ed448Point : System.IEquatable<Ed448Point>
    {
        public static readonly Ed448FieldElement D = new Ed448FieldElement(-39081);

        public static readonly Ed448Point Identity = new Ed448Point(Ed448FieldElement.Zero, Ed448FieldElement.One, Ed448FieldElement.One);

        /// <summary>
        /// The Ed448 base point B, copied verbatim from RFC 8032 §5.2 Table 2 (X(P), Y(P) of edwards448
        /// in RFC 7748). Hardcoded rather than derived, unlike Ed25519's, because edwards448's base point
        /// has no short closed form; <c>Ed448PointTests</c> checks it is on the curve and has order L.
        /// </summary>
        public static readonly Ed448Point B = FromAffine(
            new Ed448FieldElement(BigInteger.Parse("224580040295924300187604334099896036246789641632564134246125461686950415467406032909029192869357953282578032075146446173674602635247710", System.Globalization.CultureInfo.InvariantCulture)),
            new Ed448FieldElement(BigInteger.Parse("298819210078481492676017930443930673437544040154080242095928241372331506189835876003536878655418784733982303233503462500531545062832660", System.Globalization.CultureInfo.InvariantCulture)));

        public Ed448Point(Ed448FieldElement x, Ed448FieldElement y, Ed448FieldElement z)
        {
            X = x;
            Y = y;
            Z = z;
        }

        public Ed448FieldElement X { get; }

        public Ed448FieldElement Y { get; }

        public Ed448FieldElement Z { get; }

        /// <summary>The curve equation in projective form: (X^2 + Y^2) * Z^2 = Z^4 + d * X^2 * Y^2.</summary>
        public bool IsOnCurve
        {
            get
            {
                if (Z.IsZero)
                {
                    return false;
                }

                Ed448FieldElement xx = X.Square();
                Ed448FieldElement yy = Y.Square();
                Ed448FieldElement zz = Z.Square();
                Ed448FieldElement lhs = (xx + yy) * zz;
                Ed448FieldElement rhs = zz.Square() + (D * xx * yy);
                return lhs == rhs;
            }
        }

        public static Ed448Point FromAffine(Ed448FieldElement x, Ed448FieldElement y) => new Ed448Point(x, y, Ed448FieldElement.One);

        /// <summary>
        /// Complete addition on an untwisted Edwards curve with non-square d (RFC 8032 §5.2.4, from
        /// [Faster-ECC] §4). "Complete" means it is correct for every pair of valid points, including
        /// doubling and the identity, so no special cases are needed.
        /// </summary>
        public Ed448Point Add(Ed448Point other)
        {
            Ed448FieldElement a = Z * other.Z;
            Ed448FieldElement b = a.Square();
            Ed448FieldElement c = X * other.X;
            Ed448FieldElement d = Y * other.Y;
            Ed448FieldElement e = D * c * d;
            Ed448FieldElement f = b - e;
            Ed448FieldElement g = b + e;
            Ed448FieldElement h = (X + Y) * (other.X + other.Y);

            Ed448FieldElement x3 = a * f * (h - c - d);
            Ed448FieldElement y3 = a * g * (d - c);
            Ed448FieldElement z3 = f * g;
            return new Ed448Point(x3, y3, z3);
        }

        /// <summary>Dedicated doubling (RFC 8032 §5.2.4, from [Faster-ECC] §4); <see cref="Add"/> with itself gives the same point, this is just cheaper.</summary>
        public Ed448Point Double()
        {
            Ed448FieldElement b = (X + Y).Square();
            Ed448FieldElement c = X.Square();
            Ed448FieldElement d = Y.Square();
            Ed448FieldElement e = c + d;
            Ed448FieldElement h = Z.Square();
            Ed448FieldElement j = e - (h + h);

            Ed448FieldElement x3 = (b - e) * j;
            Ed448FieldElement y3 = e * (c - d);
            Ed448FieldElement z3 = e * j;
            return new Ed448Point(x3, y3, z3);
        }

        /// <summary>-P = (-x, y), i.e. (-X : Y : Z).</summary>
        public Ed448Point Negate() => new Ed448Point(-X, Y, Z);

        /// <summary>[scalar]P by left-to-right double-and-add. <paramref name="scalar"/> must be non-negative.</summary>
        public Ed448Point ScalarMultiply(BigInteger scalar) => MultiplyAdd(scalar, this, BigInteger.Zero, Identity);

        /// <summary>
        /// [u1]P + [u2]Q in a single left-to-right pass ("Shamir's trick"): one shared doubling
        /// chain, adding P, Q or the precomputed P + Q according to the current bit pair - about
        /// the cost of one scalar multiplication instead of two. Both scalars must be non-negative.
        /// </summary>
        public static Ed448Point MultiplyAdd(BigInteger u1, Ed448Point p, BigInteger u2, Ed448Point q)
        {
            byte[] u1Bytes = u1.ToByteArray(); // little-endian; bit i lives in byte i / 8
            byte[] u2Bytes = u2.ToByteArray();
            Ed448Point pPlusQ = p.Add(q);

            Ed448Point result = Identity;
            for (int bit = (System.Math.Max(u1Bytes.Length, u2Bytes.Length) * 8) - 1; bit >= 0; bit--)
            {
                result = result.Double();
                bool bit1 = TestBit(u1Bytes, bit);
                bool bit2 = TestBit(u2Bytes, bit);
                if (bit1 && bit2)
                {
                    result = result.Add(pPlusQ);
                }
                else if (bit1)
                {
                    result = result.Add(p);
                }
                else if (bit2)
                {
                    result = result.Add(q);
                }
            }

            return result;
        }

        private static bool TestBit(byte[] littleEndian, int bit)
        {
            int index = bit >> 3;
            return index < littleEndian.Length && ((littleEndian[index] >> (bit & 7)) & 1) != 0;
        }

        /// <summary>Projective equality: (X1 : Y1 : Z1) and (X2 : Y2 : Z2) are the same point iff X1*Z2 = X2*Z1 and Y1*Z2 = Y2*Z1 - no inversion needed.</summary>
        public bool Equals(Ed448Point other) =>
            X * other.Z == other.X * Z && Y * other.Z == other.Y * Z;

        public override bool Equals(object? obj) => obj is Ed448Point other && Equals(other);

        /// <summary>Hashes the affine coordinates, so that equal points with different Z hash equally (consistent with <see cref="Equals(Ed448Point)"/>).</summary>
        public override int GetHashCode()
        {
            Ed448FieldElement zInverse = Z.Invert();
            unchecked
            {
                return ((X * zInverse).GetHashCode() * 397) ^ (Y * zInverse).GetHashCode();
            }
        }
    }
}
