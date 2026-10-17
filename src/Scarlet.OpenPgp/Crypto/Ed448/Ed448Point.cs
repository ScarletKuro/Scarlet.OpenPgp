using System.Numerics;

namespace Scarlet.OpenPgp.Crypto.Ed448
{
    /// <summary>
    /// A point on edwards448, the untwisted Edwards curve x^2 + y^2 = 1 + d*x^2*y^2 with d = -39081
    /// (RFC 8032 §5.2), in projective coordinates (X : Y : Z) with x = X/Z, y = Y/Z.
    /// Unlike the Ed25519 code, which stays affine, projective coordinates are used here because
    /// affine addition needs two field inversions per step, and with a 448-bit field and ~450-bit
    /// scalars that pushes a single verification well past a second; projective formulas need
    /// no inversion at all until the final comparison, which is itself done by cross-multiplying.
    /// </summary>
    internal readonly struct Ed448Point
    {
        public static readonly Ed448FieldElement D = new Ed448FieldElement(-39081);

        public static readonly Ed448Point Identity = new Ed448Point(Ed448FieldElement.Zero, Ed448FieldElement.One, Ed448FieldElement.One);

        /// <summary>
        /// The Ed448 base point B, copied verbatim from RFC 8032 §5.2 Table 2 (X(P), Y(P) of edwards448
        /// in RFC 7748). Hardcoded rather than derived, unlike Ed25519's, because edwards448's base point
        /// has no short closed form; <c>Ed448PointTests</c> checks it is on the curve and has order L.
        /// </summary>
        public static readonly Ed448Point B = FromAffine(
            new Ed448FieldElement(BigInteger.Parse("224580040295924300187604334099896036246789641632564134246125461686950415467406032909029192869357953282578032075146446173674602635247710")),
            new Ed448FieldElement(BigInteger.Parse("298819210078481492676017930443930673437544040154080242095928241372331506189835876003536878655418784733982303233503462500531545062832660")));

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

        public Ed448Point ScalarMultiply(BigInteger scalar)
        {
            Ed448Point result = Identity;
            Ed448Point addend = this;

            BigInteger remaining = scalar;
            while (remaining > 0)
            {
                if (!remaining.IsEven)
                {
                    result = result.Add(addend);
                }

                addend = addend.Double();
                remaining >>= 1;
            }

            return result;
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
