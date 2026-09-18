using System.Numerics;

namespace Scarlet.OpenPgp.Crypto.Ed25519
{
    /// <summary>
    /// A point on Ed25519's twisted Edwards curve (-x^2 + y^2 = 1 + d*x^2*y^2), in affine
    /// coordinates. Affine (rather than extended projective) coordinates and BigInteger-backed
    /// field arithmetic are a deliberate simplicity-over-speed choice - acceptable per SPEC.md,
    /// since this is a verify-only library with no secret scalars to protect from timing leaks.
    /// </summary>
    internal readonly struct EdwardsPoint
    {
        /// <summary>The curve constant d = -121665/121666 (mod p), derived from first principles rather than hardcoded so it is auditable against RFC 8032 §5.1.1.</summary>
        public static readonly FieldElement D = new FieldElement(-121665) * new FieldElement(121666).Invert();

        public static readonly EdwardsPoint Identity = new EdwardsPoint(FieldElement.Zero, FieldElement.One);

        /// <summary>The Ed25519 base point B = (x, 4/5) with x chosen even (RFC 8032 §5.1.2), derived rather than hardcoded for the same auditability reason as <see cref="D"/>.</summary>
        public static readonly EdwardsPoint B = CreateBasePoint();

        public EdwardsPoint(FieldElement x, FieldElement y)
        {
            X = x;
            Y = y;
        }

        public FieldElement X { get; }

        public FieldElement Y { get; }

        public bool IsOnCurve
        {
            get
            {
                FieldElement xx = X * X;
                FieldElement yy = Y * Y;
                FieldElement lhs = yy - xx;
                FieldElement rhs = FieldElement.One + (D * xx * yy);
                return lhs == rhs;
            }
        }

        /// <summary>The unified twisted-Edwards addition law (RFC 8032 §5.1.4); the same formula handles doubling when <paramref name="other"/> is <c>this</c>.</summary>
        public EdwardsPoint Add(EdwardsPoint other)
        {
            FieldElement x1y2 = X * other.Y;
            FieldElement y1x2 = Y * other.X;
            FieldElement y1y2 = Y * other.Y;
            FieldElement x1x2 = X * other.X;
            FieldElement dx1x2y1y2 = D * X * other.X * Y * other.Y;

            FieldElement x3 = (x1y2 + y1x2) * (FieldElement.One + dx1x2y1y2).Invert();
            FieldElement y3 = (y1y2 + x1x2) * (FieldElement.One - dx1x2y1y2).Invert();
            return new EdwardsPoint(x3, y3);
        }

        public EdwardsPoint ScalarMultiply(BigInteger scalar)
        {
            EdwardsPoint result = Identity;
            EdwardsPoint addend = this;

            BigInteger remaining = scalar;
            while (remaining > 0)
            {
                if (!remaining.IsEven)
                {
                    result = result.Add(addend);
                }

                addend = addend.Add(addend);
                remaining >>= 1;
            }

            return result;
        }

        public bool Equals(EdwardsPoint other) => X == other.X && Y == other.Y;

        public override bool Equals(object? obj) => obj is EdwardsPoint other && Equals(other);

        public override int GetHashCode()
        {
            unchecked
            {
                return (X.GetHashCode() * 397) ^ Y.GetHashCode();
            }
        }

        private static EdwardsPoint CreateBasePoint()
        {
            FieldElement y = new FieldElement(4) * new FieldElement(5).Invert();
            if (!PointDecoder.TryRecoverX(y, xSignBit: false, out FieldElement x))
            {
                throw new System.InvalidOperationException("Failed to derive the Ed25519 base point; this indicates a bug in the field/curve arithmetic.");
            }

            return new EdwardsPoint(x, y);
        }
    }
}
