using System.Numerics;

namespace Scarlet.OpenPgp.Crypto.Ed25519
{
    /// <summary>
    /// A point on Ed25519's twisted Edwards curve (-x^2 + y^2 = 1 + d*x^2*y^2), held in extended
    /// homogeneous coordinates (X:Y:Z:T) with x = X/Z, y = Y/Z, x*y = T/Z (RFC 8032 §5.1.4).
    /// Extended coordinates make addition inversion-free - affine addition needs two field
    /// inversions per step, which made every verification (and every self-signature check in a
    /// keyring) needlessly slow. BigInteger-backed field arithmetic remains a deliberate
    /// simplicity-over-speed choice, acceptable per SPEC.md: a verify-only library has no secret
    /// scalars to protect from timing leaks.
    /// </summary>
    internal readonly struct EdwardsPoint : System.IEquatable<EdwardsPoint>
    {
        /// <summary>The curve constant d = -121665/121666 (mod p), derived from first principles rather than hardcoded so it is auditable against RFC 8032 §5.1.1.</summary>
        public static readonly FieldElement D = new FieldElement(-121665) * new FieldElement(121666).Invert();

        private static readonly FieldElement TwoD = D + D;

        public static readonly EdwardsPoint Identity = new EdwardsPoint(FieldElement.Zero, FieldElement.One);

        /// <summary>The Ed25519 base point B = (x, 4/5) with x chosen even (RFC 8032 §5.1.2), derived rather than hardcoded for the same auditability reason as <see cref="D"/>.</summary>
        public static readonly EdwardsPoint B = CreateBasePoint();

        private readonly FieldElement _x;
        private readonly FieldElement _y;
        private readonly FieldElement _z;
        private readonly FieldElement _t;

        /// <summary>Creates a point from affine coordinates.</summary>
        public EdwardsPoint(FieldElement x, FieldElement y)
            : this(x, y, FieldElement.One, x * y)
        {
        }

        private EdwardsPoint(FieldElement x, FieldElement y, FieldElement z, FieldElement t)
        {
            _x = x;
            _y = y;
            _z = z;
            _t = t;
        }

        /// <summary>The affine x coordinate (costs one field inversion).</summary>
        public FieldElement X => _x * _z.Invert();

        /// <summary>The affine y coordinate (costs one field inversion).</summary>
        public FieldElement Y => _y * _z.Invert();

        public bool IsOnCurve
        {
            get
            {
                // The homogeneous curve equation (-X^2 + Y^2) Z^2 = Z^4 + d X^2 Y^2, plus the
                // extended-coordinate invariant X*Y = Z*T.
                FieldElement xx = _x * _x;
                FieldElement yy = _y * _y;
                FieldElement zz = _z * _z;
                FieldElement lhs = (yy - xx) * zz;
                FieldElement rhs = (zz * zz) + (D * xx * yy);
                return lhs == rhs && _x * _y == _z * _t;
            }
        }

        /// <summary>
        /// The unified extended-coordinates addition law (RFC 8032 §5.1.4). It is complete for
        /// Ed25519 (a = -1 and d a non-square), so the same formula also doubles a point.
        /// </summary>
        public EdwardsPoint Add(EdwardsPoint other)
        {
            FieldElement a = (_y - _x) * (other._y - other._x);
            FieldElement b = (_y + _x) * (other._y + other._x);
            FieldElement c = _t * TwoD * other._t;
            FieldElement d = (_z + _z) * other._z;
            FieldElement e = b - a;
            FieldElement f = d - c;
            FieldElement g = d + c;
            FieldElement h = b + a;
            return new EdwardsPoint(e * f, g * h, f * g, e * h);
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

        /// <summary>Projective equality: X1/Z1 = X2/Z2 and Y1/Z1 = Y2/Z2, compared without inverting.</summary>
        public bool Equals(EdwardsPoint other) => _x * other._z == other._x * _z && _y * other._z == other._y * _z;

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
