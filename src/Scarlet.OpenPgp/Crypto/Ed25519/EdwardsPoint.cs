using System;
using System.Numerics;

namespace Scarlet.OpenPgp.Crypto.Ed25519
{
    /// <summary>
    /// A point on Ed25519's twisted Edwards curve (-x^2 + y^2 = 1 + d*x^2*y^2), held in extended
    /// homogeneous coordinates (X:Y:Z:T) with x = X/Z, y = Y/Z, x*y = T/Z (RFC 8032 §5.1.4).
    /// Extended coordinates make addition inversion-free - affine addition needs two field
    /// inversions per step, which made every verification (and every self-signature check in a
    /// keyring) needlessly slow. Nothing here is constant-time: a verify-only library has no secret
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

        /// <summary>B, 3B, ..., 15B, computed once for <see cref="DoubleScalarMultiply"/>.</summary>
        private static readonly EdwardsPoint[] BaseOddMultiples = CreateBaseOddMultiples();

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

        /// <summary>
        /// 2P with the dedicated doubling formula (RFC 8032 §5.1.4): 4 squarings and 4
        /// multiplications instead of the 9 multiplications of <see cref="Add"/> with itself.
        /// </summary>
        public EdwardsPoint Double()
        {
            FieldElement a = _x.Square();
            FieldElement b = _y.Square();
            FieldElement zz = _z.Square();
            FieldElement c = zz + zz;
            FieldElement h = a + b;
            FieldElement e = h - (_x + _y).Square();
            FieldElement g = a - b;
            FieldElement f = c + g;
            return new EdwardsPoint(e * f, g * h, f * g, e * h);
        }

        /// <summary>-P = (-x, y), i.e. (-X : Y : Z : -T).</summary>
        public EdwardsPoint Negate() => new EdwardsPoint(-_x, _y, _z, -_t);

        /// <summary>[scalar]P by left-to-right double-and-add. <paramref name="scalar"/> must be non-negative.</summary>
        public EdwardsPoint ScalarMultiply(BigInteger scalar) => MultiplyAdd(scalar, this, BigInteger.Zero, Identity);

        /// <summary>
        /// [u1]P + [u2]Q in a single left-to-right pass ("Shamir's trick"): one shared doubling
        /// chain, adding P, Q or the precomputed P + Q according to the current bit pair - about
        /// the cost of one scalar multiplication instead of two. Both scalars must be non-negative.
        /// </summary>
        public static EdwardsPoint MultiplyAdd(BigInteger u1, EdwardsPoint p, BigInteger u2, EdwardsPoint q)
        {
            byte[] u1Bytes = u1.ToByteArray(); // little-endian; bit i lives in byte i / 8
            byte[] u2Bytes = u2.ToByteArray();
            EdwardsPoint pPlusQ = p.Add(q);

            EdwardsPoint result = Identity;
            for (int bit = (Math.Max(u1Bytes.Length, u2Bytes.Length) * 8) - 1; bit >= 0; bit--)
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

        /// <summary>The number of odd multiples in a window table: P, 3P, ..., 15P.</summary>
        private const int OddMultipleCount = 8;

        /// <summary>Fills <paramref name="table"/> with P, 3P, 5P, ..., 15P: the odd multiples <see cref="DoubleScalarMultiply"/> adds, indexed by digit / 2.</summary>
        private static void OddMultiples(EdwardsPoint p, Span<EdwardsPoint> table)
        {
            table[0] = p;
            EdwardsPoint twice = p.Double();
            for (int i = 1; i < OddMultipleCount; i++)
            {
                table[i] = table[i - 1].Add(twice);
            }
        }

        private static EdwardsPoint[] CreateBaseOddMultiples()
        {
            var table = new EdwardsPoint[OddMultipleCount];
            OddMultiples(B, table);
            return table;
        }

        /// <summary>
        /// [a]A + [b]B for the base point B - ref10's ge_double_scalarmult_vartime. Both scalars are
        /// recoded into signed digits in ±{1, 3, ..., 15} with at least four zeros between non-zero
        /// digits (<see cref="SlidingWindow"/>), so one shared doubling chain needs an addition only
        /// about every sixth bit per scalar instead of every other bit. Not constant-time, which is
        /// fine here: a verifier's scalars are public. The digits and A's table of odd multiples
        /// (about 3 KB) live on the stack, so a verification allocates nothing for them.
        /// </summary>
        /// <param name="a">A scalar below 2^255.</param>
        /// <param name="pointA">The point A.</param>
        /// <param name="b">A scalar below 2^255.</param>
        public static EdwardsPoint DoubleScalarMultiply(BigInteger a, EdwardsPoint pointA, BigInteger b)
        {
            Span<EdwardsPoint> aOddMultiples = stackalloc EdwardsPoint[OddMultipleCount];
            OddMultiples(pointA, aOddMultiples);
            Span<sbyte> aDigits = stackalloc sbyte[256];
            Span<sbyte> bDigits = stackalloc sbyte[256];
            SlidingWindow(a, aDigits);
            SlidingWindow(b, bDigits);

            int i = 255;
            while (i >= 0 && aDigits[i] == 0 && bDigits[i] == 0)
            {
                i--;
            }

            EdwardsPoint result = Identity;
            for (; i >= 0; i--)
            {
                result = result.Double();
                result = AddDigit(result, aDigits[i], aOddMultiples);
                result = AddDigit(result, bDigits[i], BaseOddMultiples);
            }

            return result;
        }

        private static EdwardsPoint AddDigit(EdwardsPoint point, sbyte digit, ReadOnlySpan<EdwardsPoint> oddMultiples)
        {
            if (digit > 0)
            {
                return point.Add(oddMultiples[digit / 2]);
            }

            if (digit < 0)
            {
                return point.Add(oddMultiples[-digit / 2].Negate());
            }

            return point;
        }

        /// <summary>
        /// ref10's slide(): the scalar's 256 bits as signed digits r[i] in {0, ±1, ±3, ..., ±15} with
        /// sum r[i]·2^i equal to the scalar. Each set bit absorbs the following bits into its window
        /// while the result stays within ±15, borrowing upward when it has to subtract.
        /// </summary>
        private static void SlidingWindow(BigInteger scalar, Span<sbyte> digits)
        {
            byte[] littleEndian = scalar.ToByteArray();
            if (scalar.Sign < 0 || littleEndian.Length > 33 || (littleEndian.Length == 33 && littleEndian[32] != 0) || (littleEndian.Length >= 32 && littleEndian[31] >= 0x80))
            {
                throw new ArgumentOutOfRangeException(nameof(scalar), "The scalar must be non-negative and below 2^255.");
            }

            for (int i = 0; i < 256; i++)
            {
                int index = i >> 3;
                digits[i] = (sbyte)(index < littleEndian.Length ? (littleEndian[index] >> (i & 7)) & 1 : 0);
            }

            for (int i = 0; i < 256; i++)
            {
                if (digits[i] == 0)
                {
                    continue;
                }

                for (int b = 1; b <= 6 && i + b < 256; b++)
                {
                    if (digits[i + b] == 0)
                    {
                        continue;
                    }

                    int shifted = digits[i + b] << b;
                    if (digits[i] + shifted <= 15)
                    {
                        digits[i] = (sbyte)(digits[i] + shifted);
                        digits[i + b] = 0;
                    }
                    else if (digits[i] - shifted >= -15)
                    {
                        digits[i] = (sbyte)(digits[i] - shifted);
                        for (int k = i + b; k < 256; k++)
                        {
                            if (digits[k] == 0)
                            {
                                digits[k] = 1;
                                break;
                            }

                            digits[k] = 0;
                        }
                    }
                    else
                    {
                        break;
                    }
                }
            }

        }

        private static bool TestBit(byte[] littleEndian, int bit)
        {
            int index = bit >> 3;
            return index < littleEndian.Length && ((littleEndian[index] >> (bit & 7)) & 1) != 0;
        }

        private static EdwardsPoint CreateBasePoint()
        {
            FieldElement y = new FieldElement(4) * new FieldElement(5).Invert();
            if (!PointDecoder.TryRecoverX(y, xSignBit: false, out FieldElement x))
            {
                throw new InvalidOperationException("Failed to derive the Ed25519 base point; this indicates a bug in the field/curve arithmetic.");
            }

            return new EdwardsPoint(x, y);
        }
    }
}
