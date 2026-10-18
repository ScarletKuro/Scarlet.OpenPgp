using System.Numerics;

namespace Scarlet.OpenPgp.Crypto.Ecdsa
{
    /// <summary>
    /// A point on an <see cref="EcCurve"/> in Jacobian projective coordinates: (X : Y : Z)
    /// represents the affine point (X/Z², Y/Z³), and any Z = 0 represents the point at infinity O.
    /// </summary>
    /// <remarks>
    /// Jacobian coordinates let addition and doubling avoid a field inversion per step; a single
    /// inversion in <see cref="TryToAffine"/> at the end of a scalar multiplication replaces the
    /// hundreds an affine implementation would need. Coordinates are always kept reduced to [0, p).
    /// Nothing here is constant-time: this library only verifies, so every scalar and point it
    /// handles is public.
    /// </remarks>
    internal readonly struct JacobianPoint
    {
        public JacobianPoint(BigInteger x, BigInteger y, BigInteger z)
        {
            X = x;
            Y = y;
            Z = z;
        }

        /// <summary>The point at infinity, the group identity. (1 : 1 : 0) by convention; only Z = 0 matters.</summary>
        public static JacobianPoint Infinity => new JacobianPoint(BigInteger.One, BigInteger.One, BigInteger.Zero);

        public BigInteger X { get; }

        public BigInteger Y { get; }

        public BigInteger Z { get; }

        public bool IsInfinity => Z.IsZero;

        /// <summary>Lifts an affine point (x, y) to Jacobian coordinates as (x : y : 1). The caller is responsible for the point being on the curve.</summary>
        public static JacobianPoint FromAffine(BigInteger x, BigInteger y) => new JacobianPoint(x, y, BigInteger.One);

        /// <summary>
        /// Converts back to affine (x, y) = (X/Z², Y/Z³). Returns <c>false</c> for the point at
        /// infinity, which has no affine representation. The inverse of Z uses Fermat's little
        /// theorem (Z^(p-2)), which is valid because every curve's p is a fixed, known prime.
        /// </summary>
        public bool TryToAffine(EcCurve curve, out BigInteger x, out BigInteger y)
        {
            if (IsInfinity)
            {
                x = BigInteger.Zero;
                y = BigInteger.Zero;
                return false;
            }

            BigInteger p = curve.P;
            BigInteger zInverse = BigInteger.ModPow(Z, p - 2, p);
            BigInteger zInverse2 = (zInverse * zInverse) % p;
            BigInteger zInverse3 = (zInverse2 * zInverse) % p;
            x = (X * zInverse2) % p;
            y = (Y * zInverse3) % p;
            return true;
        }

        /// <summary>
        /// 2P, using the general-a Jacobian doubling formula ("dbl-1998-cmo-2" in the Explicit-Formulas
        /// Database; cf. SEC 1 v2 §2.2.1 for the group law): with S = 4·X·Y², M = 3·X² + a·Z⁴,
        /// X' = M² - 2S, Y' = M·(S - X') - 8·Y⁴, Z' = 2·Y·Z. The a·Z⁴ term is kept in general form
        /// rather than the a = -3 shortcut, because brainpool curves have an arbitrary a.
        /// </summary>
        public JacobianPoint Double(EcCurve curve)
        {
            // Y = 0 means P has order 2 (a vertical tangent), so 2P = O. Cannot happen on these
            // odd-prime-order curves for a valid point, but costs nothing to handle correctly.
            if (IsInfinity || Y.IsZero)
            {
                return Infinity;
            }

            BigInteger p = curve.P;
            BigInteger yy = (Y * Y) % p;
            BigInteger s = (4 * X * yy) % p;
            BigInteger zz = (Z * Z) % p;

            // With a = -3 (the NIST curves), 3·X² + a·Z⁴ = 3·(X - Z²)·(X + Z²): one product
            // instead of two squarings and a multiplication by a ("dbl-2001-b").
            BigInteger m = curve.IsAMinus3
                ? BigIntegerMath.Mod(3 * (X - zz) * (X + zz), p)
                : ((3 * X * X) + (curve.A * ((zz * zz) % p))) % p;
            BigInteger x3 = BigIntegerMath.Mod((m * m) - (2 * s), p);
            BigInteger y3 = BigIntegerMath.Mod((m * (s - x3)) - (8 * ((yy * yy) % p)), p);
            BigInteger z3 = (2 * Y * Z) % p;
            return new JacobianPoint(x3, y3, z3);
        }

        /// <summary>
        /// P + Q, using the general Jacobian addition formula ("add-1998-cmo-2"): with U1 = X1·Z2²,
        /// U2 = X2·Z1², S1 = Y1·Z2³, S2 = Y2·Z1³, H = U2 - U1, R = S2 - S1,
        /// X3 = R² - H³ - 2·U1·H², Y3 = R·(U1·H² - X3) - S1·H³, Z3 = Z1·Z2·H.
        /// The formula is not complete: H = 0 means the two inputs share an x coordinate, so they
        /// are either equal (R = 0, fall back to doubling) or negatives of each other (sum is O).
        /// Missing that special case is a classic ECDSA bug, since u1·G and u2·Q can coincide.
        /// </summary>
        public JacobianPoint Add(EcCurve curve, JacobianPoint other)
        {
            if (IsInfinity)
            {
                return other;
            }

            if (other.IsInfinity)
            {
                return this;
            }

            BigInteger p = curve.P;
            BigInteger z1z1 = (Z * Z) % p;
            BigInteger u2 = (other.X * z1z1) % p;
            BigInteger s2 = (((other.Y * Z) % p) * z1z1) % p;

            // Mixed addition: when the other point is affine (Z2 = 1, as G and Q are), U1 = X1 and
            // S1 = Y1, saving four products ("madd").
            bool otherIsAffine = other.Z.IsOne;
            BigInteger u1;
            BigInteger s1;
            if (otherIsAffine)
            {
                u1 = X;
                s1 = Y;
            }
            else
            {
                BigInteger z2z2 = (other.Z * other.Z) % p;
                u1 = (X * z2z2) % p;
                s1 = (((Y * other.Z) % p) * z2z2) % p;
            }
            BigInteger h = BigIntegerMath.Mod(u2 - u1, p);
            BigInteger r = BigIntegerMath.Mod(s2 - s1, p);

            if (h.IsZero)
            {
                return r.IsZero ? Double(curve) : Infinity;
            }

            BigInteger hh = (h * h) % p;
            BigInteger hhh = (hh * h) % p;
            BigInteger u1hh = (u1 * hh) % p;
            BigInteger x3 = BigIntegerMath.Mod((r * r) - hhh - (2 * u1hh), p);
            BigInteger y3 = BigIntegerMath.Mod((r * (u1hh - x3)) - (s1 * hhh), p);
            BigInteger z3 = otherIsAffine ? (Z * h) % p : (((Z * other.Z) % p) * h) % p;
            return new JacobianPoint(x3, y3, z3);
        }

        /// <summary>k·P by left-to-right double-and-add. <paramref name="k"/> must be non-negative.</summary>
        public JacobianPoint Multiply(EcCurve curve, BigInteger k)
        {
            return MultiplyAdd(curve, k, this, BigInteger.Zero, Infinity);
        }

        /// <summary>
        /// u1·P + u2·Q in a single left-to-right pass ("Shamir's trick", Hankerson-Menezes-Vanstone
        /// Algorithm 3.48): one shared doubling chain, adding P, Q, or the precomputed P + Q
        /// according to the current bit pair. This is the ECDSA verification step
        /// (FIPS 186-5 §6.4.2 step 5: R = u1·G + u2·Q) at roughly the cost of one scalar
        /// multiplication. Both scalars must be non-negative.
        /// </summary>
        public static JacobianPoint MultiplyAdd(EcCurve curve, BigInteger u1, JacobianPoint p, BigInteger u2, JacobianPoint q)
        {
            // Normalized to affine (one inversion), so every addition in the loop - of P, Q or P + Q -
            // takes the cheaper mixed form. P + Q = O can't be normalized and stays as it is.
            JacobianPoint pPlusQ = p.Add(curve, q);
            if (pPlusQ.TryToAffine(curve, out BigInteger sumX, out BigInteger sumY))
            {
                pPlusQ = FromAffine(sumX, sumY);
            }
            int bits = System.Math.Max(BigIntegerMath.BitLength(u1), BigIntegerMath.BitLength(u2));
            byte[] u1Bytes = u1.ToByteArray(); // little-endian; bit i lives in byte i/8
            byte[] u2Bytes = u2.ToByteArray();

            JacobianPoint result = Infinity;
            for (int i = bits - 1; i >= 0; i--)
            {
                result = result.Double(curve);
                bool bit1 = TestBit(u1Bytes, i);
                bool bit2 = TestBit(u2Bytes, i);
                if (bit1 && bit2)
                {
                    result = result.Add(curve, pPlusQ);
                }
                else if (bit1)
                {
                    result = result.Add(curve, p);
                }
                else if (bit2)
                {
                    result = result.Add(curve, q);
                }
            }

            return result;
        }

        private static bool TestBit(byte[] littleEndian, int bit)
        {
            int index = bit >> 3;
            return index < littleEndian.Length && ((littleEndian[index] >> (bit & 7)) & 1) != 0;
        }
    }
}
