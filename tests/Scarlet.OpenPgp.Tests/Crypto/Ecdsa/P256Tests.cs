using System.Numerics;
using Scarlet.OpenPgp.Crypto.Ecdsa;

namespace Scarlet.OpenPgp.Tests.Crypto.Ecdsa
{
    /// <summary>
    /// The fixed-width P-256 path checked against the generic BigInteger arithmetic it replaces for
    /// that curve: the same u1·G + u2·Q must come out of both, including the special cases the
    /// mixed-addition formula can't handle by itself.
    /// </summary>
    public class P256Tests
    {
        private static readonly EcCurve Curve = EcCurve.NistP256;

        /// <summary>The affine x of u1·G + u2·Q by the generic code, or null for the point at infinity.</summary>
        private static BigInteger? Generic(BigInteger u1, BigInteger u2, BigInteger qx, BigInteger qy)
        {
            JacobianPoint sum = JacobianPoint.MultiplyAdd(Curve, u1, JacobianPoint.FromAffine(Curve.Gx, Curve.Gy), u2, JacobianPoint.FromAffine(qx, qy));
            return sum.TryToAffine(Curve, out BigInteger x, out _) ? x : null;
        }

        private static BigInteger? FixedWidth(BigInteger u1, BigInteger u2, BigInteger qx, BigInteger qy) =>
            P256.TryLinearCombinationX(u1, u2, qx, qy, out BigInteger x) ? x : null;

        private static (BigInteger X, BigInteger Y) Multiple(BigInteger k)
        {
            Assert.True(JacobianPoint.FromAffine(Curve.Gx, Curve.Gy).Multiply(Curve, k).TryToAffine(Curve, out BigInteger x, out BigInteger y));
            return (x, y);
        }

        [Fact]
        public void TryLinearCombinationX_ShouldMatchTheGenericArithmetic()
        {
            // Arrange: special points (G itself, -G so that G + Q = O) and scalars (zero, n - 1, all
            // bits set below 2^256), plus seeded random ones.
            BigInteger n = Curve.N;
            (BigInteger gx, BigInteger gy) = (Curve.Gx, Curve.Gy);
            var points = new List<(BigInteger X, BigInteger Y)> { (gx, gy), (gx, Curve.P - gy), Multiple(2), Multiple(n - 1) };
            var scalars = new List<BigInteger> { 0, 1, 2, 3, n - 1, n - 2, (BigInteger.One << 255) - 1, (BigInteger.One << 256) - 1 };
            var random = new Random(256);
            var bytes = new byte[32];
            for (int i = 0; i < 12; i++)
            {
                random.NextBytes(bytes);
                BigInteger k = new BigInteger(bytes, isUnsigned: true) % n;
                points.Add(Multiple(k == 0 ? 1 : k));
                random.NextBytes(bytes);
                scalars.Add(new BigInteger(bytes, isUnsigned: true));
            }

            // Act & Assert
            foreach ((BigInteger qx, BigInteger qy) in points)
            {
                for (int i = 0; i < scalars.Count; i++)
                {
                    BigInteger u1 = scalars[i];
                    BigInteger u2 = scalars[(i * 5 + 3) % scalars.Count];
                    Assert.Equal(Generic(u1, u2, qx, qy), FixedWidth(u1, u2, qx, qy));
                    Assert.Equal(Generic(u1, u1, qx, qy), FixedWidth(u1, u1, qx, qy)); // equal scalars hit G + Q on every set bit
                }
            }
        }

        [Fact]
        public void TryLinearCombinationX_WithCancellingTerms_ShouldReturnFalseForThePointAtInfinity()
        {
            // Arrange: Q = -G, so u·G + u·Q = O for every u; and both scalars zero.
            BigInteger negatedGy = Curve.P - Curve.Gy;

            // Act & Assert
            Assert.False(P256.TryLinearCombinationX(12345, 12345, Curve.Gx, negatedGy, out _));
            Assert.False(P256.TryLinearCombinationX(0, 0, Curve.Gx, Curve.Gy, out _));
        }
    }
}
