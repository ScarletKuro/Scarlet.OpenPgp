using System.Numerics;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Math.EC;
using Org.BouncyCastle.Security;
using Scarlet.OpenPgp.Crypto.Ecdsa;
using BcBigInteger = Org.BouncyCastle.Math.BigInteger;

namespace Scarlet.OpenPgp.Tests.Crypto.Ecdsa
{
    public class EcCurveTests
    {
        // Every curve constant in EcCurve was transcribed from BouncyCastle; these tests re-derive
        // them from BouncyCastle at test time and also check the internal consistency that holds
        // for any genuine curve (G on the curve, n·G = O), so a single wrong hex digit fails loudly.

        [Theory]
        [InlineData("P-256", 32, 256)]
        [InlineData("P-384", 48, 384)]
        [InlineData("P-521", 66, 521)]
        [InlineData("brainpoolP256r1", 32, 256)]
        [InlineData("brainpoolP384r1", 48, 384)]
        [InlineData("brainpoolP512r1", 64, 512)]
        public void Constants_ShouldMatchBouncyCastle(string name, int expectedFieldByteLength, int expectedOrderBitLength)
        {
            // Arrange
            EcCurve curve = EcTestCurves.Get(name);
            X9ECParameters reference = EcTestCurves.GetReference(name);
            ECPoint g = reference.G.Normalize();
            byte[] derOid = ECNamedCurveTable.GetOid(name).GetEncoded(Asn1Encodable.Der);

            // Act
            byte[] oidContent = derOid[2..]; // strip the 0x06 tag and one-byte length

            // Assert
            Assert.Equal(EcTestCurves.ToNumerics(reference.Curve.Field.Characteristic), curve.P);
            Assert.Equal(EcTestCurves.ToNumerics(reference.Curve.A.ToBigInteger()), curve.A);
            Assert.Equal(EcTestCurves.ToNumerics(reference.Curve.B.ToBigInteger()), curve.B);
            Assert.Equal(EcTestCurves.ToNumerics(g.AffineXCoord.ToBigInteger()), curve.Gx);
            Assert.Equal(EcTestCurves.ToNumerics(g.AffineYCoord.ToBigInteger()), curve.Gy);
            Assert.Equal(EcTestCurves.ToNumerics(reference.N), curve.N);
            Assert.Equal(BcBigInteger.One, reference.H); // cofactor 1 is what makes on-curve validation sufficient
            Assert.Equal(0x06, derOid[0]);
            Assert.Equal(derOid.Length - 2, derOid[1]);
            Assert.Equal(oidContent, curve.Oid);
            Assert.Equal(expectedFieldByteLength, curve.FieldByteLength);
            Assert.Equal((reference.Curve.FieldSize + 7) / 8, curve.FieldByteLength);
            Assert.Equal(expectedOrderBitLength, curve.OrderBitLength);
        }

        [Theory]
        [InlineData("P-256", "2A8648CE3D030107")]
        [InlineData("P-384", "2B81040022")]
        [InlineData("P-521", "2B81040023")]
        [InlineData("brainpoolP256r1", "2B2403030208010107")]
        [InlineData("brainpoolP384r1", "2B240303020801010B")]
        [InlineData("brainpoolP512r1", "2B240303020801010D")]
        public void FindByOid_WithRfc9580Oid_ShouldReturnCurve(string name, string oidHex)
        {
            // Arrange: the "Curve OID Octets" column of RFC 9580 §9.2 Table 19.
            byte[] oid = System.Convert.FromHexString(oidHex);

            // Act
            EcCurve? curve = EcCurve.FindByOid(oid);

            // Assert
            Assert.Same(EcTestCurves.Get(name), curve);
        }

        [Theory]
        [InlineData("2B060104019755010501")] // Curve25519Legacy: an ECDH curve, not ECDSA
        [InlineData("2B06010401DA470F01")] // Ed25519Legacy: not a Weierstrass curve
        [InlineData("2B8104000A")] // secp256k1: not in RFC 9580
        [InlineData("06082A8648CE3D030107")] // P-256 with the DER tag/length still attached
        [InlineData("2A8648CE3D0301")] // P-256 truncated by one byte
        [InlineData("2A8648CE3D03010700")] // P-256 with a trailing byte
        [InlineData("")]
        public void FindByOid_WithUnknownOrMalformedOid_ShouldReturnNull(string oidHex)
        {
            // Arrange
            byte[] oid = System.Convert.FromHexString(oidHex);

            // Act
            EcCurve? curve = EcCurve.FindByOid(oid);

            // Assert
            Assert.Null(curve);
        }

        [Fact]
        public void Oid_WhenMutatedByCaller_ShouldNotAffectCurveTable()
        {
            // Arrange
            byte[] oid = EcCurve.NistP256.Oid;

            // Act
            oid[0] ^= 0xFF;

            // Assert
            Assert.Same(EcCurve.NistP256, EcCurve.FindByOid(System.Convert.FromHexString("2A8648CE3D030107")));
            Assert.Equal(0x2A, EcCurve.NistP256.Oid[0]);
        }

        [Fact]
        public void All_ShouldContainSixDistinctCurves()
        {
            // Act
            var all = EcCurve.All;

            // Assert
            Assert.Equal(6, all.Count);
            Assert.Equal(6, all.Distinct().Count());
        }

        [Theory]
        [InlineData("P-256")]
        [InlineData("P-384")]
        [InlineData("P-521")]
        [InlineData("brainpoolP256r1")]
        [InlineData("brainpoolP384r1")]
        [InlineData("brainpoolP512r1")]
        public void BasePoint_ShouldBeOnCurve(string name)
        {
            // Arrange
            EcCurve curve = EcTestCurves.Get(name);

            // Act
            bool onCurve = curve.IsOnCurve(curve.Gx, curve.Gy);
            bool perturbedOnCurve = curve.IsOnCurve(curve.Gx, (curve.Gy + 1) % curve.P);

            // Assert
            Assert.True(onCurve);
            Assert.False(perturbedOnCurve);
        }

        [Theory]
        [InlineData("P-256")]
        [InlineData("P-384")]
        [InlineData("P-521")]
        [InlineData("brainpoolP256r1")]
        [InlineData("brainpoolP384r1")]
        [InlineData("brainpoolP512r1")]
        public void ScalarMultiply_ByOrder_ShouldYieldInfinity(string name)
        {
            // Arrange
            EcCurve curve = EcTestCurves.Get(name);
            JacobianPoint g = JacobianPoint.FromAffine(curve.Gx, curve.Gy);

            // Act
            JacobianPoint nG = g.Multiply(curve, curve.N);
            JacobianPoint nMinusOneG = g.Multiply(curve, curve.N - 1);

            // Assert: n·G = O, and (n-1)·G = -G = (Gx, p - Gy).
            Assert.True(nG.IsInfinity);
            Assert.True(nMinusOneG.TryToAffine(curve, out BigInteger x, out BigInteger y));
            Assert.Equal(curve.Gx, x);
            Assert.Equal(curve.P - curve.Gy, y);
        }

        [Theory]
        [InlineData("P-256")]
        [InlineData("P-384")]
        [InlineData("P-521")]
        [InlineData("brainpoolP256r1")]
        [InlineData("brainpoolP384r1")]
        [InlineData("brainpoolP512r1")]
        public void ScalarMultiply_WithRandomScalars_ShouldMatchBouncyCastle(string name)
        {
            // Arrange
            EcCurve curve = EcTestCurves.Get(name);
            X9ECParameters reference = EcTestCurves.GetReference(name);
            var random = new SecureRandom();
            JacobianPoint g = JacobianPoint.FromAffine(curve.Gx, curve.Gy);

            for (int i = 0; i < 5; i++)
            {
                BcBigInteger k = new BcBigInteger(reference.N.BitLength + 8, random); // occasionally >= n, exercising wrap-around
                ECPoint expected = reference.G.Multiply(k).Normalize();

                // Act
                JacobianPoint actual = g.Multiply(curve, EcTestCurves.ToNumerics(k));

                // Assert
                Assert.True(actual.TryToAffine(curve, out BigInteger x, out BigInteger y));
                Assert.Equal(EcTestCurves.ToNumerics(expected.AffineXCoord.ToBigInteger()), x);
                Assert.Equal(EcTestCurves.ToNumerics(expected.AffineYCoord.ToBigInteger()), y);
                Assert.True(curve.IsOnCurve(x, y));
            }
        }

        [Theory]
        [InlineData("P-256")]
        [InlineData("P-521")]
        [InlineData("brainpoolP384r1")]
        [InlineData("brainpoolP512r1")]
        public void MultiplyAdd_WithRandomScalars_ShouldMatchBouncyCastleSumOfTwoMultiplies(string name)
        {
            // Arrange
            EcCurve curve = EcTestCurves.Get(name);
            X9ECParameters reference = EcTestCurves.GetReference(name);
            var random = new SecureRandom();
            BcBigInteger d = new BcBigInteger(reference.N.BitLength - 1, random).Add(BcBigInteger.One);
            ECPoint referenceQ = reference.G.Multiply(d).Normalize();
            JacobianPoint g = JacobianPoint.FromAffine(curve.Gx, curve.Gy);
            JacobianPoint q = JacobianPoint.FromAffine(
                EcTestCurves.ToNumerics(referenceQ.AffineXCoord.ToBigInteger()),
                EcTestCurves.ToNumerics(referenceQ.AffineYCoord.ToBigInteger()));

            for (int i = 0; i < 5; i++)
            {
                BcBigInteger u1 = new BcBigInteger(reference.N.BitLength, random).Mod(reference.N);
                BcBigInteger u2 = new BcBigInteger(reference.N.BitLength, random).Mod(reference.N);
                ECPoint expected = ECAlgorithms.SumOfTwoMultiplies(reference.G, u1, referenceQ, u2).Normalize();

                // Act
                JacobianPoint actual = JacobianPoint.MultiplyAdd(curve, EcTestCurves.ToNumerics(u1), g, EcTestCurves.ToNumerics(u2), q);

                // Assert
                Assert.True(actual.TryToAffine(curve, out BigInteger x, out BigInteger y));
                Assert.Equal(EcTestCurves.ToNumerics(expected.AffineXCoord.ToBigInteger()), x);
                Assert.Equal(EcTestCurves.ToNumerics(expected.AffineYCoord.ToBigInteger()), y);
            }
        }

        [Theory]
        [InlineData("P-256")]
        [InlineData("brainpoolP256r1")]
        public void Add_WithEqualAndOppositePoints_ShouldHandleSpecialCases(string name)
        {
            // Arrange: the incomplete Jacobian addition formula needs explicit P + P and P + (-P)
            // handling; the latter is exactly what happens in ECDSA when u1·G = -u2·Q.
            EcCurve curve = EcTestCurves.Get(name);
            JacobianPoint g = JacobianPoint.FromAffine(curve.Gx, curve.Gy);
            JacobianPoint threeG = g.Multiply(curve, 3);
            JacobianPoint minusThreeG = g.Multiply(curve, curve.N - 3);

            // Act
            JacobianPoint doubled = threeG.Add(curve, threeG);
            JacobianPoint cancelled = threeG.Add(curve, minusThreeG);
            JacobianPoint sixG = g.Multiply(curve, 6);
            JacobianPoint identityLeft = JacobianPoint.Infinity.Add(curve, g);
            JacobianPoint identityRight = g.Add(curve, JacobianPoint.Infinity);
            JacobianPoint shamirCancelled = JacobianPoint.MultiplyAdd(curve, 3, g, curve.N - 3, g);

            // Assert
            Assert.True(doubled.TryToAffine(curve, out BigInteger dx, out BigInteger dy));
            Assert.True(sixG.TryToAffine(curve, out BigInteger sx, out BigInteger sy));
            Assert.Equal(sx, dx);
            Assert.Equal(sy, dy);
            Assert.True(cancelled.IsInfinity);
            Assert.True(shamirCancelled.IsInfinity);
            Assert.True(identityLeft.TryToAffine(curve, out BigInteger lx, out _));
            Assert.True(identityRight.TryToAffine(curve, out BigInteger rx, out _));
            Assert.Equal(curve.Gx, lx);
            Assert.Equal(curve.Gx, rx);
            Assert.True(g.Multiply(curve, BigInteger.Zero).IsInfinity);
            Assert.True(JacobianPoint.Infinity.Double(curve).IsInfinity);
        }

        [Fact]
        public void IsOnCurve_WithNonCanonicalCoordinates_ShouldReturnFalse()
        {
            // Arrange: (Gx + p, Gy) satisfies the congruence but is not a canonical field element.
            EcCurve curve = EcCurve.NistP256;

            // Act
            bool xOverflow = curve.IsOnCurve(curve.Gx + curve.P, curve.Gy);
            bool yOverflow = curve.IsOnCurve(curve.Gx, curve.Gy + curve.P);
            bool negative = curve.IsOnCurve(curve.Gx - curve.P, curve.Gy);

            // Assert
            Assert.False(xOverflow);
            Assert.False(yOverflow);
            Assert.False(negative);
        }
    }
}
