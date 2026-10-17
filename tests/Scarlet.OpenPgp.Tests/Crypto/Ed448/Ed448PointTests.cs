using System.Numerics;
using Scarlet.OpenPgp.Crypto.Ed448;
using Scarlet.OpenPgp.Hashing;

namespace Scarlet.OpenPgp.Tests.Crypto.Ed448
{
    public class Ed448PointTests
    {
        [Fact]
        public void B_ShouldBeOnTheCurve()
        {
            // Assert
            Assert.True(Ed448Point.B.IsOnCurve);
        }

        [Fact]
        public void B_MultipliedByGroupOrder_ShouldBeTheIdentity()
        {
            // Act
            Ed448Point result = Ed448Point.B.ScalarMultiply(Ed448Verifier.GroupOrderL);

            // Assert: B generates the prime-order subgroup of order L (RFC 8032 §5.2).
            Assert.True(result.Equals(Ed448Point.Identity));
            Assert.False(Ed448Point.B.ScalarMultiply(Ed448Verifier.GroupOrderL - 1).Equals(Ed448Point.Identity));
        }

        [Fact]
        public void D_ShouldBeANonSquare()
        {
            // Act: Euler's criterion, d^((p-1)/2) = -1 for a non-residue. Non-square d is what makes the
            // RFC 8032 §5.2.4 addition formulas complete and the decoder's denominator never zero.
            Ed448FieldElement legendre = Ed448Point.D.Pow((Ed448FieldElement.P - 1) / 2);

            // Assert
            Assert.True(legendre == -Ed448FieldElement.One);
        }

        [Fact]
        public void Double_ShouldMatchAddingAPointToItself()
        {
            // Arrange
            Ed448Point p = Ed448Point.B.ScalarMultiply(12345);

            // Act
            Ed448Point doubled = p.Double();
            Ed448Point added = p.Add(p);

            // Assert
            Assert.True(doubled.Equals(added));
            Assert.True(doubled.IsOnCurve);
        }

        [Fact]
        public void Add_WithIdentity_ShouldReturnTheSamePoint()
        {
            // Act
            Ed448Point result = Ed448Point.B.Add(Ed448Point.Identity);

            // Assert
            Assert.True(result.Equals(Ed448Point.B));
        }

        [Fact]
        public void ScalarMultiply_ShouldBeDistributiveOverScalarAddition()
        {
            // Arrange
            var a = BigInteger.Parse("987654321987654321987654321");
            var b = BigInteger.Parse("123456789123456789123456789123456789");

            // Act
            Ed448Point left = Ed448Point.B.ScalarMultiply(a + b);
            Ed448Point right = Ed448Point.B.ScalarMultiply(a).Add(Ed448Point.B.ScalarMultiply(b));

            // Assert
            Assert.True(left.Equals(right));
        }

        [Fact]
        public void TryDecode_WithEncodedBasePoint_ShouldRoundTrip()
        {
            // Arrange
            byte[] encoded = Encode(Ed448Point.B);

            // Act
            bool decoded = Ed448PointDecoder.TryDecode(encoded, out Ed448Point point);

            // Assert
            Assert.True(decoded);
            Assert.True(point.Equals(Ed448Point.B));
        }

        [Fact]
        public void TryDecode_WithCanonicalIdentity_ShouldSucceed()
        {
            // Arrange: y = 1, x_0 = 0.
            var encoded = new byte[57];
            encoded[0] = 0x01;

            // Act
            bool decoded = Ed448PointDecoder.TryDecode(encoded, out Ed448Point point);

            // Assert
            Assert.True(decoded);
            Assert.True(point.Equals(Ed448Point.Identity));
        }

        [Fact]
        public void TryDecode_WithXZeroAndSignBitSet_ShouldFail()
        {
            // Arrange: y = 1 forces x = 0, and RFC 8032 §5.2.3 step 4 forbids x_0 = 1 with x = 0.
            var encoded = new byte[57];
            encoded[0] = 0x01;
            encoded[56] = 0x80;

            // Act
            bool decoded = Ed448PointDecoder.TryDecode(encoded, out _);

            // Assert
            Assert.False(decoded);
        }

        [Fact]
        public void TryDecode_ForSmallY_ShouldSucceedExactlyWhenXSquaredIsAQuadraticResidue()
        {
            int failures = 0;
            for (int yValue = 0; yValue < 40; yValue++)
            {
                // Arrange: independently decide solvability with Euler's criterion on (y^2 - 1)/(d y^2 - 1).
                var y = new Ed448FieldElement(yValue);
                Ed448FieldElement x2 = (y.Square() - Ed448FieldElement.One) * ((Ed448Point.D * y.Square()) - Ed448FieldElement.One).Invert();
                bool expected = x2.IsZero || x2.Pow((Ed448FieldElement.P - 1) / 2) == Ed448FieldElement.One;
                var encoded = new byte[57];
                encoded[0] = (byte)yValue;

                // Act
                bool decoded = Ed448PointDecoder.TryDecode(encoded, out Ed448Point point);

                // Assert
                Assert.True(expected == decoded, "Decoder disagreed with Euler's criterion for y = " + yValue);
                if (decoded)
                {
                    Assert.True(point.IsOnCurve);
                    Assert.False(point.X.IsOdd); // x_0 = 0 was requested
                }
                else
                {
                    failures++;
                }
            }

            // Roughly half of all y have no matching x; make sure the rejection path was exercised.
            Assert.True(failures > 0);
        }

        [Fact]
        public void TryDecode_WithStrayBitsInLastByte_ShouldFail()
        {
            for (int bit = 0; bit < 7; bit++)
            {
                // Arrange: identity encoding plus one of the seven must-be-zero bits.
                var encoded = new byte[57];
                encoded[0] = 0x01;
                encoded[56] = (byte)(1 << bit);

                // Act
                bool decoded = Ed448PointDecoder.TryDecode(encoded, out _);

                // Assert
                Assert.False(decoded);
            }
        }

        [Fact]
        public void B_MultipliedByRfc8032SecretScalar_ShouldMatchPublishedPublicKey()
        {
            // Arrange: RFC 8032 §5.2.5 key generation for §7.4 TEST "Blank". Ties the hardcoded base
            // point, the projective arithmetic and SHAKE256 together against a published value.
            byte[] secretKey = System.Convert.FromHexString(
                "6c82a562cb808d10d632be89c8513ebf6c929f34ddfa8c9f63c9960ef6e348a3528c8a3fcc2f044e39a3fc5b94492f8f032e7549a20098f95b");
            byte[] h = KeccakHash.Shake256(secretKey, 114);
            var scalarBytes = new byte[57];
            System.Array.Copy(h, scalarBytes, 57);
            scalarBytes[0] &= 0xFC;
            scalarBytes[56] = 0;
            scalarBytes[55] |= 0x80;
            BigInteger s = Ed448PointDecoder.LittleEndianToBigInteger(scalarBytes);

            // Act
            byte[] publicKey = Encode(Ed448Point.B.ScalarMultiply(s));

            // Assert
            Assert.Equal(
                "5fd7449b59b461fd2ce787ec616ad46a1da1342485a70e1f8a0ea75d80e96778edf124769b46c7061bd6783df1e50f6cd1fa1abeafe8256180",
                System.Convert.ToHexString(publicKey).ToLowerInvariant());
        }

        /// <summary>RFC 8032 §5.2.2 encoding, test-side only (the library is verify-only and never encodes).</summary>
        private static byte[] Encode(Ed448Point point)
        {
            Ed448FieldElement zInverse = point.Z.Invert();
            Ed448FieldElement x = point.X * zInverse;
            Ed448FieldElement y = point.Y * zInverse;

            var encoded = new byte[57];
            byte[] yBytes = y.Value.ToByteArray();
            System.Array.Copy(yBytes, encoded, System.Math.Min(yBytes.Length, 57));
            if (x.IsOdd)
            {
                encoded[56] |= 0x80;
            }

            return encoded;
        }
    }
}
