using Scarlet.OpenPgp.Crypto.Ed25519;

namespace Scarlet.OpenPgp.Tests.Crypto.Ed25519
{
    public class PointDecoderTests
    {
        [Fact]
        public void TryDecode_WithBasePointsOwnEncoding_ShouldRoundTrip()
        {
            // Arrange: encode B by hand (little-endian y, sign bit of x in the top bit) and decode it back.
            byte[] yLittleEndian = EdwardsPoint.B.Y.Value.ToByteArray();
            var encoded = new byte[32];
            System.Array.Copy(yLittleEndian, encoded, System.Math.Min(yLittleEndian.Length, 32));
            if (EdwardsPoint.B.X.IsOdd)
            {
                encoded[31] |= 0x80;
            }

            // Act
            bool ok = PointDecoder.TryDecode(encoded, out EdwardsPoint decoded);

            // Assert
            Assert.True(ok);
            Assert.Equal(EdwardsPoint.B, decoded);
        }

        [Fact]
        public void TryDecode_WithYGreaterOrEqualToP_ShouldReturnFalse()
        {
            // Arrange: 32 bytes of 0xFF little-endian decodes to a value >= p.
            var encoded = new byte[32];
            for (int i = 0; i < 32; i++)
            {
                encoded[i] = 0xFF;
            }

            // Act
            bool ok = PointDecoder.TryDecode(encoded, out _);

            // Assert
            Assert.False(ok);
        }

        [Fact]
        public void TryDecode_WithWrongLength_ShouldReturnFalse()
        {
            // Act
            bool ok = PointDecoder.TryDecode(new byte[31], out _);

            // Assert
            Assert.False(ok);
        }

        [Fact]
        public void TryRecoverX_ForIdentityPointY1_ShouldReturnZero()
        {
            // Arrange: the identity point (0, 1) - x=0 is a valid, even root for y=1.
            var y = new FieldElement(1);

            // Act
            bool ok = PointDecoder.TryRecoverX(y, xSignBit: false, out FieldElement x);

            // Assert
            Assert.True(ok);
            Assert.True(x.IsZero);
        }

        [Fact]
        public void TryRecoverX_ForIdentityPointY1_WithOddSignRequested_ShouldFail()
        {
            // Arrange: x=0 can only be encoded with the sign bit clear (RFC 8032 §5.1.3).
            var y = new FieldElement(1);

            // Act
            bool ok = PointDecoder.TryRecoverX(y, xSignBit: true, out _);

            // Assert
            Assert.False(ok);
        }
    }
}
