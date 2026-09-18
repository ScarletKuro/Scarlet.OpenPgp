using System.Numerics;
using Scarlet.OpenPgp.Internal;
using Scarlet.OpenPgp.Packets;

namespace Scarlet.OpenPgp.Tests.Packets
{
    public class MpiTests
    {
        [Fact]
        public void ReadFrom_WithSimpleSingleByteValue_ShouldDecodeCorrectly()
        {
            // Arrange: bit length 8, value byte 0x05. This is a deliberately *non-canonical*
            // encoding (5's true minimal bit length is 3, not 8) - exercising the permissive,
            // default `requireCanonical: false` path used for EdDSA's opaque-bytestring MPIs.
            // See the requireCanonical tests below for the RSA-style strict path.
            byte[] data = { 0x00, 0x08, 0x05 };

            // Act
            (BigInteger value, int consumed) = Mpi.ReadFrom(data, 0);

            // Assert
            Assert.Equal(new BigInteger(5), value);
            Assert.Equal(3, consumed);
        }

        [Fact]
        public void ReadFrom_WithRequireCanonicalAndNonCanonicalBitLength_ShouldFailClosed()
        {
            // Arrange: same non-canonical encoding as above (declared 8 bits, true minimal is 3).
            byte[] data = { 0x00, 0x08, 0x05 };

            // Act & Assert
            Assert.Throws<FailClosedException>(() => Mpi.ReadFrom(data, 0, requireCanonical: true));
        }

        [Fact]
        public void ReadFrom_WithRequireCanonicalAndCanonicalBitLength_ShouldSucceed()
        {
            // Arrange: 5's true minimal bit length is 3.
            byte[] data = { 0x00, 0x03, 0x05 };

            // Act
            (BigInteger value, int consumed) = Mpi.ReadFrom(data, 0, requireCanonical: true);

            // Assert
            Assert.Equal(new BigInteger(5), value);
            Assert.Equal(3, consumed);
        }

        [Fact]
        public void ReadFrom_WithRequireCanonicalAndLeadingZeroByte_ShouldFailClosed()
        {
            // Arrange: value 5 re-encoded with a redundant leading 0x00 byte (bit length 16 instead
            // of the canonical 3) - the same value, but an ambiguous/non-unique wire encoding.
            byte[] data = { 0x00, 0x10, 0x00, 0x05 };

            // Act & Assert
            Assert.Throws<FailClosedException>(() => Mpi.ReadFrom(data, 0, requireCanonical: true));
        }

        [Fact]
        public void ReadFrom_WithRequireCanonicalAndZeroValue_ShouldSucceed()
        {
            // Arrange: zero's canonical encoding is bit length 0, zero body bytes.
            byte[] data = { 0x00, 0x00 };

            // Act
            (BigInteger value, int consumed) = Mpi.ReadFrom(data, 0, requireCanonical: true);

            // Assert
            Assert.Equal(BigInteger.Zero, value);
            Assert.Equal(2, consumed);
        }

        [Fact]
        public void ReadFrom_WithHighBitSetInMostSignificantByte_ShouldTreatValueAsUnsignedAndPositive()
        {
            // Arrange: bit length 8, value byte 0x80 (128). A naive little-endian BigInteger read
            // of this single byte would be interpreted as -128 (two's complement) without the
            // unsigned guard byte.
            byte[] data = { 0x00, 0x08, 0x80 };

            // Act
            (BigInteger value, int consumed) = Mpi.ReadFrom(data, 0);

            // Assert
            Assert.Equal(new BigInteger(128), value);
            Assert.True(value > 0);
            Assert.Equal(3, consumed);
        }

        [Fact]
        public void ReadFrom_WithMultiByteHighBitSetValue_ShouldDecodeCorrectly()
        {
            // Arrange: bit length 16, bytes {0xFF, 0x01} -> 0xFF01 = 65281.
            byte[] data = { 0x00, 0x10, 0xFF, 0x01 };

            // Act
            (BigInteger value, int consumed) = Mpi.ReadFrom(data, 0);

            // Assert
            Assert.Equal(new BigInteger(0xFF01), value);
            Assert.Equal(4, consumed);
        }

        [Fact]
        public void ReadFrom_AtNonZeroOffset_ShouldConsumeOnlyItsOwnBytesAndAllowChaining()
        {
            // Arrange: two consecutive MPIs; read the second at offset 3.
            byte[] data = { 0x00, 0x08, 0xAA, 0x00, 0x08, 0xBB };

            // Act
            (BigInteger value, int consumed) = Mpi.ReadFrom(data, 3);

            // Assert
            Assert.Equal(new BigInteger(0xBB), value);
            Assert.Equal(3, consumed);
        }

        [Fact]
        public void ReadFrom_WithTruncatedBody_ShouldFailClosed()
        {
            // Arrange: bit length claims 16 bits (2 bytes) but only 1 byte follows.
            byte[] data = { 0x00, 0x10, 0xFF };

            // Act & Assert
            Assert.Throws<FailClosedException>(() => Mpi.ReadFrom(data, 0));
        }

        [Fact]
        public void ReadFrom_WithTruncatedLengthPrefix_ShouldFailClosed()
        {
            // Arrange: only one byte of the 2-byte length prefix present.
            byte[] data = { 0x00 };

            // Act & Assert
            Assert.Throws<FailClosedException>(() => Mpi.ReadFrom(data, 0));
        }

        [Fact]
        public void ToFixedLengthUnsignedBytes_RoundTripsThroughReadFrom()
        {
            // Arrange
            var original = new BigInteger(0xFF01);

            // Act
            byte[] fixedBytes = Mpi.ToFixedLengthUnsignedBytes(original, 2);
            BigInteger roundTripped = Mpi.ToUnsignedBigInteger(fixedBytes);

            // Assert
            Assert.Equal(new byte[] { 0xFF, 0x01 }, fixedBytes);
            Assert.Equal(original, roundTripped);
        }

        [Fact]
        public void ToFixedLengthUnsignedBytes_WithValueTooLargeForLength_ShouldFailClosed()
        {
            // Arrange
            var tooLarge = new BigInteger(0x10000);

            // Act & Assert
            Assert.Throws<FailClosedException>(() => Mpi.ToFixedLengthUnsignedBytes(tooLarge, 1));
        }
    }
}
