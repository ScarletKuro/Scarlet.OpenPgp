using Scarlet.OpenPgp.Internal;
using Scarlet.OpenPgp.Packets;

namespace Scarlet.OpenPgp.Tests.Packets
{
    public class SubpacketReaderTests
    {
        [Fact]
        public void ReadAll_WithOneByteLength_ShouldParseTypeAndData()
        {
            // Arrange: length=5 (type + 4 data bytes), type=2 (SignatureCreationTime), data=4 bytes.
            byte[] data = [0x05, 0x02, 0xAA, 0xBB, 0xCC, 0xDD];

            // Act
            List<SignatureSubpacket> subpackets = SubpacketReader.ReadAll(data);

            // Assert
            Assert.Single(subpackets);
            Assert.Equal(2, subpackets[0].RawType);
            Assert.False(subpackets[0].Critical);
            Assert.Equal([0xAA, 0xBB, 0xCC, 0xDD], subpackets[0].Data);
        }

        [Fact]
        public void ReadAll_WithCriticalBitSet_ShouldReportCritical()
        {
            // Arrange: type byte 0x90 = 0x80 (critical) | 0x10 (raw type 16).
            byte[] data = [0x02, 0x90, 0xAA];

            // Act
            List<SignatureSubpacket> subpackets = SubpacketReader.ReadAll(data);

            // Assert
            Assert.True(subpackets[0].Critical);
            Assert.Equal(16, subpackets[0].RawType);
        }

        [Fact]
        public void ReadAll_WithTwoByteLength_ShouldParseCorrectly()
        {
            // Arrange: first=192, second=1 -> length = ((192-192)<<8)+1+192 = 193 (type + 192 data bytes).
            var data = new List<byte> { 192, 1, 0x02 };
            for (int i = 0; i < 192; i++)
            {
                data.Add((byte)i);
            }

            // Act
            List<SignatureSubpacket> subpackets = SubpacketReader.ReadAll(data.ToArray());

            // Assert
            Assert.Single(subpackets);
            Assert.Equal(192, subpackets[0].Data.Length);
        }

        [Fact]
        public void ReadAll_WithOversizedFiveByteLengthCausingIntOverflow_ShouldFailClosedNotThrowUnhandled()
        {
            // Arrange: 5-octet length marker (255) followed by 0x7FFFFFFF. Naively checking
            // "position + length > data.Length" in 32-bit int arithmetic overflows (position=5
            // plus 0x7FFFFFFF wraps negative), which would previously bypass the truncation check
            // and crash inside Array.Copy/array allocation instead of failing closed.
            byte[] data = [255, 0x7F, 0xFF, 0xFF, 0xFF];

            // Act & Assert
            Assert.Throws<FailClosedException>(() => SubpacketReader.ReadAll(data));
        }

        [Fact]
        public void ReadAll_WithLengthExceedingRemainingData_ShouldFailClosed()
        {
            // Arrange: length=10 but only 2 bytes follow.
            byte[] data = [10, 0x02, 0xAA];

            // Act & Assert
            Assert.Throws<FailClosedException>(() => SubpacketReader.ReadAll(data));
        }

        [Fact]
        public void ReadAll_WithTruncatedLength_ShouldFailClosed()
        {
            // Arrange: a 2-octet length marker (>=192, <255) with no second byte.
            byte[] data = [200];

            // Act & Assert
            Assert.Throws<FailClosedException>(() => SubpacketReader.ReadAll(data));
        }

        [Fact]
        public void ReadAll_WithLengthOfZero_ShouldFailClosed()
        {
            // Arrange: a subpacket must include at least its own type octet.
            byte[] data = [0x00];

            // Act & Assert
            Assert.Throws<FailClosedException>(() => SubpacketReader.ReadAll(data));
        }
    }
}
