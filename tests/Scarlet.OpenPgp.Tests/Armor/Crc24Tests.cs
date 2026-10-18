
namespace Scarlet.OpenPgp.Tests.Armor
{
    public class Crc24Tests
    {
        [Fact]
        public void Compute_WithEmptyInput_ShouldReturnTheInitializationValue()
        {
            // Arrange
            byte[] data = [];

            // Act
            int crc = Crc24.Compute(data);

            // Assert
            Assert.Equal(0x00B704CE, crc);
        }

        [Fact]
        public void Compute_WithKnownReferenceString_ShouldMatchThePublishedCrc24Vector()
        {
            // Arrange
            // "123456789" -> 0x21CF02 is the standard published CRC-24/OPENPGP test vector.
            byte[] data = "123456789"u8.ToArray();

            // Act
            int crc = Crc24.Compute(data);

            // Assert
            Assert.Equal(0x0021CF02, crc);
        }
    }
}
