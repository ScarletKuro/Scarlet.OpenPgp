using System.Text;
using Scarlet.OpenPgp.Armor;
using Scarlet.OpenPgp.Internal;

namespace Scarlet.OpenPgp.Tests.Armor
{
    public class PacketInputTests
    {
        private static string Armor(string label, byte[] body) =>
            "-----BEGIN PGP " + label + "-----\n\n" + Convert.ToBase64String(body) + "\n-----END PGP " + label + "-----\n";

        [Fact]
        public void Decode_WithBinaryPackets_ShouldReturnThemUnchanged()
        {
            // Arrange: a packet's first octet always has its high bit set.
            byte[] binary = [0xC2, 0x01, 0xAA];

            // Act
            byte[] result = PacketInput.Decode(binary, "SIGNATURE");

            // Assert
            Assert.Equal(binary, result);
        }

        [Fact]
        public void Decode_WithArmorAfterABomAndPreamble_ShouldDearmor()
        {
            // Arrange
            byte[] body = [0xC2, 0x01, 0xAA];
            byte[] input = new byte[] { 0xEF, 0xBB, 0xBF }.Concat(Encoding.ASCII.GetBytes("Some mail preamble\r\n\r\n" + Armor("SIGNATURE", body))).ToArray();

            // Act
            byte[] result = PacketInput.Decode(input, "SIGNATURE");

            // Assert
            Assert.Equal(body, result);
        }

        [Fact]
        public void Decode_WithSeveralConcatenatedBlocks_ShouldConcatenateTheirPackets()
        {
            // Arrange: e.g. two key files appended into one.
            byte[] first = [0xC6, 0x01, 0x01];
            byte[] second = [0xC6, 0x01, 0x02];
            string input = Armor("PUBLIC KEY BLOCK", first) + "\n" + Armor("PUBLIC KEY BLOCK", second);

            // Act
            byte[] result = PacketInput.Decode(input, "PUBLIC KEY BLOCK");

            // Assert
            Assert.Equal(first.Concat(second).ToArray(), result);
        }

        [Fact]
        public void Decode_WithABlockOfTheWrongLabel_ShouldFailClosed()
        {
            // Arrange
            string input = Armor("PUBLIC KEY BLOCK", [0xC6, 0x01, 0x01]) + Armor("PRIVATE KEY BLOCK", [0xC5, 0x01, 0x01]);

            // Act & Assert
            Assert.Throws<FailClosedException>(() => PacketInput.Decode(input, "PUBLIC KEY BLOCK"));
        }

        [Fact]
        public void Decode_WithArmorThatIsNotValidUtf8_ShouldFailClosed()
        {
            // Arrange
            byte[] input = Encoding.ASCII.GetBytes(Armor("SIGNATURE", [0xC2, 0x01, 0xAA])).Concat(new byte[] { 0xFF, 0xFE }).ToArray();

            // Act & Assert
            Assert.Throws<FailClosedException>(() => PacketInput.Decode(input, "SIGNATURE"));
        }

        [Fact]
        public void Decode_WithEmptyInput_ShouldFailClosed()
        {
            // Act & Assert
            Assert.Throws<FailClosedException>(() => PacketInput.Decode([], "SIGNATURE"));
        }
    }
}
