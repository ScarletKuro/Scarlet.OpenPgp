using System;
using System.Text;
using Scarlet.OpenPgp.Armor;
using Scarlet.OpenPgp.Internal;

namespace Scarlet.OpenPgp.Tests.Armor
{
    public class AsciiArmorReaderTests
    {
        private static string BuildArmor(string label, string headerLines, byte[] body, bool corruptCrc = false)
        {
            int crc = Crc24.Compute(body);
            if (corruptCrc)
            {
                crc ^= 0xFF;
            }

            byte[] crcBytes = { (byte)(crc >> 16), (byte)(crc >> 8), (byte)crc };

            var sb = new StringBuilder();
            sb.Append("-----BEGIN PGP ").Append(label).Append("-----\n");
            if (headerLines.Length > 0)
            {
                sb.Append(headerLines);
            }
            sb.Append('\n');
            sb.Append(Convert.ToBase64String(body)).Append('\n');
            sb.Append('=').Append(Convert.ToBase64String(crcBytes)).Append('\n');
            sb.Append("-----END PGP ").Append(label).Append("-----\n");
            return sb.ToString();
        }

        [Fact]
        public void Read_WithWellFormedBlock_ShouldDecodeLabelHeadersAndBody()
        {
            // Arrange
            byte[] body = Encoding.ASCII.GetBytes("hello world");
            string armor = BuildArmor("SIGNATURE", "Version: Test\n", body);

            // Act
            AsciiArmorBlock block = AsciiArmorReader.Read(armor);

            // Assert
            Assert.Equal("SIGNATURE", block.Label);
            Assert.Equal("Version", block.Headers[0].Key);
            Assert.Equal("Test", block.Headers[0].Value);
            Assert.Equal(body, block.Body);
        }

        [Fact]
        public void Read_WithNoHeaders_ShouldStillDecodeBody()
        {
            // Arrange
            byte[] body = Encoding.ASCII.GetBytes("abc");
            string armor = BuildArmor("PUBLIC KEY BLOCK", "", body);

            // Act
            AsciiArmorBlock block = AsciiArmorReader.Read(armor);

            // Assert
            Assert.Empty(block.Headers);
            Assert.Equal(body, block.Body);
        }

        [Fact]
        public void Read_WithMissingEndLine_ShouldFailClosed()
        {
            // Arrange
            byte[] body = Encoding.ASCII.GetBytes("abc");
            string armor = BuildArmor("SIGNATURE", "", body).Replace("-----END PGP SIGNATURE-----\n", "");

            // Act & Assert
            Assert.Throws<FailClosedException>(() => AsciiArmorReader.Read(armor));
        }

        [Fact]
        public void Read_WithMismatchedCrc24_ShouldFailClosed()
        {
            // Arrange
            byte[] body = Encoding.ASCII.GetBytes("abc");
            string armor = BuildArmor("SIGNATURE", "", body, corruptCrc: true);

            // Act & Assert
            Assert.Throws<FailClosedException>(() => AsciiArmorReader.Read(armor));
        }

        [Fact]
        public void Read_WithMalformedBase64Body_ShouldFailClosed()
        {
            // Arrange
            string armor = "-----BEGIN PGP SIGNATURE-----\n\n!!!not-base64!!!\n=AAAA\n-----END PGP SIGNATURE-----\n";

            // Act & Assert
            Assert.Throws<FailClosedException>(() => AsciiArmorReader.Read(armor));
        }

        [Fact]
        public void Read_WithMismatchedBeginEndLabels_ShouldFailClosed()
        {
            // Arrange
            byte[] body = Encoding.ASCII.GetBytes("abc");
            string armor = BuildArmor("SIGNATURE", "", body).Replace(
                "-----END PGP SIGNATURE-----", "-----END PGP PUBLIC KEY BLOCK-----");

            // Act & Assert
            Assert.Throws<FailClosedException>(() => AsciiArmorReader.Read(armor));
        }

        [Fact]
        public void Read_WithNoBeginLine_ShouldFailClosed()
        {
            // Arrange
            string armor = "just some text\nwith no armor at all\n";

            // Act & Assert
            Assert.Throws<FailClosedException>(() => AsciiArmorReader.Read(armor));
        }

        [Fact]
        public void Read_WithTrailingGarbageAfterEndLine_ShouldFailClosed()
        {
            // Arrange
            byte[] body = Encoding.ASCII.GetBytes("abc");
            string armor = BuildArmor("SIGNATURE", "", body) + "unexpected trailing content\n";

            // Act & Assert
            Assert.Throws<FailClosedException>(() => AsciiArmorReader.Read(armor));
        }

        [Fact]
        public void Read_WithASecondConcatenatedArmorBlockAfterEndLine_ShouldFailClosed()
        {
            // Arrange: the caller is expected to supply exactly one armor block - a second,
            // otherwise-valid block appended after the first must not be silently ignored.
            byte[] body = Encoding.ASCII.GetBytes("abc");
            string armor = BuildArmor("SIGNATURE", "", body) + BuildArmor("SIGNATURE", "", body);

            // Act & Assert
            Assert.Throws<FailClosedException>(() => AsciiArmorReader.Read(armor));
        }

        [Fact]
        public void Read_WithTrailingBlankAndWhitespaceOnlyLinesAfterEndLine_ShouldStillSucceed()
        {
            // Arrange: ordinary trailing newline(s)/whitespace after the END line - a completely
            // normal way for a real file to end - must still be tolerated.
            byte[] body = Encoding.ASCII.GetBytes("abc");
            string armor = BuildArmor("SIGNATURE", "", body) + "\n   \n";

            // Act
            AsciiArmorBlock block = AsciiArmorReader.Read(armor);

            // Assert
            Assert.Equal(body, block.Body);
        }
    }
}
