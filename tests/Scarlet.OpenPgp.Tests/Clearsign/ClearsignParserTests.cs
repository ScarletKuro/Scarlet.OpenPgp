using System;
using System.Text;
using Scarlet.OpenPgp.Armor;
using Scarlet.OpenPgp.Clearsign;
using Scarlet.OpenPgp.Internal;

namespace Scarlet.OpenPgp.Tests.Clearsign
{
    public class ClearsignParserTests
    {
        private static string BuildSignatureArmor(byte[] body)
        {
            int crc = Crc24.Compute(body);
            byte[] crcBytes = { (byte)(crc >> 16), (byte)(crc >> 8), (byte)crc };

            return "-----BEGIN PGP SIGNATURE-----\n"
                   + "Version: Test\n"
                   + "\n"
                   + Convert.ToBase64String(body) + "\n"
                   + "=" + Convert.ToBase64String(crcBytes) + "\n"
                   + "-----END PGP SIGNATURE-----\n";
        }

        [Fact]
        public void Parse_WithWellFormedClearsignMessage_ShouldExtractBodyLinesAndSignatureArmor()
        {
            // Arrange
            byte[] sigBody = Encoding.ASCII.GetBytes("fake-signature-bytes");
            string message = "-----BEGIN PGP SIGNED MESSAGE-----\n"
                              + "Hash: SHA256\n"
                              + "\n"
                              + "line one\n"
                              + "line two\n"
                              + BuildSignatureArmor(sigBody);

            // Act
            ClearsignMessage result = ClearsignParser.Parse(message);

            // Assert
            Assert.Equal(new[] { "line one", "line two" }, result.DashEscapedBodyLines);
            Assert.Equal("SIGNATURE", result.SignatureArmor.Label);
            Assert.Equal(sigBody, result.SignatureArmor.Body);
        }

        [Fact]
        public void Parse_WithNoBeginSignedMessageLine_ShouldFailClosed()
        {
            // Arrange
            string message = "just some text\nwith no clearsign markers\n";

            // Act & Assert
            Assert.Throws<FailClosedException>(() => ClearsignParser.Parse(message));
        }

        [Fact]
        public void Parse_WithNoBeginSignatureLine_ShouldFailClosed()
        {
            // Arrange
            string message = "-----BEGIN PGP SIGNED MESSAGE-----\n\nbody text\n";

            // Act & Assert
            Assert.Throws<FailClosedException>(() => ClearsignParser.Parse(message));
        }

        [Fact]
        public void Parse_WithWrongTrailingArmorLabel_ShouldFailClosed()
        {
            // Arrange: a PUBLIC KEY BLOCK where a SIGNATURE was expected.
            byte[] body = Encoding.ASCII.GetBytes("not a signature");
            int crc = Crc24.Compute(body);
            byte[] crcBytes = { (byte)(crc >> 16), (byte)(crc >> 8), (byte)crc };
            string wrongArmor = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\n"
                                 + Convert.ToBase64String(body) + "\n"
                                 + "=" + Convert.ToBase64String(crcBytes) + "\n"
                                 + "-----END PGP PUBLIC KEY BLOCK-----\n";
            string message = "-----BEGIN PGP SIGNED MESSAGE-----\n\nbody text\n" + wrongArmor;

            // Act & Assert
            Assert.Throws<FailClosedException>(() => ClearsignParser.Parse(message));
        }

        [Fact]
        public void Parse_WithNoHashHeaders_ShouldStillWork()
        {
            // Arrange
            byte[] sigBody = Encoding.ASCII.GetBytes("sig");
            string message = "-----BEGIN PGP SIGNED MESSAGE-----\n"
                              + "\n"
                              + "only line\n"
                              + BuildSignatureArmor(sigBody);

            // Act
            ClearsignMessage result = ClearsignParser.Parse(message);

            // Assert
            Assert.Equal(new[] { "only line" }, result.DashEscapedBodyLines);
        }
    }
}
