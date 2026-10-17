using System;
using System.Text;
using Scarlet.OpenPgp.Armor;
using Scarlet.OpenPgp.Clearsign;
using Scarlet.OpenPgp.Hashing;
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
            Assert.Empty(result.HashHeaderAlgorithms);
        }

        private static string WellFormedMessage(string headers = "Hash: SHA256\n", string body = "line one\n")
        {
            return "-----BEGIN PGP SIGNED MESSAGE-----\n"
                   + headers
                   + "\n"
                   + body
                   + BuildSignatureArmor(Encoding.ASCII.GetBytes("sig"));
        }

        [Fact]
        public void Parse_WithHashHeaders_ShouldCollectTheNamedAlgorithms()
        {
            // Arrange
            string message = WellFormedMessage(headers: "Hash: SHA256, SHA512\nHash: SHA384\n");

            // Act
            ClearsignMessage result = ClearsignParser.Parse(message);

            // Assert
            Assert.Equal(new[] { HashAlgorithmId.Sha256, HashAlgorithmId.Sha512, HashAlgorithmId.Sha384 }, result.HashHeaderAlgorithms);
        }

        [Fact]
        public void Parse_WithBlankLinesAroundTheMessageAndAByteOrderMark_ShouldStillWork()
        {
            // Arrange
            string message = "﻿\n  \n" + WellFormedMessage() + "\n\t\n";

            // Act
            ClearsignMessage result = ClearsignParser.Parse(message);

            // Assert
            Assert.Equal(new[] { "line one" }, result.DashEscapedBodyLines);
        }

        [Theory]
        [InlineData("unsigned preamble line\n", "")] // text before the BEGIN line
        [InlineData("", "unsigned trailing line\n")] // text after the END line
        public void Parse_WithUnsignedTextOutsideTheMessage_ShouldFailClosed(string before, string after)
        {
            // Arrange: a caller reading the file directly would see this text as if it were signed.
            string message = before + WellFormedMessage() + after;

            // Act & Assert
            Assert.Throws<FailClosedException>(() => ClearsignParser.Parse(message));
        }

        [Theory]
        [InlineData("Comment: deadbeef  bun-linux-x64.zip\n")]
        [InlineData("Hash: SHA256\nInjected: anything\n")]
        [InlineData("hash: SHA256\n")]
        [InlineData("not a header at all\n")]
        public void Parse_WithAnArmorHeaderOtherThanHash_ShouldFailClosed(string headers)
        {
            // Arrange
            string message = WellFormedMessage(headers: headers);

            // Act & Assert
            Assert.Throws<FailClosedException>(() => ClearsignParser.Parse(message));
        }

        [Fact]
        public void Parse_WithAnUnrecognizedHashName_ShouldFailClosed()
        {
            // Arrange
            string message = WellFormedMessage(headers: "Hash: SHA3-256\n");

            // Act & Assert
            Assert.Throws<FailClosedException>(() => ClearsignParser.Parse(message));
        }

        [Theory]
        [InlineData("-not escaped\n")]
        [InlineData("-----BEGIN PGP SIGNED MESSAGE-----\n")]
        public void Parse_WithABodyLineStartingWithAnUnescapedDash_ShouldFailClosed(string body)
        {
            // Arrange
            string message = WellFormedMessage(body: body);

            // Act & Assert
            Assert.Throws<FailClosedException>(() => ClearsignParser.Parse(message));
        }

        [Fact]
        public void Parse_WithABareCarriageReturn_ShouldFailClosed()
        {
            // Arrange
            string message = WellFormedMessage(body: "line one\rline two\n");

            // Act & Assert
            Assert.Throws<FailClosedException>(() => ClearsignParser.Parse(message));
        }

        [Fact]
        public void Parse_WithCrlfLineEndings_ShouldStillWork()
        {
            // Arrange
            string message = WellFormedMessage(body: "line one\nline two\n").Replace("\n", "\r\n");

            // Act
            ClearsignMessage result = ClearsignParser.Parse(message);

            // Assert
            Assert.Equal(new[] { "line one", "line two" }, result.DashEscapedBodyLines);
        }
    }
}
