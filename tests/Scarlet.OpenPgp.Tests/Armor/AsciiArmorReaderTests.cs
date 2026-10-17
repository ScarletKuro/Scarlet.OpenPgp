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
        public void Read_WithMismatchedCrc24_ShouldStillSucceed()
        {
            // Arrange: RFC 9580 §6.1 - an implementation MUST NOT reject armor whose CRC24 is
            // missing, malformed, or wrong. Tampering is the signature check's job.
            byte[] body = Encoding.ASCII.GetBytes("abc");
            string armor = BuildArmor("SIGNATURE", "", body, corruptCrc: true);

            // Act
            AsciiArmorBlock block = AsciiArmorReader.Read(armor);

            // Assert
            Assert.Equal(body, block.Body);
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
        public void Read_WithTrailingGarbageAfterEndLine_ShouldStillSucceed()
        {
            // Arrange: confirmed against real GnuPG 2.4.9, which tolerates arbitrary trailing text
            // after a detached signature's armor block (`gpg --verify` still reports "Good
            // signature"). See AsciiArmorReader.Read's doc comment.
            byte[] body = Encoding.ASCII.GetBytes("abc");
            string armor = BuildArmor("SIGNATURE", "", body) + "unexpected trailing content\n";

            // Act
            AsciiArmorBlock block = AsciiArmorReader.Read(armor);

            // Assert
            Assert.Equal(body, block.Body);
        }

        [Fact]
        public void Read_WithASecondConcatenatedArmorBlockAfterEndLine_ShouldStillSucceedAndUseTheFirstBlock()
        {
            // Arrange: confirmed against real GnuPG 2.4.9, which - for a detached signature -
            // happily checks every Signature packet it finds rather than rejecting the file. This
            // library's single-bool API only reports on the first block found; the second is
            // ignored rather than causing a failure, matching gpg's tolerance rather than gpg's
            // fuller multi-signature reporting.
            byte[] firstBody = Encoding.ASCII.GetBytes("first");
            byte[] secondBody = Encoding.ASCII.GetBytes("second");
            string armor = BuildArmor("SIGNATURE", "", firstBody) + BuildArmor("SIGNATURE", "", secondBody);

            // Act
            AsciiArmorBlock block = AsciiArmorReader.Read(armor);

            // Assert
            Assert.Equal(firstBody, block.Body);
        }

        [Fact]
        public void Read_WithLeadingGarbageBeforeBeginLine_ShouldStillSucceed()
        {
            // Arrange: confirmed against real GnuPG 2.4.9, which tolerates an arbitrary preamble
            // before the armor block (e.g. mail/commentary text) for both detached and clearsigned
            // verification.
            byte[] body = Encoding.ASCII.GetBytes("abc");
            string armor = "some leading preamble text that is not part of the armor\n\n" + BuildArmor("SIGNATURE", "", body);

            // Act
            AsciiArmorBlock block = AsciiArmorReader.Read(armor);

            // Assert
            Assert.Equal(body, block.Body);
        }
    }
}
