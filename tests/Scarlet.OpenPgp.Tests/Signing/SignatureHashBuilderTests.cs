using System.Text;
using Scarlet.OpenPgp.Hashing;
using Scarlet.OpenPgp.Packets;
using Scarlet.OpenPgp.Signing;
using Scarlet.OpenPgp.Tests.Packets;

namespace Scarlet.OpenPgp.Tests.Signing
{
    public class SignatureHashBuilderTests
    {
        // draft-koch-eddsa-for-openpgp-04 Appendix A documents the exact bytes hashed when
        // verifying its worked example (signing the literal text "OpenPGP"), plus the resulting
        // SHA-256 digest - an authoritative, independent-of-this-library ground truth for exactly
        // the byte sequence SPEC.md calls out for its own isolated test.
        private static readonly byte[] ExpectedHashInput =
        [
            // "OpenPGP"
            0x4f, 0x70, 0x65, 0x6e, 0x50, 0x47, 0x50,
            // hashed portion: version, type, pubalg, hashalg, 2-byte hashed-subpacket count, hashed-subpacket data
            0x04, 0x00, 0x16, 0x08, 0x00, 0x06, 0x05, 0x02, 0x55, 0xf9, 0x5f, 0x95,
            // trailer: 0x04, 0xFF, 4-byte big-endian length of the hashed portion (12)
            0x04, 0xff, 0x00, 0x00, 0x00, 0x0c,
        ];

        private static readonly byte[] ExpectedDigest =
        [
            0xf6, 0x22, 0x0a, 0x3f, 0x75, 0x78, 0x14, 0xf4, 0xc2, 0x17, 0x6f, 0xfb, 0xb6, 0x8b, 0x00, 0x24,
            0x9c, 0xd4, 0xcc, 0xdc, 0x05, 0x9c, 0x4b, 0x34, 0xad, 0x87, 0x1f, 0x30, 0xb1, 0x74, 0x02, 0x80,
        ];

        private static SignaturePacket ParseSignatureFixture()
        {
            List<Packet> packets = PacketReader.ReadAll(SignaturePacketTests.Ed25519SignaturePacketBytes);
            return SignaturePacket.Parse(packets[0].Body);
        }

        [Fact]
        public void BuildDataToHash_WithRealEd25519SignatureFromEddsaDraft_ShouldProduceTheDocumentedByteSequence()
        {
            // Arrange
            SignaturePacket signature = ParseSignatureFixture();
            byte[] content = "OpenPGP"u8.ToArray();

            // Act
            byte[] dataToHash = SignatureHashBuilder.BuildDataToHash(content, signature);

            // Assert
            Assert.Equal(ExpectedHashInput, dataToHash);
        }

        [Fact]
        public void BuildDataToHash_WhenHashed_ShouldProduceTheDocumentedDigest()
        {
            // Arrange
            SignaturePacket signature = ParseSignatureFixture();
            byte[] content = "OpenPGP"u8.ToArray();
            byte[] dataToHash = SignatureHashBuilder.BuildDataToHash(content, signature);

            // Act
            byte[] digest = OpenPgpHash.ComputeHash(HashAlgorithmId.Sha256, dataToHash);

            // Assert
            Assert.Equal(ExpectedDigest, digest);
        }

        [Fact]
        public void BuildDataToHash_DigestPrefix_ShouldMatchTheSignaturePacketsLeftHashBytes()
        {
            // Arrange: the signature packet's own 2-byte quick-check field must equal the first
            // two bytes of the real digest - an internal consistency check independent of the
            // draft's own documented values.
            SignaturePacket signature = ParseSignatureFixture();
            byte[] content = "OpenPGP"u8.ToArray();
            byte[] dataToHash = SignatureHashBuilder.BuildDataToHash(content, signature);

            // Act
            byte[] digest = OpenPgpHash.ComputeHash(HashAlgorithmId.Sha256, dataToHash);

            // Assert
            Assert.Equal(signature.LeftHashBytes16, new[] { digest[0], digest[1] });
        }
    }
}
