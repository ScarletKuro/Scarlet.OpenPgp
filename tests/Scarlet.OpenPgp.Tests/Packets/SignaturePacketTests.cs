using System.Collections.Generic;
using Scarlet.OpenPgp.Hashing;
using Scarlet.OpenPgp.Internal;
using Scarlet.OpenPgp.Packets;

namespace Scarlet.OpenPgp.Tests.Packets
{
    public class SignaturePacketTests
    {
        // The matching signature packet from draft-koch-eddsa-for-openpgp-04 Appendix A: signs the
        // literal text "OpenPGP" with the key from PublicKeyPacketTests.
        internal static readonly byte[] Ed25519SignaturePacketBytes =
        {
            0x88, 0x5e, 0x04, 0x00, 0x16, 0x08, 0x00, 0x06, 0x05, 0x02, 0x55, 0xf9, 0x5f, 0x95, 0x00, 0x0a,
            0x09, 0x10, 0x8c, 0xfd, 0xe1, 0x21, 0x97, 0x96, 0x5a, 0x9a, 0xf6, 0x22, 0x01, 0x00, 0x56, 0xf9,
            0x0c, 0xca, 0x98, 0xe2, 0x10, 0x26, 0x37, 0xbd, 0x98, 0x3f, 0xdb, 0x16, 0xc1, 0x31, 0xdf, 0xd2,
            0x7e, 0xd8, 0x2b, 0xf4, 0xdd, 0xe5, 0x60, 0x6e, 0x0d, 0x75, 0x6a, 0xed, 0x33, 0x66, 0x01, 0x00,
            0xd0, 0x9c, 0x4f, 0xa1, 0x15, 0x27, 0xf0, 0x38, 0xe0, 0xf5, 0x7f, 0x22, 0x01, 0xd8, 0x2f, 0x2e,
            0xa2, 0xc9, 0x03, 0x32, 0x65, 0xfa, 0x6c, 0xeb, 0x48, 0x9e, 0x85, 0x4b, 0xae, 0x61, 0xb4, 0x04,
        };

        internal static readonly byte[] ExpectedIssuerKeyId = { 0x8c, 0xfd, 0xe1, 0x21, 0x97, 0x96, 0x5a, 0x9a };

        internal static readonly byte[] ExpectedR =
        {
            0x56, 0xf9, 0x0c, 0xca, 0x98, 0xe2, 0x10, 0x26, 0x37, 0xbd, 0x98, 0x3f, 0xdb, 0x16, 0xc1, 0x31,
            0xdf, 0xd2, 0x7e, 0xd8, 0x2b, 0xf4, 0xdd, 0xe5, 0x60, 0x6e, 0x0d, 0x75, 0x6a, 0xed, 0x33, 0x66,
        };

        internal static readonly byte[] ExpectedS =
        {
            0xd0, 0x9c, 0x4f, 0xa1, 0x15, 0x27, 0xf0, 0x38, 0xe0, 0xf5, 0x7f, 0x22, 0x01, 0xd8, 0x2f, 0x2e,
            0xa2, 0xc9, 0x03, 0x32, 0x65, 0xfa, 0x6c, 0xeb, 0x48, 0x9e, 0x85, 0x4b, 0xae, 0x61, 0xb4, 0x04,
        };

        private static SignaturePacket ParseFixture()
        {
            List<Packet> packets = PacketReader.ReadAll(Ed25519SignaturePacketBytes);
            return SignaturePacket.Parse(packets[0].Body);
        }

        [Fact]
        public void Parse_WithRealEd25519SignatureFromEddsaDraft_ShouldExtractHeaderFields()
        {
            // Act
            SignaturePacket signature = ParseFixture();

            // Assert
            Assert.True(signature.IsBinaryDocument);
            Assert.Equal(PublicKeyAlgorithm.EdDsaLegacy, signature.PublicKeyAlgorithm);
            Assert.Equal(HashAlgorithmId.Sha256, signature.HashAlgorithm);
        }

        [Fact]
        public void Parse_WithRealEd25519Signature_ShouldExtractIssuerKeyIdFromUnhashedArea()
        {
            // Act
            SignaturePacket signature = ParseFixture();

            // Assert
            Assert.Equal(ExpectedIssuerKeyId, signature.IssuerKeyId);
        }

        [Fact]
        public void Parse_WithRealEd25519Signature_ShouldExtractLeftHashBytes()
        {
            // Act
            SignaturePacket signature = ParseFixture();

            // Assert: documented SHA-256 digest starts with f6 22.
            Assert.Equal(new byte[] { 0xf6, 0x22 }, signature.LeftHashBytes16);
        }

        [Fact]
        public void Parse_WithRealEd25519Signature_ShouldReconstructRAndSAsA64ByteSignature()
        {
            // Act
            SignaturePacket signature = ParseFixture();

            // Assert
            Assert.NotNull(signature.EdDsaSignatureValue);
            var expected = new byte[64];
            System.Array.Copy(ExpectedR, 0, expected, 0, 32);
            System.Array.Copy(ExpectedS, 0, expected, 32, 32);
            Assert.Equal(expected, signature.EdDsaSignatureValue);
        }

        [Fact]
        public void Parse_WithHashedSubpacketData_ShouldPreserveItVerbatimForHashBuilding()
        {
            // Act
            SignaturePacket signature = ParseFixture();

            // Assert: version(04) type(00) pubalg(16) hashalg(08) hashed-subpacket-count(0006)
            // hashed-subpacket-data(05 02 55 f9 5f 95) - the exact 12-byte "hashed data" region
            // documented in the draft's own hash-input worked example.
            Assert.Equal(new byte[] { 0x05, 0x02, 0x55, 0xf9, 0x5f, 0x95 }, signature.HashedSubpacketData);
        }

        [Fact]
        public void Parse_WithUnknownCriticalHashedSubpacket_ShouldFailClosed()
        {
            // Arrange: flip the critical bit (0x80) on the SignatureCreationTime subpacket's type
            // byte, but also change its type to an unrecognized value so it can't be safely ignored.
            byte[] packetBytes = (byte[])Ed25519SignaturePacketBytes.Clone();
            packetBytes[9] = 0xFF; // index 9 = the subpacket type byte (was 0x02) inside hashed data
            List<Packet> packets = PacketReader.ReadAll(packetBytes);

            // Act & Assert
            Assert.Throws<FailClosedException>(() => SignaturePacket.Parse(packets[0].Body));
        }

        [Fact]
        public void Parse_WithUnknownNonCriticalHashedSubpacket_ShouldStillSucceed()
        {
            // Arrange: an unrecognized subpacket type (0x7F) with the critical bit clear must be
            // safely skippable - it must NOT cause a parse failure ("must not over-fail").
            byte[] packetBytes = (byte[])Ed25519SignaturePacketBytes.Clone();
            packetBytes[9] = 0x7F; // index 9 = the subpacket type byte (was 0x02), critical bit clear
            List<Packet> packets = PacketReader.ReadAll(packetBytes);

            // Act
            SignaturePacket signature = SignaturePacket.Parse(packets[0].Body);

            // Assert
            Assert.Equal(PublicKeyAlgorithm.EdDsaLegacy, signature.PublicKeyAlgorithm);
        }

        [Fact]
        public void Parse_WithNonV4Version_ShouldFailClosed()
        {
            // Arrange
            byte[] packetBytes = (byte[])Ed25519SignaturePacketBytes.Clone();
            packetBytes[2] = 3; // offset 2 in full packet = offset 0 in body = version byte
            List<Packet> packets = PacketReader.ReadAll(packetBytes);

            // Act & Assert
            Assert.Throws<FailClosedException>(() => SignaturePacket.Parse(packets[0].Body));
        }

        [Fact]
        public void Parse_WithTruncatedBody_ShouldFailClosed()
        {
            // Arrange
            byte[] body = { 0x04, 0x00, 0x16, 0x08 };

            // Act & Assert
            Assert.Throws<FailClosedException>(() => SignaturePacket.Parse(body));
        }
    }
}
