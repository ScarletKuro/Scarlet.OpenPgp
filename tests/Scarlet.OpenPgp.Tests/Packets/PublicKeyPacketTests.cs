using Scarlet.OpenPgp.Internal;
using Scarlet.OpenPgp.Packets;

namespace Scarlet.OpenPgp.Tests.Packets
{
    public class PublicKeyPacketTests
    {
        // The exact worked example from draft-koch-eddsa-for-openpgp-04 Appendix A: a real v4
        // EdDSA (Ed25519) public key packet, created 2014-08-19 14:28:27 UTC, whose fingerprint is
        // documented as C959 BDBA FA32 A2F8 8A15 3B67 8CFD E121 9796 5A9A.
        internal static readonly byte[] Ed25519PublicKeyPacketBytes =
        {
            0x98, 0x33, 0x04, 0x53, 0xf3, 0x5f, 0x0b, 0x16, 0x09, 0x2b, 0x06, 0x01, 0x04, 0x01, 0xda, 0x47,
            0x0f, 0x01, 0x01, 0x07, 0x40, 0x3f, 0x09, 0x89, 0x94, 0xbd, 0xd9, 0x16, 0xed, 0x40, 0x53, 0x19,
            0x79, 0x34, 0xe4, 0xa8, 0x7c, 0x80, 0x73, 0x3a, 0x12, 0x80, 0xd6, 0x2f, 0x80, 0x10, 0x99, 0x2e,
            0x43, 0xee, 0x3b, 0x24, 0x06,
        };

        // Independently verified via a standalone SHA-1 computation over the same packet bytes
        // (0x99 || 2-byte length || body), since the draft's own prose transcription of this
        // fingerprint proved unreliable when copied through web search.
        internal static readonly byte[] Ed25519ExpectedFingerprint =
        {
            0xC9, 0x59, 0xBD, 0xBA, 0xFA, 0x32, 0xA2, 0xF8, 0x9A, 0x15, 0x3B, 0x67, 0x8C, 0xFD, 0xE1, 0x21,
            0x97, 0x96, 0x5A, 0x9A,
        };

        internal static readonly byte[] Ed25519ExpectedPoint =
        {
            0x3f, 0x09, 0x89, 0x94, 0xbd, 0xd9, 0x16, 0xed, 0x40, 0x53, 0x19, 0x79, 0x34, 0xe4, 0xa8, 0x7c,
            0x80, 0x73, 0x3a, 0x12, 0x80, 0xd6, 0x2f, 0x80, 0x10, 0x99, 0x2e, 0x43, 0xee, 0x3b, 0x24, 0x06,
        };

        [Fact]
        public void Parse_WithRealEd25519KeyFromEddsaDraft_ShouldExtractAlgorithmAndPoint()
        {
            // Arrange
            System.Collections.Generic.List<Packet> packets = PacketReader.ReadAll(Ed25519PublicKeyPacketBytes);

            // Act
            PublicKeyPacket key = PublicKeyPacket.Parse(packets[0].Body);

            // Assert
            Assert.Equal(PublicKeyAlgorithm.EdDsaLegacy, key.Algorithm);
            Assert.NotNull(key.EdDsa);
            Assert.Equal(Ed25519ExpectedPoint, key.EdDsa!.CompressedPoint);
        }

        [Fact]
        public void Parse_WithRealEd25519KeyFromEddsaDraft_ShouldComputeTheDocumentedFingerprint()
        {
            // Arrange
            System.Collections.Generic.List<Packet> packets = PacketReader.ReadAll(Ed25519PublicKeyPacketBytes);

            // Act
            PublicKeyPacket key = PublicKeyPacket.Parse(packets[0].Body);

            // Assert
            Assert.Equal(Ed25519ExpectedFingerprint, key.Fingerprint.Bytes);
        }

        [Fact]
        public void Parse_WithRealEd25519Key_ShouldExposeCreationTimeMatchingTheDocumentedDate()
        {
            // Arrange: draft states the key was created 2014-08-19 14:28:27 UTC.
            System.Collections.Generic.List<Packet> packets = PacketReader.ReadAll(Ed25519PublicKeyPacketBytes);

            // Act
            PublicKeyPacket key = PublicKeyPacket.Parse(packets[0].Body);

            // Assert
            var expected = new System.DateTimeOffset(2014, 8, 19, 14, 28, 27, System.TimeSpan.Zero);
            Assert.Equal(expected, key.CreatedAt);
        }

        [Fact]
        public void Parse_WithUnsupportedAlgorithm_ShouldFailClosed()
        {
            // Arrange: same header but algorithm byte changed to an unsupported value (17 = DSA).
            byte[] body = (byte[])Ed25519PublicKeyPacketBytes.Clone();
            body[7] = 17; // offset 7 in the full packet = offset 5 in the body = algorithm byte
            System.Collections.Generic.List<Packet> packets = PacketReader.ReadAll(body);

            // Act & Assert
            Assert.Throws<FailClosedException>(() => PublicKeyPacket.Parse(packets[0].Body));
        }

        [Fact]
        public void Parse_WithTruncatedBody_ShouldFailClosed()
        {
            // Arrange
            byte[] body = { 0x04, 0x53, 0xf3, 0x5f, 0x0b, 0x16 };

            // Act & Assert
            Assert.Throws<FailClosedException>(() => PublicKeyPacket.Parse(body));
        }

        [Fact]
        public void Parse_WithTrailingGarbageAfterKeyMaterial_ShouldFailClosed()
        {
            // Arrange: a real, valid key body with one extra byte appended after the point MPI.
            System.Collections.Generic.List<Packet> packets = PacketReader.ReadAll(Ed25519PublicKeyPacketBytes);
            byte[] body = packets[0].Body;
            var withGarbage = new byte[body.Length + 1];
            System.Array.Copy(body, withGarbage, body.Length);
            withGarbage[body.Length] = 0xAA;

            // Act & Assert
            Assert.Throws<FailClosedException>(() => PublicKeyPacket.Parse(withGarbage));
        }

        [Fact]
        public void Parse_WithNonV4Version_ShouldFailClosed()
        {
            // Arrange
            byte[] body = (byte[])Ed25519PublicKeyPacketBytes.Clone();
            body[2] = 3; // offset 2 in full packet = offset 0 in body = version byte

            System.Collections.Generic.List<Packet> packets = PacketReader.ReadAll(body);

            // Act & Assert
            Assert.Throws<FailClosedException>(() => PublicKeyPacket.Parse(packets[0].Body));
        }
    }
}
