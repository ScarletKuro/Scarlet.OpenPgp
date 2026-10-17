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
        public void TryGetHashedTime_WithRealEd25519Signature_ShouldReadTheHashedCreationTime()
        {
            // Act
            SignaturePacket signature = ParseFixture();
            bool found = signature.TryGetHashedTime(SignatureSubpacketType.SignatureCreationTime, out uint seconds);

            // Assert: hashed subpacket 05 02 55 f9 5f 95.
            Assert.True(found);
            Assert.Equal(0x55f95f95u, seconds);
            Assert.False(signature.TryGetHashedTime(SignatureSubpacketType.SignatureExpirationTime, out _));
        }

        [Fact]
        public void TryGetHashedTime_WithDuplicateHashedSubpacket_ShouldFailClosed()
        {
            // Arrange: v4, binary, EdDSA, SHA-256, hashed area holding two creation-time subpackets,
            // empty unhashed area, left-16 bits, then r and s as 1-bit MPIs.
            byte[] body =
            {
                0x04, 0x00, 0x16, 0x08,
                0x00, 0x0C, 0x05, 0x02, 0x00, 0x00, 0x00, 0x01, 0x05, 0x02, 0x00, 0x00, 0x00, 0x02,
                0x00, 0x00,
                0x00, 0x00,
                0x00, 0x01, 0x01, 0x00, 0x01, 0x01,
            };
            SignaturePacket signature = SignaturePacket.Parse(body);

            // Act & Assert
            Assert.Throws<FailClosedException>(() => signature.TryGetHashedTime(SignatureSubpacketType.SignatureCreationTime, out _));
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
        public void Parse_WithCriticalSignatureCreationTimeOfWrongLength_ShouldFailClosed()
        {
            // Arrange: critical SignatureCreationTime (type 2) with 3 data bytes instead of the
            // required 4 - "critical" means understood, and a malformed payload for a recognized
            // type is exactly as unusable as an unknown type would be.
            byte[] body =
            {
                0x04, 0x00, 0x01, 0x08, 0x00, 0x05, 0x04, 0x82, 0xAA, 0xBB, 0xCC,
            };

            // Act & Assert
            Assert.Throws<FailClosedException>(() => SignaturePacket.Parse(body));
        }

        [Fact]
        public void Parse_WithCriticalIssuerKeyIdOfWrongLength_ShouldFailClosed()
        {
            // Arrange: critical IssuerKeyId (type 16) with 7 data bytes instead of the required 8.
            byte[] body =
            {
                0x04, 0x00, 0x01, 0x08, 0x00, 0x09, 0x08, 0x90, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            };

            // Act & Assert
            Assert.Throws<FailClosedException>(() => SignaturePacket.Parse(body));
        }

        [Fact]
        public void Parse_WithCriticalIssuerFingerprintOfWrongVersion_ShouldFailClosed()
        {
            // Arrange: critical IssuerFingerprint (type 33), 21 bytes total, but version byte 5
            // instead of 4 (this library only supports v4 signatures/keys).
            byte[] body =
            {
                0x04, 0x00, 0x01, 0x08, 0x00, 0x17, 0x16, 0xA1, 0x05,
                0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
                0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
            };

            // Act & Assert
            Assert.Throws<FailClosedException>(() => SignaturePacket.Parse(body));
        }

        [Fact]
        public void Parse_WithCriticalIssuerFingerprintOfWrongLength_ShouldFailClosed()
        {
            // Arrange: critical IssuerFingerprint (type 33) with 20 data bytes (missing the version
            // octet) instead of the required 21.
            byte[] body =
            {
                0x04, 0x00, 0x01, 0x08, 0x00, 0x16, 0x15, 0xA1,
                0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
                0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
            };

            // Act & Assert
            Assert.Throws<FailClosedException>(() => SignaturePacket.Parse(body));
        }

        [Fact]
        public void Parse_WithNonCriticalSignatureCreationTimeOfWrongLength_ShouldStillSucceed()
        {
            // Arrange: same malformed 3-byte SignatureCreationTime payload as above, but with the
            // critical bit clear (type byte 0x02, not 0x82) - non-critical malformed data in a
            // known type must still be tolerated, matching RFC 4880's "safe to ignore" rule.
            byte[] body =
            {
                0x04, 0x00, 0x01, 0x08, 0x00, 0x05, 0x04, 0x02, 0xAA, 0xBB, 0xCC,
                0x00, 0x00,
                0x00, 0x00,
                0x00, 0x08, 0x80,
            };

            // Act
            SignaturePacket signature = SignaturePacket.Parse(body);

            // Assert
            Assert.Equal(PublicKeyAlgorithm.RsaEncryptOrSign, signature.PublicKeyAlgorithm);
        }

        [Fact]
        public void Parse_WithEdDsaRValueEncodedAs31BytesDueToALeadingZeroByte_ShouldReconstructA32ByteValue()
        {
            // Arrange: a compliant encoder is free to minimize R/S's MPI when the true 32-byte value
            // has a leading 0x00 byte, producing a 31-byte wire encoding. Reconstructing r32/s32
            // using the *wire* byte count instead of a fixed 32 would spuriously reject this
            // otherwise-valid signature (this is exactly what an intermittent BouncyCastle
            // cross-validation test failure caught - random keys occasionally hit this case).
            var body = new List<byte> { 0x04, 0x00, 0x16, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

            // R: bit length 248 (31 bytes), value = 31 bytes of 0xAA - the true 32-byte R is
            // 0x00 followed by those 31 bytes.
            body.Add(0x00);
            body.Add(0xF8);
            for (int i = 0; i < 31; i++)
            {
                body.Add(0xAA);
            }

            // S: a full, unambiguous 32-byte value.
            body.Add(0x01);
            body.Add(0x00);
            for (int i = 0; i < 32; i++)
            {
                body.Add(0xBB);
            }

            // Act
            SignaturePacket signature = SignaturePacket.Parse(body.ToArray());

            // Assert
            Assert.NotNull(signature.EdDsaSignatureValue);
            var expectedR = new byte[32];
            for (int i = 1; i < 32; i++)
            {
                expectedR[i] = 0xAA;
            }

            var expectedS = new byte[32];
            for (int i = 0; i < 32; i++)
            {
                expectedS[i] = 0xBB;
            }

            var expected = new byte[64];
            System.Array.Copy(expectedR, 0, expected, 0, 32);
            System.Array.Copy(expectedS, 0, expected, 32, 32);
            Assert.Equal(expected, signature.EdDsaSignatureValue);
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

        [Fact]
        public void Parse_WithTrailingGarbageAfterSignatureValue_ShouldFailClosed()
        {
            // Arrange: a real, valid signature body with one extra byte appended after S.
            List<Packet> packets = PacketReader.ReadAll(Ed25519SignaturePacketBytes);
            byte[] body = packets[0].Body;
            var withGarbage = new byte[body.Length + 1];
            System.Array.Copy(body, withGarbage, body.Length);
            withGarbage[body.Length] = 0xAA;

            // Act & Assert
            Assert.Throws<FailClosedException>(() => SignaturePacket.Parse(withGarbage));
        }

        [Fact]
        public void Parse_WithNonCanonicalRsaSignatureValueMpi_ShouldFailClosed()
        {
            // Arrange: a minimal v4 RSA signature body whose signature-value MPI re-encodes the
            // value 5 with a redundant leading zero byte (declared bit length 16 instead of the
            // canonical 3) - an attacker could otherwise re-encode any real RSA signature value in
            // more than one way and have it still verify.
            byte[] body =
            {
                0x04, 0x00, 0x01, 0x08, 0x00, 0x00, 0x00, 0x00, 0xAA, 0xBB, 0x00, 0x10, 0x00, 0x05,
            };

            // Act & Assert
            Assert.Throws<FailClosedException>(() => SignaturePacket.Parse(body));
        }

        /// <summary>A v4 binary EdDSA/SHA-256 signature body with the given hashed subpacket area.</summary>
        private static byte[] V4Body(params byte[] hashedSubpackets)
        {
            var body = new List<byte> { 0x04, 0x00, 0x16, 0x08, (byte)(hashedSubpackets.Length >> 8), (byte)hashedSubpackets.Length };
            body.AddRange(hashedSubpackets);
            body.AddRange(new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01 });
            return body.ToArray();
        }

        [Fact]
        public void Parse_WithCriticalNotationData_ShouldFailClosed()
        {
            // Arrange: critical subpacket 20 (0x80 | 20) - a notation the verifier would have to
            // understand to know what the signature means.
            byte[] body = V4Body(0x05, 0x02, 0x00, 0x00, 0x00, 0x01, 0x09, 0x80 | 20, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00);

            // Act & Assert
            Assert.Throws<FailClosedException>(() => SignaturePacket.Parse(body));
        }

        [Fact]
        public void Parse_WithCriticalKeyFlagsAndKeyExpiration_ShouldSucceed()
        {
            // Arrange: RFC 9580 says both SHOULD be marked critical; they must not be mistaken for
            // unknown critical subpackets.
            byte[] body = V4Body(0x05, 0x02, 0x00, 0x00, 0x00, 0x01, 0x02, 0x80 | 27, 0x03, 0x05, 0x80 | 9, 0x00, 0x00, 0x0E, 0x10);

            // Act
            SignaturePacket signature = SignaturePacket.Parse(body);

            // Assert
            Assert.Equal(new byte[] { 0x03 }, signature.KeyFlags);
            Assert.True(signature.TryGetHashedTime(SignatureSubpacketType.KeyExpirationTime, out uint lifetime));
            Assert.Equal(3600u, lifetime);
        }

        [Fact]
        public void Parse_WithAnIssuerFingerprintOfTheWrongVersion_ShouldFailClosedEvenWhenNotCritical()
        {
            // Arrange: a v4 signature naming a v6 fingerprint (RFC 9580 §5.2.3.35: malformed).
            var subpacket = new List<byte> { 34, 33, 6 };
            subpacket.AddRange(new byte[32]);
            byte[] body = V4Body(subpacket.ToArray());

            // Act & Assert
            Assert.Throws<FailClosedException>(() => SignaturePacket.Parse(body));
        }

        [Fact]
        public void Parse_WithTheRfc9580V6CleartextSignature_ShouldReadTheSaltAndNativeEd25519Value()
        {
            // Arrange: the Signature packet of RFC 9580 Appendix A.6.
            string armor = System.IO.File.ReadAllText("TestAssets/rfc9580/a6-cleartext-signed.asc");
            string signatureArmor = armor.Substring(armor.IndexOf("-----BEGIN PGP SIGNATURE-----", System.StringComparison.Ordinal));
            byte[] packetBytes = Scarlet.OpenPgp.Armor.AsciiArmorReader.Read(signatureArmor).Body;

            // Act
            SignaturePacket signature = SignaturePacket.Parse(PacketReader.ReadAll(packetBytes)[0].Body);

            // Assert
            Assert.Equal(6, signature.Version);
            Assert.Equal(PublicKeyAlgorithm.Ed25519, signature.PublicKeyAlgorithm);
            Assert.Equal(HashAlgorithmId.Sha512, signature.HashAlgorithm);
            Assert.Equal("76495F50218890F7F5E2EE3C1822514F70500F551D86E5C921E404E34A53FBAC", System.Convert.ToHexString(signature.Salt));
            Assert.Equal(64, signature.EdDsaSignatureValue!.Length);
            Assert.Equal(new byte[] { 0x69, 0x36 }, signature.LeftHashBytes16);
        }

        [Fact]
        public void Parse_WithAV6SignatureWhoseSaltSizeDoesNotMatchItsHash_ShouldFailClosed()
        {
            // Arrange: v6, SHA2-512 (needs a 32-octet salt) but declaring a 16-octet one.
            var body = new List<byte> { 0x06, 0x00, 27, 10, 0, 0, 0, 0, 0, 0, 0, 0, 0x00, 0x00, 16 };
            body.AddRange(new byte[16 + 64]);

            // Act & Assert
            Assert.Throws<FailClosedException>(() => SignaturePacket.Parse(body.ToArray()));
        }

        [Fact]
        public void Parse_WithAV6EdDsaLegacySignature_ShouldFailClosed()
        {
            // Arrange: EdDSALegacy (22) is forbidden in v6 signatures (RFC 9580 §5.2.3.3).
            var body = new List<byte> { 0x06, 0x00, 22, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0x00, 0x00, 16 };
            body.AddRange(new byte[16]);
            body.AddRange(new byte[] { 0x00, 0x01, 0x01, 0x00, 0x01, 0x01 });

            // Act & Assert
            Assert.Throws<FailClosedException>(() => SignaturePacket.Parse(body.ToArray()));
        }
    }
}
