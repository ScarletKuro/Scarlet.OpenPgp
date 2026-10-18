using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Bcpg.OpenPgp;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Scarlet.OpenPgp.Packets;
using Packet = Scarlet.OpenPgp.Packets.Packet;
using PacketTag = Scarlet.OpenPgp.Packets.PacketTag;
using SignaturePacket = Scarlet.OpenPgp.Packets.SignaturePacket;
using PacketHeader = Scarlet.OpenPgp.Packets.PacketHeader;

namespace Scarlet.OpenPgp.Tests.Verification
{
    /// <summary>
    /// A signature's unhashed subpacket area isn't covered by the signature, so anyone handling a
    /// certificate can change it without a private key (RFC 9580 §13.13). Nothing there may change a
    /// verdict - in particular it must not make a revocation or an expiring self-signature vanish.
    /// Regression: adding the two bytes 01 FF (an unknown "critical" subpacket) to a revocation's
    /// unhashed area turned KeyRevoked into Valid.
    /// </summary>
    public class UnhashedAreaTests
    {
        private const string Assets = "TestAssets/gnupg-generated/";

        private static readonly DateTimeOffset Now = new DateTimeOffset(2026, 10, 17, 0, 0, 0, TimeSpan.Zero);

        /// <summary>Unsigned additions an attacker could make: an unknown critical subpacket, and an issuer fingerprint of the wrong version.</summary>
        public static TheoryData<string> UnsignedAdditions => new TheoryData<string>
        {
            "01FF",
            "16 21 06 0000000000000000000000000000000000000000".Replace(" ", string.Empty, StringComparison.Ordinal),
        };

        private static byte[] Frame(Packet packet) =>
            [(byte)(0xC0 | (byte)packet.Header.Tag), 0xFF, (byte)(packet.Body.Length >> 24), (byte)(packet.Body.Length >> 16), (byte)(packet.Body.Length >> 8), (byte)packet.Body.Length, .. packet.Body];

        /// <summary>Appends <paramref name="extra"/> to a v4 signature body's unhashed subpacket area.</summary>
        private static byte[] AddToUnhashedArea(byte[] body, byte[] extra)
        {
            int unhashedLengthOffset = 6 + ((body[4] << 8) | body[5]);
            int unhashedLength = (body[unhashedLengthOffset] << 8) | body[unhashedLengthOffset + 1];
            int insertAt = unhashedLengthOffset + 2 + unhashedLength;
            byte[] result = [.. body[..insertAt], .. extra, .. body[insertAt..]];
            result[unhashedLengthOffset] = (byte)((unhashedLength + extra.Length) >> 8);
            result[unhashedLengthOffset + 1] = (byte)(unhashedLength + extra.Length);
            return result;
        }

        /// <summary>The certificate with <paramref name="change"/> applied to every signature of type <paramref name="type"/>.</summary>
        private static byte[] AlterSignatures(byte[] certificate, byte type, Func<byte[], byte[]> change) =>
            [.. PacketReader.ReadAll(certificate)
                .Select(p => p.Header.Tag == PacketTag.Signature && p.Body[1] == type ? new Packet(p.Header, change(p.Body)) : p)
                .SelectMany(Frame)];

        [Theory]
        [MemberData(nameof(UnsignedAdditions))]
        public void Revocation_WithUnsignedAdditions_ShouldStillRevoke(string extraHex)
        {
            // Arrange
            const string folder = Assets + "v4-revoked-key-hard/";
            byte[] altered = AlterSignatures(File.ReadAllBytes(folder + "public-key.gpg"), 0x20, b => AddToUnhashedArea(b, Convert.FromHexString(extraHex)));

            // Act
            VerificationResult result = OpenPgpVerifier.VerifyDetached(File.ReadAllBytes(folder + "data.txt"), File.ReadAllBytes(folder + "data.txt.after-revocation.sig"), altered, Now);

            // Assert
            Assert.Equal(VerificationStatus.KeyRevoked, result.Status);
        }

        [Theory]
        [MemberData(nameof(UnsignedAdditions))]
        public void ExpiringSelfSignature_WithUnsignedAdditions_ShouldStillExpireTheKey(string extraHex)
        {
            // Arrange
            const string folder = Assets + "v4-expired-key/";
            byte[] altered = AlterSignatures(File.ReadAllBytes(folder + "public-key.gpg"), 0x13, b => AddToUnhashedArea(b, Convert.FromHexString(extraHex)));

            // Act
            VerificationResult result = OpenPgpVerifier.VerifyDetached(File.ReadAllBytes(folder + "data.txt"), File.ReadAllBytes(folder + "data.txt.while-valid.sig"), altered, Now);

            // Assert
            Assert.Equal(VerificationStatus.KeyExpired, result.Status);
        }

        [Fact]
        public void Revocation_WithBrokenUnhashedFraming_ShouldStillRevoke()
        {
            // Arrange: a lone 0xFF announces a 5-octet subpacket length that isn't there.
            const string folder = Assets + "v4-revoked-key-hard/";
            byte[] altered = AlterSignatures(File.ReadAllBytes(folder + "public-key.gpg"), 0x20, b => AddToUnhashedArea(b, [0xFF]));

            // Act
            VerificationResult result = OpenPgpVerifier.VerifyDetached(File.ReadAllBytes(folder + "data.txt"), File.ReadAllBytes(folder + "data.txt.after-revocation.sig"), altered, Now);

            // Assert
            Assert.Equal(VerificationStatus.KeyRevoked, result.Status);
        }

        [Fact]
        public void Revocation_WhoseOnlyIssuerHintIsUnsignedAndReplaced_ShouldStillRevoke()
        {
            // Arrange: a revocation whose issuer is named only by an unhashed key ID (as older
            // GnuPG does). Replacing that ID used to make the revocation look like someone else's.
            var generator = new Ed25519KeyPairGenerator();
            generator.Init(new Ed25519KeyGenerationParameters(new SecureRandom()));
            var key = new PgpKeyPair(PublicKeyAlgorithmTag.EdDsa, generator.GenerateKeyPair(), new DateTime(2025, 1, 1, 0, 0, 0, DateTimeKind.Utc));

            var subpackets = new PgpSignatureSubpacketGenerator();
            subpackets.SetSignatureCreationTime(false, new DateTime(2025, 1, 1, 0, 0, 0, DateTimeKind.Utc));
            var unhashed = new PgpSignatureSubpacketGenerator();
            unhashed.SetIssuerKeyID(false, key.KeyId);
            var revocationGenerator = new PgpSignatureGenerator(PublicKeyAlgorithmTag.EdDsa, HashAlgorithmTag.Sha256);
            revocationGenerator.InitSign(PgpSignature.KeyRevocation, key.PrivateKey);
            revocationGenerator.SetHashedSubpackets(subpackets.Generate());
            revocationGenerator.SetUnhashedSubpackets(unhashed.Generate());
            byte[] revocation = PacketReader.ReadAll(revocationGenerator.GenerateCertification(key.PublicKey).GetEncoded())[0].Body;

            SignaturePacket parsed = SignaturePacket.Parse(revocation);
            Assert.DoesNotContain(parsed.HashedSubpackets, s => s.Is(SignatureSubpacketType.IssuerFingerprint) || s.Is(SignatureSubpacketType.IssuerKeyId));
            byte[] keyId = Assert.Single(parsed.GetIssuerKeyIds(hashedOnly: false));

            // Replace the unsigned key ID in place (flip every byte).
            int at = revocation.AsSpan().IndexOf(keyId);
            for (int i = 0; i < 8; i++)
            {
                revocation[at + i] ^= 0xFF;
            }

            byte[] keyBody = PacketReader.ReadAll(key.PublicKey.PublicKeyPacket.GetEncoded())[0].Body;
            byte[] certificate = [.. Frame(new Packet(new PacketHeader(PacketTag.PublicKey, 6), keyBody)), .. Frame(new Packet(new PacketHeader(PacketTag.Signature, 2), revocation))];

            var documentGenerator = new PgpSignatureGenerator(PublicKeyAlgorithmTag.EdDsa, HashAlgorithmTag.Sha256);
            documentGenerator.InitSign(PgpSignature.BinaryDocument, key.PrivateKey);
            documentGenerator.SetHashedSubpackets(subpackets.Generate());
            documentGenerator.Update("data"u8.ToArray());
            byte[] signature = documentGenerator.Generate().GetEncoded();

            // Act
            VerificationResult result = OpenPgpVerifier.VerifyDetached("data"u8, signature, certificate, Now);

            // Assert
            Assert.Equal(VerificationStatus.KeyRevoked, result.Status);
        }

        [Fact]
        public void Revocation_ThatCannotBeParsed_ShouldMakeTheKeyUnusable()
        {
            // Arrange: the unrevoked certificate plus a truncated key-revocation packet right after
            // the primary key. It might be a genuine revocation, so it must not just be skipped.
            const string folder = Assets + "v4-revoked-key-hard/";
            List<Packet> packets = PacketReader.ReadAll(File.ReadAllBytes(folder + "public-key-unrevoked.gpg"));
            var truncatedRevocation = new Packet(new PacketHeader(PacketTag.Signature, 2), [0x04, 0x20, 0x16, 0x08, 0xFF]);
            byte[] certificate = [.. Frame(packets[0]), .. Frame(truncatedRevocation), .. packets.Skip(1).SelectMany(Frame)];

            // Act
            VerificationResult result = OpenPgpVerifier.VerifyDetached(File.ReadAllBytes(folder + "data.txt"), File.ReadAllBytes(folder + "data.txt.before-revocation.sig"), certificate, Now);

            // Assert
            Assert.Equal(VerificationStatus.KeyNotValidForSigning, result.Status);
        }

        [Fact]
        public void DocumentSignature_WithUnsignedAdditions_ShouldStillVerify()
        {
            // Arrange: the same rule for document signatures - unsigned additions neither break nor
            // change a valid signature.
            const string folder = Assets + "v4-eddsa-ed25519-legacy/";
            Packet signature = PacketReader.ReadAll(File.ReadAllBytes(folder + "data.txt.sig"))[0];
            byte[] altered = Frame(new Packet(signature.Header, AddToUnhashedArea(signature.Body, [0x01, 0xFF])));

            // Act
            VerificationResult result = OpenPgpVerifier.VerifyDetached(File.ReadAllBytes(folder + "data.txt"), altered, File.ReadAllBytes(folder + "public-key.gpg"), Now);

            // Assert
            Assert.True(result.IsValid, result.ToString());
        }
    }
}
