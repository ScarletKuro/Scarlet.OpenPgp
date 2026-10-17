using System.Text;
using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Bcpg.OpenPgp;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Scarlet.OpenPgp.Packets;
using PacketTag = Scarlet.OpenPgp.Packets.PacketTag;
using Packet = Scarlet.OpenPgp.Packets.Packet;

namespace Scarlet.OpenPgp.Tests.Signing
{
    /// <summary>
    /// Certificate rules that GnuPG refuses to produce violations of, so the fixtures can't cover
    /// them: certificates are assembled packet by packet here, with BouncyCastle making the
    /// signatures, to check that a key is only trusted to sign data when its certificate says so.
    /// </summary>
    public class CertificateTests
    {
        private const PublicKeyAlgorithmTag Algorithm = PublicKeyAlgorithmTag.EdDsa;

        private static readonly byte[] Data = "Scarlet.OpenPgp certificate rules."u8.ToArray();

        private static readonly DateTime CreatedAt = new DateTime(2025, 1, 1, 0, 0, 0, DateTimeKind.Utc);

        private static readonly DateTimeOffset Now = new DateTimeOffset(2025, 6, 1, 0, 0, 0, TimeSpan.Zero);

        private static PgpKeyPair NewKey()
        {
            var generator = new Ed25519KeyPairGenerator();
            generator.Init(new Ed25519KeyGenerationParameters(new SecureRandom()));
            return new PgpKeyPair(Algorithm, generator.GenerateKeyPair(), CreatedAt);
        }

        /// <summary>A new-format packet with a 5-octet length.</summary>
        private static byte[] Packet(PacketTag tag, byte[] body)
        {
            var packet = new byte[6 + body.Length];
            packet[0] = (byte)(0xC0 | (byte)tag);
            packet[1] = 0xFF;
            packet[2] = (byte)(body.Length >> 24);
            packet[3] = (byte)(body.Length >> 16);
            packet[4] = (byte)(body.Length >> 8);
            packet[5] = (byte)body.Length;
            Array.Copy(body, 0, packet, 6, body.Length);
            return packet;
        }

        private static byte[] KeyBody(PgpPublicKey key) => PacketReader.ReadAll(key.PublicKeyPacket.GetEncoded())[0].Body;

        private static byte[] Encoded(PgpSignature signature) => signature.GetEncoded();

        private static PgpSignatureSubpacketVector Subpackets(Action<PgpSignatureSubpacketGenerator> configure)
        {
            var generator = new PgpSignatureSubpacketGenerator();
            generator.SetSignatureCreationTime(false, CreatedAt);
            configure(generator);
            return generator.Generate();
        }

        private static PgpSignature SubkeyBinding(PgpKeyPair primary, PgpKeyPair subkey, int keyFlags, bool withBackSignature, HashAlgorithmTag hash = HashAlgorithmTag.Sha256, PgpKeyPair? backSigner = null)
        {
            PgpSignature? backSignature = null;
            if (withBackSignature)
            {
                var back = new PgpSignatureGenerator(Algorithm, hash);
                back.InitSign(PgpSignature.PrimaryKeyBinding, (backSigner ?? subkey).PrivateKey);
                back.SetHashedSubpackets(Subpackets(_ => { }));
                backSignature = back.GenerateCertification(primary.PublicKey, subkey.PublicKey);
            }

            var binding = new PgpSignatureGenerator(Algorithm, hash);
            binding.InitSign(PgpSignature.SubkeyBinding, primary.PrivateKey);
            binding.SetHashedSubpackets(Subpackets(g =>
            {
                g.SetKeyFlags(false, keyFlags);
                if (backSignature is not null)
                {
                    g.AddEmbeddedSignature(false, backSignature);
                }
            }));
            return binding.GenerateCertification(primary.PublicKey, subkey.PublicKey);
        }

        private static PgpSignature DirectKeySignature(PgpKeyPair primary, int keyFlags)
        {
            var generator = new PgpSignatureGenerator(Algorithm, HashAlgorithmTag.Sha256);
            generator.InitSign(PgpSignature.DirectKey, primary.PrivateKey);
            generator.SetHashedSubpackets(Subpackets(g => g.SetKeyFlags(false, keyFlags)));
            return generator.GenerateCertification(primary.PublicKey);
        }

        private static byte[] SignData(PgpKeyPair signer) => SignData(signer, CreatedAt);

        private static byte[] SignData(PgpKeyPair signer, DateTime signedAt)
        {
            var subpackets = new PgpSignatureSubpacketGenerator();
            subpackets.SetSignatureCreationTime(false, signedAt);
            subpackets.SetIssuerFingerprint(false, signer.PublicKey);

            var generator = new PgpSignatureGenerator(Algorithm, HashAlgorithmTag.Sha256);
            generator.InitSign(PgpSignature.BinaryDocument, signer.PrivateKey);
            generator.SetHashedSubpackets(subpackets.Generate());
            generator.Update(Data);
            return Encoded(generator.Generate());
        }

        /// <summary>A direct-key self-signature with the given flags that itself expires after <paramref name="signatureLifetimeSeconds"/> (and optionally sets a key lifetime).</summary>
        private static byte[] ExpiringDirectKeySignature(PgpKeyPair primary, int keyFlags, long signatureLifetimeSeconds, long keyLifetimeSeconds = 0)
        {
            var generator = new PgpSignatureGenerator(Algorithm, HashAlgorithmTag.Sha256);
            generator.InitSign(PgpSignature.DirectKey, primary.PrivateKey);
            generator.SetHashedSubpackets(Subpackets(g =>
            {
                g.SetKeyFlags(false, keyFlags);
                g.SetSignatureExpirationTime(false, signatureLifetimeSeconds);
                if (keyLifetimeSeconds != 0)
                {
                    g.SetKeyExpirationTime(false, keyLifetimeSeconds);
                }
            }));
            return Encoded(generator.GenerateCertification(primary.PublicKey));
        }

        private static byte[] Certificate(PgpKeyPair primary, IEnumerable<byte[]> primarySignatures, PgpKeyPair? subkey = null, IEnumerable<byte[]>? subkeySignatures = null)
        {
            var packets = new List<byte[]> { Packet(PacketTag.PublicKey, KeyBody(primary.PublicKey)) };
            packets.AddRange(primarySignatures);
            if (subkey is not null)
            {
                packets.Add(Packet(PacketTag.PublicSubkey, KeyBody(subkey.PublicKey)));
                packets.AddRange(subkeySignatures ?? []);
            }

            return packets.SelectMany(p => p).ToArray();
        }

        private static VerificationResult Verify(byte[] signature, byte[] certificate)
        {
            return OpenPgpVerifier.VerifyDetached(Data, signature, certificate, Now);
        }

        [Fact]
        public void SigningSubkey_WithFlagsAndBackSignature_ShouldVerify()
        {
            // Arrange
            PgpKeyPair primary = NewKey();
            PgpKeyPair subkey = NewKey();
            byte[] certificate = Certificate(primary, [Encoded(DirectKeySignature(primary, PgpKeyFlags.CanCertify))], subkey, [Encoded(SubkeyBinding(primary, subkey, PgpKeyFlags.CanSign, withBackSignature: true))]);

            // Act
            VerificationResult result = Verify(SignData(subkey), certificate);

            // Assert
            Assert.True(result.IsValid, result.ToString());
            Assert.NotEqual(result.PrimaryKeyFingerprint, result.SignerFingerprint);
        }

        [Fact]
        public void SigningSubkey_WithoutBackSignature_ShouldNotBeTrustedToSign()
        {
            // Arrange: without the back-signature anyone could bind someone else's signing key to
            // their own certificate and claim its signatures.
            PgpKeyPair primary = NewKey();
            PgpKeyPair subkey = NewKey();
            byte[] certificate = Certificate(primary, [], subkey, [Encoded(SubkeyBinding(primary, subkey, PgpKeyFlags.CanSign, withBackSignature: false))]);

            // Act
            VerificationResult result = Verify(SignData(subkey), certificate);

            // Assert
            Assert.Equal(VerificationStatus.KeyNotValidForSigning, result.Status);
        }

        [Fact]
        public void SigningSubkey_WithABackSignatureFromTheWrongKey_ShouldNotBeTrustedToSign()
        {
            // Arrange
            PgpKeyPair primary = NewKey();
            PgpKeyPair subkey = NewKey();
            PgpKeyPair impostor = NewKey();
            byte[] certificate = Certificate(primary, [], subkey, [Encoded(SubkeyBinding(primary, subkey, PgpKeyFlags.CanSign, withBackSignature: true, backSigner: impostor))]);

            // Act
            VerificationResult result = Verify(SignData(subkey), certificate);

            // Assert
            Assert.Equal(VerificationStatus.KeyNotValidForSigning, result.Status);
        }

        [Fact]
        public void Subkey_WhoseBindingLacksTheSignFlag_ShouldNotBeTrustedToSign()
        {
            // Arrange: an encryption subkey (with a back-signature even) must not sign data.
            PgpKeyPair primary = NewKey();
            PgpKeyPair subkey = NewKey();
            byte[] certificate = Certificate(primary, [], subkey, [Encoded(SubkeyBinding(primary, subkey, PgpKeyFlags.CanEncryptCommunications, withBackSignature: true))]);

            // Act
            VerificationResult result = Verify(SignData(subkey), certificate);

            // Assert
            Assert.Equal(VerificationStatus.KeyNotValidForSigning, result.Status);
        }

        [Fact]
        public void Subkey_BoundByAnotherCertificatesPrimary_ShouldNotBeTrustedToSign()
        {
            // Arrange: a binding signature made by a key other than this certificate's primary.
            PgpKeyPair primary = NewKey();
            PgpKeyPair otherPrimary = NewKey();
            PgpKeyPair subkey = NewKey();
            PgpSignature foreignBinding = SubkeyBinding(otherPrimary, subkey, PgpKeyFlags.CanSign, withBackSignature: true);
            byte[] certificate = Certificate(primary, [], subkey, [Encoded(foreignBinding)]);

            // Act
            VerificationResult result = Verify(SignData(subkey), certificate);

            // Assert
            Assert.Equal(VerificationStatus.KeyNotValidForSigning, result.Status);
        }

        [Fact]
        public void SigningSubkey_WithSha1BindingAndBackSignature_ShouldStillVerify()
        {
            // Arrange: SHA-1 self-signatures are common on older certificates and acceptable there
            // (only second-preimage resistance matters for them); data signatures still need SHA-2/3.
            PgpKeyPair primary = NewKey();
            PgpKeyPair subkey = NewKey();
            byte[] certificate = Certificate(primary, [], subkey, [Encoded(SubkeyBinding(primary, subkey, PgpKeyFlags.CanSign, withBackSignature: true, HashAlgorithmTag.Sha1))]);

            // Act
            VerificationResult result = Verify(SignData(subkey), certificate);

            // Assert
            Assert.True(result.IsValid, result.ToString());
        }

        [Fact]
        public void CertifyOnlyPrimary_SigningData_ShouldNotBeTrustedToSign()
        {
            // Arrange
            PgpKeyPair primary = NewKey();
            byte[] certificate = Certificate(primary, [Encoded(DirectKeySignature(primary, PgpKeyFlags.CanCertify))]);

            // Act
            VerificationResult result = Verify(SignData(primary), certificate);

            // Assert
            Assert.Equal(VerificationStatus.KeyNotValidForSigning, result.Status);
        }

        [Fact]
        public void PrimaryWithSignFlag_SigningData_ShouldVerify()
        {
            // Arrange
            PgpKeyPair primary = NewKey();
            byte[] certificate = Certificate(primary, [Encoded(DirectKeySignature(primary, PgpKeyFlags.CanCertify | PgpKeyFlags.CanSign))]);

            // Act
            VerificationResult result = Verify(SignData(primary), certificate);

            // Assert
            Assert.True(result.IsValid, result.ToString());
        }

        [Fact]
        public void ForgedDirectKeySignature_ShouldNotChangeTheKeysFlags()
        {
            // Arrange: a "direct-key signature" claiming certify-only, but made by another key -
            // it must be ignored, leaving a bare key that may sign.
            PgpKeyPair primary = NewKey();
            PgpKeyPair other = NewKey();
            var generator = new PgpSignatureGenerator(Algorithm, HashAlgorithmTag.Sha256);
            generator.InitSign(PgpSignature.DirectKey, other.PrivateKey);
            generator.SetHashedSubpackets(Subpackets(g => g.SetKeyFlags(false, PgpKeyFlags.CanCertify)));
            PgpSignature forged = generator.GenerateCertification(primary.PublicKey);
            byte[] certificate = Certificate(primary, [Encoded(forged)]);

            // Act
            VerificationResult result = Verify(SignData(primary), certificate);

            // Assert
            Assert.True(result.IsValid, result.ToString());
        }

        [Fact]
        public void V6Certificate_WithoutItsDirectKeySignature_ShouldNotBeTrustedToSign()
        {
            // Arrange: RFC 9580 §5.2.3.10 - a v6 key needs a valid Direct Key signature before use,
            // so stripping it (to drop, say, an expiration) must not leave a usable key.
            List<Packet> packets = PacketReader.ReadAll(File.ReadAllBytes("TestAssets/rfc9580/a3-v6-certificate.gpg"));
            Assert.Equal(PacketTag.Signature, packets[1].Header.Tag);
            byte[] stripped = Packet(PacketTag.PublicKey, packets[0].Body)
                .Concat(Packet(PacketTag.PublicSubkey, packets[2].Body))
                .Concat(Packet(PacketTag.Signature, packets[3].Body))
                .ToArray();
            string message = File.ReadAllText("TestAssets/rfc9580/a6-cleartext-signed.asc");

            // Act
            VerificationResult result = OpenPgpVerifier.VerifyClearsign(message, stripped, Now);

            // Assert
            Assert.Equal(VerificationStatus.KeyNotValidForSigning, result.Status);
        }

        [Fact]
        public void KeyInput_ContainingASecretKeyPacket_ShouldBeRejected()
        {
            // Arrange: secret key material has no business in a trusted public key file.
            PgpKeyPair primary = NewKey();
            byte[] certificate = Certificate(primary, [])
                .Concat(Packet(PacketTag.SecretKey, KeyBody(primary.PublicKey)))
                .ToArray();

            // Act
            VerificationResult result = Verify(SignData(primary), certificate);

            // Assert
            Assert.Equal(VerificationStatus.InvalidPublicKey, result.Status);
        }

        [Fact]
        public void CertifyOnlyPrimary_AfterItsSelfSignatureExpires_ShouldStillNotBeTrustedToSign()
        {
            // Arrange: regression - once the only (restrictive) self-signature expired, the key used
            // to fall back to "bare key, no restrictions" and verify. Expiry must never widen
            // authority. Self-signature lifetime 1 h, key lifetime 2 h.
            PgpKeyPair primary = NewKey();
            byte[] certificate = Certificate(primary, [ExpiringDirectKeySignature(primary, PgpKeyFlags.CanCertify, 3600, 7200)]);
            byte[] signature = SignData(primary, CreatedAt.AddMinutes(10));

            // Act
            VerificationResult whileCurrent = OpenPgpVerifier.VerifyDetached(Data, signature, certificate, new DateTimeOffset(CreatedAt.AddMinutes(20)));
            VerificationResult afterExpiry = OpenPgpVerifier.VerifyDetached(Data, signature, certificate, new DateTimeOffset(CreatedAt.AddDays(1)));

            // Assert
            Assert.Equal(VerificationStatus.KeyNotValidForSigning, whileCurrent.Status);
            Assert.Equal(VerificationStatus.KeyNotValidForSigning, afterExpiry.Status);
        }

        [Fact]
        public void SigningPrimary_WhoseOnlySelfSignatureExpired_ShouldNotBeTrustedToSign()
        {
            // Arrange: a permissive self-signature that expires after 1 h.
            PgpKeyPair primary = NewKey();
            byte[] certificate = Certificate(primary, [ExpiringDirectKeySignature(primary, PgpKeyFlags.CanCertify | PgpKeyFlags.CanSign, 3600)]);
            byte[] signature = SignData(primary, CreatedAt.AddMinutes(10));

            // Act
            VerificationResult whileCurrent = OpenPgpVerifier.VerifyDetached(Data, signature, certificate, new DateTimeOffset(CreatedAt.AddMinutes(20)));
            VerificationResult afterExpiry = OpenPgpVerifier.VerifyDetached(Data, signature, certificate, new DateTimeOffset(CreatedAt.AddDays(1)));

            // Assert
            Assert.True(whileCurrent.IsValid, whileCurrent.ToString());
            Assert.Equal(VerificationStatus.KeyNotValidForSigning, afterExpiry.Status);
        }

        [Fact]
        public void Signature_DatedInTheFuture_ShouldBeRejected()
        {
            // Arrange: regression - a signature dated a day after "now" used to verify.
            PgpKeyPair primary = NewKey();
            byte[] certificate = Certificate(primary, []);
            byte[] future = SignData(primary, Now.UtcDateTime.AddDays(1));

            // Act
            VerificationResult result = Verify(future, certificate);

            // Assert
            Assert.Equal(VerificationStatus.InvalidSignatureTime, result.Status);
        }

        [Fact]
        public void Signature_DatedSlightlyAhead_ShouldBeAcceptedWithinTheClockSkewAllowance()
        {
            // Arrange: one minute ahead - within the 5-minute allowance for clocks being slightly off.
            PgpKeyPair primary = NewKey();
            byte[] certificate = Certificate(primary, []);
            byte[] slightlyAhead = SignData(primary, Now.UtcDateTime.AddMinutes(1));

            // Act
            VerificationResult result = Verify(slightlyAhead, certificate);

            // Assert
            Assert.True(result.IsValid, result.ToString());
        }
    }
}
