using System.Text;
using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Bcpg.OpenPgp;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Scarlet.OpenPgp.Packets;
using PacketTag = Scarlet.OpenPgp.Packets.PacketTag;
using Packet = Scarlet.OpenPgp.Packets.Packet;

namespace Scarlet.OpenPgp.Tests.Verification
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
        public void EdDsaSigningSubkey_WithSha1BindingAndBackSignature_ShouldNotBeTrustedToSign()
        {
            // Arrange: SHA-1 is accepted for key self-signatures only where the algorithm allows a
            // 160-bit hash (RSA). EdDSALegacy requires at least 256 bits, and RFC 9580 §5.2.3.3 says
            // a verifier MUST reject a weaker hash - so this binding can't be checked, and the
            // subkey isn't usable. (RSA SHA-1 self-signatures: RsaKey_WithAnExpiringSelfSignature_*.)
            PgpKeyPair primary = NewKey();
            PgpKeyPair subkey = NewKey();
            byte[] certificate = Certificate(primary, [], subkey, [Encoded(SubkeyBinding(primary, subkey, PgpKeyFlags.CanSign, withBackSignature: true, HashAlgorithmTag.Sha1))]);

            // Act
            VerificationResult result = Verify(SignData(subkey), certificate);

            // Assert
            Assert.Equal(VerificationStatus.KeyNotValidForSigning, result.Status);
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

        private static PgpKeyPair NewRsaKey()
        {
            var generator = new RsaKeyPairGenerator();
            generator.Init(new RsaKeyGenerationParameters(Org.BouncyCastle.Math.BigInteger.ValueOf(65537), new SecureRandom(), 2048, 80));
            return new PgpKeyPair(PublicKeyAlgorithmTag.RsaGeneral, generator.GenerateKeyPair(), CreatedAt);
        }

        private static byte[] KeySignature(PgpKeyPair key, int type, HashAlgorithmTag hash, Action<PgpSignatureSubpacketGenerator> configure)
        {
            var generator = new PgpSignatureGenerator(key.PublicKey.Algorithm, hash);
            generator.InitSign(type, key.PrivateKey);
            generator.SetHashedSubpackets(Subpackets(configure));
            return Encoded(generator.GenerateCertification(key.PublicKey));
        }

        private static byte[] SignDataWith(PgpKeyPair signer)
        {
            var generator = new PgpSignatureGenerator(signer.PublicKey.Algorithm, HashAlgorithmTag.Sha256);
            generator.InitSign(PgpSignature.BinaryDocument, signer.PrivateKey);
            generator.SetHashedSubpackets(Subpackets(g => g.SetIssuerFingerprint(false, signer.PublicKey)));
            generator.Update(Data);
            return Encoded(generator.Generate());
        }

        [Theory]
        [InlineData(HashAlgorithmTag.Sha256)]
        [InlineData(HashAlgorithmTag.Sha1)]
        public void RsaKey_WithAnExpiringSelfSignature_ShouldExpireWhicheverHashTheSelfSignatureUses(HashAlgorithmTag selfSignatureHash)
        {
            // Arrange: regression - SHA-1 RSA self-signatures used to fail verification (no SHA-1
            // DigestInfo), be ignored, and leave an unrestricted bare key. Key lifetime 1 h.
            PgpKeyPair key = NewRsaKey();
            byte[] certificate = Certificate(key, [KeySignature(key, PgpSignature.DirectKey, selfSignatureHash, g => g.SetKeyExpirationTime(false, 3600))]);

            // Act
            VerificationResult result = Verify(SignDataWith(key), certificate);

            // Assert
            Assert.Equal(VerificationStatus.KeyExpired, result.Status);
        }

        [Fact]
        public void RsaKey_WithASha1Revocation_ShouldBeRevoked()
        {
            // Arrange: regression - a SHA-1 key revocation was likewise ignored.
            PgpKeyPair key = NewRsaKey();
            byte[] certificate = Certificate(key, [KeySignature(key, PgpSignature.KeyRevocation, HashAlgorithmTag.Sha1, _ => { })]);

            // Act
            VerificationResult result = Verify(SignDataWith(key), certificate);

            // Assert
            Assert.Equal(VerificationStatus.KeyRevoked, result.Status);
        }

        [Fact]
        public void Key_WithASelfSignatureItCannotCheck_ShouldNotBeTreatedAsBare()
        {
            // Arrange: an EdDSA self-signature over SHA-1 - too weak for EdDSA, so it can't be
            // verified. It might be a genuine restriction; ignoring it must not leave an
            // unrestricted key.
            PgpKeyPair key = NewKey();
            byte[] certificate = Certificate(key, [KeySignature(key, PgpSignature.DirectKey, HashAlgorithmTag.Sha1, g => g.SetKeyFlags(false, PgpKeyFlags.CanCertify))]);

            // Act
            VerificationResult result = Verify(SignData(key), certificate);

            // Assert
            Assert.Equal(VerificationStatus.KeyNotValidForSigning, result.Status);
            Assert.Contains("can't be checked", result.Message, StringComparison.Ordinal);
        }

        [Fact]
        public void SignatureInput_WithManyIdenticalCopies_ShouldBeDeduplicatedAndVerify()
        {
            // Arrange: 256 copies of one signature - previously 256 passes over the data.
            PgpKeyPair key = NewKey();
            byte[] one = SignData(key);
            byte[] copies = [.. Enumerable.Repeat(one, 256).SelectMany(b => b)];

            // Act
            VerificationResult result = Verify(copies, Certificate(key, []));

            // Assert
            Assert.True(result.IsValid, result.ToString());
        }

        [Fact]
        public void SignatureInput_WithMoreDistinctSignaturesThanTheLimit_ShouldBeRejected()
        {
            // Arrange: 33 distinct (differently timed) signatures, one over the limit of 32.
            PgpKeyPair key = NewKey();
            byte[] signatures = [.. Enumerable.Range(0, 33).SelectMany(i => SignData(key, CreatedAt.AddSeconds(i)))];

            // Act
            VerificationResult result = Verify(signatures, Certificate(key, []));

            // Assert
            Assert.Equal(VerificationStatus.MalformedInput, result.Status);
            Assert.Contains("more than 32", result.Message, StringComparison.Ordinal);
        }

        private const string UserId = "Owner <owner@example.test>";

        /// <summary>A key signature made at <paramref name="at"/>; <paramref name="generate"/> picks what it certifies.</summary>
        private static byte[] Timed(PgpKeyPair signer, int type, DateTime at, Func<PgpSignatureGenerator, PgpSignature> generate, Action<PgpSignatureSubpacketGenerator>? configure = null)
        {
            var subpackets = new PgpSignatureSubpacketGenerator();
            subpackets.SetSignatureCreationTime(false, at);
            configure?.Invoke(subpackets);
            var generator = new PgpSignatureGenerator(Algorithm, HashAlgorithmTag.Sha256);
            generator.InitSign(type, signer.PrivateKey);
            generator.SetHashedSubpackets(subpackets.Generate());
            return Encoded(generate(generator));
        }

        private static byte[] UserIdCertification(PgpKeyPair signer, PgpKeyPair owner, int type, DateTime at) =>
            Timed(signer, type, at, g => g.GenerateCertification(UserId, owner.PublicKey), g => g.SetKeyFlags(false, PgpKeyFlags.CanSign));

        private static byte[] Concat(params byte[][] parts) => parts.SelectMany(p => p).ToArray();

        [Theory]
        [InlineData(PgpKeyFlags.CanCertify, false)]
        [InlineData(PgpKeyFlags.CanSign, true)]
        public void SelfSignatures_TiedForNewest_ShouldGiveTheSameVerdictInEitherOrder(int secondFlags, bool expectValid)
        {
            // Arrange: two Direct Key signatures made in the same second. When they disagree (one
            // allows signing, one doesn't) neither can be "the newest", so the key fails closed;
            // picking by position let reordering the packets turn KeyNotValidForSigning into Valid.
            PgpKeyPair primary = NewKey();
            byte[] first = Timed(primary, PgpSignature.DirectKey, CreatedAt, g => g.GenerateCertification(primary.PublicKey), g => g.SetKeyFlags(false, PgpKeyFlags.CanSign));
            byte[] second = Timed(primary, PgpSignature.DirectKey, CreatedAt, g => g.GenerateCertification(primary.PublicKey), g => g.SetKeyFlags(false, secondFlags));
            byte[] signature = SignData(primary, CreatedAt.AddDays(10));

            // Act
            VerificationResult forward = Verify(signature, Certificate(primary, [first, second]));
            VerificationResult backward = Verify(signature, Certificate(primary, [second, first]));

            // Assert
            Assert.Equal(forward.Status, backward.Status);
            Assert.Equal(expectValid, forward.IsValid);
        }

        [Fact]
        public void KeyRevocation_MovedAfterAUserId_ShouldStillRevokeThePrimaryKey()
        {
            // Arrange: the same revocation, in its usual place and moved after a User ID - which
            // used to be read as a User ID certification and ignored, turning KeyRevoked into Valid.
            PgpKeyPair primary = NewKey();
            byte[] revocation = Timed(primary, PgpSignature.KeyRevocation, CreatedAt.AddDays(1), g => g.GenerateCertification(primary.PublicKey));
            byte[] key = Packet(PacketTag.PublicKey, KeyBody(primary.PublicKey));
            byte[] userId = Packet(PacketTag.UserId, Encoding.UTF8.GetBytes(UserId));
            byte[] signature = SignData(primary, CreatedAt.AddDays(10));

            // Act
            VerificationResult inPlace = Verify(signature, Concat(key, revocation, userId));
            VerificationResult moved = Verify(signature, Concat(key, userId, revocation));

            // Assert
            Assert.Equal(VerificationStatus.KeyRevoked, inPlace.Status);
            Assert.Equal(VerificationStatus.KeyRevoked, moved.Status);
        }

        [Fact]
        public void CertificationRevocation_PlacedBeforeTheCertification_ShouldStillRevokeTheUserId()
        {
            // Arrange: a revocation (0x30) of the User ID's older self-certification, read first.
            PgpKeyPair primary = NewKey();
            byte[] certificate = Concat(
                Packet(PacketTag.PublicKey, KeyBody(primary.PublicKey)),
                Packet(PacketTag.UserId, Encoding.UTF8.GetBytes(UserId)),
                UserIdCertification(primary, primary, PgpSignature.CertificationRevocation, CreatedAt.AddDays(1)),
                UserIdCertification(primary, primary, PgpSignature.PositiveCertification, CreatedAt));

            // Act
            OpenPgpKeyRing ring = OpenPgpKeyRing.Parse(certificate);

            // Assert
            Assert.DoesNotContain(UserId, ring.Certificates[0].UserIds);
        }

        [Fact]
        public void V6Key_WhoseOnlyDirectKeySignatureIsRevoked_ShouldNotBeTrustedToSign()
        {
            // Arrange: a v6 key's Direct Key signature, then a certification revocation (0x30) of it
            // over the same content (RFC 9580 §5.2.1.14). BouncyCastle can't make v6 keys, so the
            // packets are built here and signed with raw Ed25519.
            var v6 = new V6Ed25519Key(CreatedAt);
            byte[] directKey = v6.Sign(0x1F, v6.KeyHashContent, CreatedAt);
            byte[] revocation = v6.Sign(0x30, v6.KeyHashContent, CreatedAt.AddDays(1));
            byte[] signature = v6.Sign(0x00, Data, CreatedAt.AddDays(10));
            byte[] certificate = Concat(v6.KeyPacket, directKey);

            // Act
            VerificationResult beforeRevocation = Verify(signature, certificate);
            VerificationResult afterRevocation = Verify(signature, Concat(certificate, revocation));

            // Assert
            Assert.True(beforeRevocation.IsValid, beforeRevocation.ToString());
            Assert.Equal(VerificationStatus.KeyNotValidForSigning, afterRevocation.Status);
        }

        /// <summary>A v6 Ed25519 key (algorithm 27) that signs with SHA-256 and a fixed zero salt - enough to build v6 test certificates by hand.</summary>
        private sealed class V6Ed25519Key
        {
            private readonly Ed25519PrivateKeyParameters _private;

            public V6Ed25519Key(DateTime createdAt)
            {
                var generator = new Ed25519KeyPairGenerator();
                generator.Init(new Ed25519KeyGenerationParameters(new SecureRandom()));
                var pair = generator.GenerateKeyPair();
                _private = (Ed25519PrivateKeyParameters)pair.Private;
                byte[] body = [6, .. BigEndian(Seconds(createdAt)), 27, 0, 0, 0, 32, .. ((Ed25519PublicKeyParameters)pair.Public).GetEncoded()];
                KeyPacket = Packet(PacketTag.PublicKey, body);
                KeyHashContent = KeyHashPrefix.Build(6, body);
            }

            public byte[] KeyPacket { get; }

            /// <summary>The key as Direct Key and key revocation signatures hash it.</summary>
            public byte[] KeyHashContent { get; }

            public byte[] Sign(byte type, byte[] content, DateTime at)
            {
                byte[] subpackets = [5, 2, .. BigEndian(Seconds(at))];
                byte[] hashed = [6, type, 27, 8, .. BigEndian((uint)subpackets.Length), .. subpackets];
                byte[] salt = new byte[16];
                byte[] digest = System.Security.Cryptography.SHA256.HashData([.. salt, .. content, .. hashed, 6, 0xFF, .. BigEndian((uint)hashed.Length)]);
                var signer = new Org.BouncyCastle.Crypto.Signers.Ed25519Signer();
                signer.Init(true, _private);
                signer.BlockUpdate(digest, 0, digest.Length);
                return Packet(PacketTag.Signature, [.. hashed, 0, 0, 0, 0, digest[0], digest[1], 16, .. salt, .. signer.GenerateSignature()]);
            }

            private static uint Seconds(DateTime at) => (uint)new DateTimeOffset(at).ToUnixTimeSeconds();

            private static byte[] BigEndian(uint value) => [(byte)(value >> 24), (byte)(value >> 16), (byte)(value >> 8), (byte)value];
        }

        [Fact]
        public void KeyRevocation_PlacedInTheSubkeySection_ShouldStillRevokeThePrimaryKey()
        {
            // Arrange: where a signature sits in the block is unsigned; what it covers is signed.
            PgpKeyPair primary = NewKey();
            PgpKeyPair subkey = NewKey();
            byte[] revocation = Timed(primary, PgpSignature.KeyRevocation, CreatedAt.AddDays(1), g => g.GenerateCertification(primary.PublicKey));
            byte[] certificate = Certificate(
                primary,
                [Encoded(DirectKeySignature(primary, PgpKeyFlags.CanSign))],
                subkey,
                [Encoded(SubkeyBinding(primary, subkey, PgpKeyFlags.CanSign, withBackSignature: true)), revocation]);

            // Act
            VerificationResult result = Verify(SignData(primary, CreatedAt.AddDays(10)), certificate);

            // Assert
            Assert.Equal(VerificationStatus.KeyRevoked, result.Status);
        }

        [Fact]
        public void SubkeyRevocation_PlacedBeforeItsSubkey_ShouldStillRevokeIt()
        {
            // Arrange
            PgpKeyPair primary = NewKey();
            PgpKeyPair subkey = NewKey();
            byte[] revocation = Timed(primary, PgpSignature.SubkeyRevocation, CreatedAt.AddDays(1), g => g.GenerateCertification(primary.PublicKey, subkey.PublicKey));
            byte[] certificate = Certificate(
                primary,
                [Encoded(DirectKeySignature(primary, PgpKeyFlags.CanCertify)), revocation],
                subkey,
                [Encoded(SubkeyBinding(primary, subkey, PgpKeyFlags.CanSign, withBackSignature: true))]);

            // Act
            VerificationResult result = Verify(SignData(subkey, CreatedAt.AddDays(10)), certificate);

            // Assert
            Assert.Equal(VerificationStatus.KeyRevoked, result.Status);
        }

        [Fact]
        public void SubkeyRevocation_PlacedUnderAnotherSubkey_ShouldStillRevokeItsOwnSubkey()
        {
            // Arrange: subkey A's revocation moved into subkey B's section.
            PgpKeyPair primary = NewKey();
            PgpKeyPair a = NewKey();
            PgpKeyPair b = NewKey();
            byte[] revocationOfA = Timed(primary, PgpSignature.SubkeyRevocation, CreatedAt.AddDays(1), g => g.GenerateCertification(primary.PublicKey, a.PublicKey));
            byte[] certificate = Concat(
                Packet(PacketTag.PublicKey, KeyBody(primary.PublicKey)),
                Encoded(DirectKeySignature(primary, PgpKeyFlags.CanCertify)),
                Packet(PacketTag.PublicSubkey, KeyBody(a.PublicKey)),
                Encoded(SubkeyBinding(primary, a, PgpKeyFlags.CanSign, withBackSignature: true)),
                Packet(PacketTag.PublicSubkey, KeyBody(b.PublicKey)),
                Encoded(SubkeyBinding(primary, b, PgpKeyFlags.CanSign, withBackSignature: true)),
                revocationOfA);

            // Act
            VerificationResult byA = Verify(SignData(a, CreatedAt.AddDays(10)), certificate);
            VerificationResult byB = Verify(SignData(b, CreatedAt.AddDays(10)), certificate);

            // Assert
            Assert.Equal(VerificationStatus.KeyRevoked, byA.Status);
            Assert.True(byB.IsValid, byB.ToString());
        }

        [Fact]
        public void UserId_RecertifiedAfterItsRevocation_ShouldBeValidAgain()
        {
            // Arrange: certified, revoked a day later, certified again a day after that.
            PgpKeyPair primary = NewKey();
            byte[] revoked = Concat(
                Packet(PacketTag.PublicKey, KeyBody(primary.PublicKey)),
                Packet(PacketTag.UserId, Encoding.UTF8.GetBytes(UserId)),
                UserIdCertification(primary, primary, PgpSignature.PositiveCertification, CreatedAt),
                UserIdCertification(primary, primary, PgpSignature.CertificationRevocation, CreatedAt.AddDays(1)));
            byte[] recertified = Concat(revoked, UserIdCertification(primary, primary, PgpSignature.PositiveCertification, CreatedAt.AddDays(2)));

            // Act
            OpenPgpKeyRing revokedRing = OpenPgpKeyRing.Parse(revoked);
            OpenPgpKeyRing recertifiedRing = OpenPgpKeyRing.Parse(recertified);

            // Assert
            Assert.Empty(revokedRing.Certificates[0].UserIds);
            Assert.Equal([UserId], recertifiedRing.Certificates[0].UserIds);
            Assert.True(Verify(SignData(primary, CreatedAt.AddDays(10)), recertified).IsValid);
        }

        [Fact]
        public void V4Key_WhoseOnlySelfCertificationIsRevoked_ShouldNotBeTreatedAsBare()
        {
            // Arrange: with the revoked certification gone, the key must not fall back to "no
            // self-signature, so no restrictions and no expiration".
            PgpKeyPair primary = NewKey();
            byte[] certificate = Concat(
                Packet(PacketTag.PublicKey, KeyBody(primary.PublicKey)),
                Packet(PacketTag.UserId, Encoding.UTF8.GetBytes(UserId)),
                UserIdCertification(primary, primary, PgpSignature.PositiveCertification, CreatedAt),
                UserIdCertification(primary, primary, PgpSignature.CertificationRevocation, CreatedAt.AddDays(1)));

            // Act
            VerificationResult result = Verify(SignData(primary, CreatedAt.AddDays(10)), certificate);

            // Assert
            Assert.Equal(VerificationStatus.KeyNotValidForSigning, result.Status);
        }

        [Fact]
        public void ThirdPartyCertificationRevocation_ShouldNotRevokeTheOwnersUserId()
        {
            // Arrange: someone else revoking their own certification of this User ID.
            PgpKeyPair primary = NewKey();
            PgpKeyPair other = NewKey();
            byte[] certificate = Concat(
                Packet(PacketTag.PublicKey, KeyBody(primary.PublicKey)),
                Packet(PacketTag.UserId, Encoding.UTF8.GetBytes(UserId)),
                UserIdCertification(primary, primary, PgpSignature.PositiveCertification, CreatedAt),
                UserIdCertification(other, primary, PgpSignature.CertificationRevocation, CreatedAt.AddDays(1)));

            // Act
            OpenPgpKeyRing ring = OpenPgpKeyRing.Parse(certificate);

            // Assert
            Assert.Equal([UserId], ring.Certificates[0].UserIds);
            Assert.True(Verify(SignData(primary, CreatedAt.AddDays(10)), certificate).IsValid);
        }
    }
}
