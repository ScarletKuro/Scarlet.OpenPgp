using System.Text;
using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Bcpg.OpenPgp;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace Scarlet.OpenPgp.Tests.FixtureGeneration
{
    /// <summary>
    /// Signature- and key-lifetime checks against BouncyCastle-generated keys and signatures: a
    /// signature past its expiration time, a key past the expiration set by its self-signature, and
    /// a signature older than its key must all fail, while expiration data from a certification the
    /// key didn't make itself must be ignored.
    /// </summary>
    public class ExpirationCrossValidationTests
    {
        private const PublicKeyAlgorithmTag Algorithm = PublicKeyAlgorithmTag.EdDsa;
        private const string UserId = "Scarlet Test <test@example.invalid>";

        private static readonly byte[] Data = "Scarlet.OpenPgp expiration cross-validation."u8.ToArray();

        private static string Armor(string label, byte[] body)
        {
            int crc = Scarlet.OpenPgp.Armor.Crc24.Compute(body);
            byte[] crcBytes = [(byte)(crc >> 16), (byte)(crc >> 8), (byte)crc];
            return "-----BEGIN PGP " + label + "-----\n\n"
                   + Convert.ToBase64String(body) + "\n"
                   + "=" + Convert.ToBase64String(crcBytes) + "\n"
                   + "-----END PGP " + label + "-----\n";
        }

        private static PgpKeyPair GenerateKeyPair(DateTime createdAt)
        {
            var generator = new Ed25519KeyPairGenerator();
            generator.Init(new Ed25519KeyGenerationParameters(new SecureRandom()));
            return new PgpKeyPair(Algorithm, generator.GenerateKeyPair(), createdAt);
        }

        private static string ArmorPublicKey(PgpPublicKey publicKey)
        {
            using var ms = new MemoryStream();
            publicKey.Encode(ms);
            return Armor("PUBLIC KEY BLOCK", ms.ToArray());
        }

        /// <summary>Adds a positive User ID certification of <paramref name="subject"/>, made by <paramref name="signer"/>, carrying a key-expiration time.</summary>
        private static PgpPublicKey Certify(PgpPublicKey subject, PgpPrivateKey signer, DateTime createdAt, long keyLifetimeSeconds)
        {
            var subpackets = new PgpSignatureSubpacketGenerator();
            subpackets.SetSignatureCreationTime(false, createdAt);
            subpackets.SetKeyExpirationTime(false, keyLifetimeSeconds);

            var generator = new PgpSignatureGenerator(Algorithm, HashAlgorithmTag.Sha256);
            generator.InitSign(PgpSignature.PositiveCertification, signer);
            generator.SetHashedSubpackets(subpackets.Generate());
            PgpSignature certification = generator.GenerateCertification(UserId, subject);
            return PgpPublicKey.AddCertification(subject, UserId, certification);
        }

        private static string SignDetached(PgpPrivateKey signer, DateTime createdAt, long signatureLifetimeSeconds = 0)
        {
            var subpackets = new PgpSignatureSubpacketGenerator();
            subpackets.SetSignatureCreationTime(false, createdAt);
            if (signatureLifetimeSeconds != 0)
            {
                subpackets.SetSignatureExpirationTime(false, signatureLifetimeSeconds);
            }

            var generator = new PgpSignatureGenerator(Algorithm, HashAlgorithmTag.Sha256);
            generator.InitSign(PgpSignature.BinaryDocument, signer);
            generator.SetHashedSubpackets(subpackets.Generate());
            generator.Update(Data);

            using var ms = new MemoryStream();
            generator.Generate().Encode(ms);
            return Armor("SIGNATURE", ms.ToArray());
        }

        private static DateTime TruncateToSeconds(DateTime value) => new DateTime(value.Ticks - (value.Ticks % TimeSpan.TicksPerSecond), DateTimeKind.Utc);

        [Fact]
        public void VerifyDetached_WithSignaturePastItsExpirationTime_ShouldReturnFalse()
        {
            // Arrange
            DateTime now = TruncateToSeconds(DateTime.UtcNow);
            PgpKeyPair key = GenerateKeyPair(now);
            string signatureArmor = SignDetached(key.PrivateKey, now, signatureLifetimeSeconds: 3600);
            string publicKeyArmor = ArmorPublicKey(key.PublicKey);

            // Act
            bool validNow = OpenPgpVerifier.VerifyDetached(Data, signatureArmor, publicKeyArmor, now.AddMinutes(1)).IsValid;
            bool validLater = OpenPgpVerifier.VerifyDetached(Data, signatureArmor, publicKeyArmor, now.AddHours(2)).IsValid;

            // Assert
            Assert.True(validNow);
            Assert.False(validLater);
        }

        [Fact]
        public void VerifyDetached_WithKeyPastTheExpirationSetByItsSelfSignature_ShouldReturnFalse()
        {
            // Arrange
            DateTime now = TruncateToSeconds(DateTime.UtcNow);
            PgpKeyPair key = GenerateKeyPair(now);
            PgpPublicKey certified = Certify(key.PublicKey, key.PrivateKey, now, keyLifetimeSeconds: 3600);
            string signatureArmor = SignDetached(key.PrivateKey, now);
            string publicKeyArmor = ArmorPublicKey(certified);

            // Act
            bool validNow = OpenPgpVerifier.VerifyDetached(Data, signatureArmor, publicKeyArmor, now.AddMinutes(1)).IsValid;
            bool validLater = OpenPgpVerifier.VerifyDetached(Data, signatureArmor, publicKeyArmor, now.AddHours(2)).IsValid;

            // Assert
            Assert.True(validNow);
            Assert.False(validLater);
        }

        [Fact]
        public void VerifyDetached_WithSignatureMadeAfterTheKeyExpired_ShouldReturnFalse()
        {
            // Arrange: the key lived for one hour; the signature claims to be from a day later.
            DateTime keyCreated = TruncateToSeconds(DateTime.UtcNow);
            PgpKeyPair key = GenerateKeyPair(keyCreated);
            PgpPublicKey certified = Certify(key.PublicKey, key.PrivateKey, keyCreated, keyLifetimeSeconds: 3600);
            string signatureArmor = SignDetached(key.PrivateKey, keyCreated.AddDays(1));
            string publicKeyArmor = ArmorPublicKey(certified);

            // Act: even with a clock still inside the key's lifetime.
            bool result = OpenPgpVerifier.VerifyDetached(Data, signatureArmor, publicKeyArmor, keyCreated.AddMinutes(1)).IsValid;

            // Assert
            Assert.False(result);
        }

        [Fact]
        public void VerifyDetached_WithTheMostRecentSelfSignatureRemovingTheExpiration_ShouldReturnTrue()
        {
            // Arrange: an older self-signature set a one-hour lifetime; a newer one extends it to
            // "never expires". The newest valid self-signature wins (RFC 4880 §5.2.3.3).
            DateTime now = TruncateToSeconds(DateTime.UtcNow);
            PgpKeyPair key = GenerateKeyPair(now);
            PgpPublicKey certified = Certify(key.PublicKey, key.PrivateKey, now, keyLifetimeSeconds: 3600);
            certified = Certify(certified, key.PrivateKey, now.AddSeconds(10), keyLifetimeSeconds: 0);
            string signatureArmor = SignDetached(key.PrivateKey, now);
            string publicKeyArmor = ArmorPublicKey(certified);

            // Act
            bool result = OpenPgpVerifier.VerifyDetached(Data, signatureArmor, publicKeyArmor, now.AddHours(2)).IsValid;

            // Assert
            Assert.True(result);
        }

        [Fact]
        public void VerifyDetached_WithKeyExpirationFromACertificationByAnotherKey_ShouldIgnoreIt()
        {
            // Arrange: only signatures the key made over itself may set its lifetime. A certification
            // by some other key (or a forged one) must neither expire it nor otherwise count.
            DateTime now = TruncateToSeconds(DateTime.UtcNow);
            PgpKeyPair key = GenerateKeyPair(now);
            PgpKeyPair otherKey = GenerateKeyPair(now);
            PgpPublicKey certified = Certify(key.PublicKey, otherKey.PrivateKey, now, keyLifetimeSeconds: 60);
            string signatureArmor = SignDetached(key.PrivateKey, now);
            string publicKeyArmor = ArmorPublicKey(certified);

            // Act
            bool result = OpenPgpVerifier.VerifyDetached(Data, signatureArmor, publicKeyArmor, now.AddHours(2)).IsValid;

            // Assert
            Assert.True(result);
        }

        [Fact]
        public void VerifyDetached_WithSignatureOlderThanTheKey_ShouldReturnFalse()
        {
            // Arrange
            DateTime now = TruncateToSeconds(DateTime.UtcNow);
            PgpKeyPair key = GenerateKeyPair(now);
            string signatureArmor = SignDetached(key.PrivateKey, now.AddDays(-1));
            string publicKeyArmor = ArmorPublicKey(key.PublicKey);

            // Act
            bool result = OpenPgpVerifier.VerifyDetached(Data, signatureArmor, publicKeyArmor, now).IsValid;

            // Assert
            Assert.False(result);
        }
    }
}
