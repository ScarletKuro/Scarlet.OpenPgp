using System;
using System.IO;
using System.Text;
using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Bcpg.OpenPgp;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using BigInteger = Org.BouncyCastle.Math.BigInteger;

namespace Scarlet.OpenPgp.Tests.FixtureGeneration
{
    /// <summary>
    /// Cross-validates Scarlet.OpenPgp against BouncyCastle - a mature, independent OpenPGP
    /// implementation - used here purely as a test-only reference signer/packet-writer, per
    /// SPEC.md's explicit carve-out. Never referenced by the shipped library. Each test generates
    /// a fresh key and signature at run time rather than relying on committed fixture files, which
    /// keeps this self-contained at the cost of re-running key generation on every test run.
    /// </summary>
    public class BouncyCastleCrossValidationTests
    {
        private static string Armor(string label, byte[] body)
        {
            int crc = Scarlet.OpenPgp.Armor.Crc24.Compute(body);
            byte[] crcBytes = { (byte)(crc >> 16), (byte)(crc >> 8), (byte)crc };
            return "-----BEGIN PGP " + label + "-----\n\n"
                   + Convert.ToBase64String(body) + "\n"
                   + "=" + Convert.ToBase64String(crcBytes) + "\n"
                   + "-----END PGP " + label + "-----\n";
        }

        private static AsymmetricCipherKeyPair GenerateRsaKeyPair()
        {
            var generator = new RsaKeyPairGenerator();
            generator.Init(new RsaKeyGenerationParameters(BigInteger.ValueOf(65537), new SecureRandom(), 2048, 80));
            return generator.GenerateKeyPair();
        }

        private static AsymmetricCipherKeyPair GenerateEd25519KeyPair()
        {
            var generator = new Ed25519KeyPairGenerator();
            generator.Init(new Ed25519KeyGenerationParameters(new SecureRandom()));
            return generator.GenerateKeyPair();
        }

        private static (string PublicKeyArmor, PgpPrivateKey PrivateKey) CreateKeyPair(PublicKeyAlgorithmTag algorithm, AsymmetricCipherKeyPair rawKeyPair)
        {
            var pgpKeyPair = new PgpKeyPair(algorithm, rawKeyPair, DateTime.UtcNow);
            using (var ms = new MemoryStream())
            {
                pgpKeyPair.PublicKey.Encode(ms);
                string armor = Armor("PUBLIC KEY BLOCK", ms.ToArray());
                return (armor, pgpKeyPair.PrivateKey);
            }
        }

        private static string SignDetached(PublicKeyAlgorithmTag algorithm, PgpPrivateKey privateKey, byte[] content)
        {
            var generator = new PgpSignatureGenerator(algorithm, HashAlgorithmTag.Sha256);
            generator.InitSign(PgpSignature.BinaryDocument, privateKey);
            generator.Update(content);
            PgpSignature signature = generator.Generate();

            using (var ms = new MemoryStream())
            {
                signature.Encode(ms);
                return Armor("SIGNATURE", ms.ToArray());
            }
        }

        private static string SignClearsign(PublicKeyAlgorithmTag algorithm, PgpPrivateKey privateKey, string[] lines)
        {
            // No trailing CRLF after the last line - confirmed empirically against a real
            // production signature (see ClearsignCanonicalizer's remarks).
            byte[] canonicalContent = Encoding.UTF8.GetBytes(string.Join("\r\n", lines));

            var generator = new PgpSignatureGenerator(algorithm, HashAlgorithmTag.Sha256);
            generator.InitSign(PgpSignature.CanonicalTextDocument, privateKey);
            generator.Update(canonicalContent);
            PgpSignature signature = generator.Generate();

            using (var ms = new MemoryStream())
            {
                signature.Encode(ms);
                string signatureArmor = Armor("SIGNATURE", ms.ToArray());

                var sb = new StringBuilder();
                sb.Append("-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA256\n\n");
                foreach (string line in lines)
                {
                    // Dash-escape on the wire (RFC 4880 §7.1) - the hash above was computed over
                    // the *unescaped* canonical content, exactly as ClearsignCanonicalizer expects
                    // to reconstruct it after unescaping.
                    string wireLine = line.StartsWith("-", StringComparison.Ordinal) ? "- " + line : line;
                    sb.Append(wireLine).Append('\n');
                }

                sb.Append(signatureArmor);
                return sb.ToString();
            }
        }

        [Fact]
        public void VerifyDetached_WithBouncyCastleRsaSignature_ShouldReturnTrue()
        {
            // Arrange
            (string publicKeyArmor, PgpPrivateKey privateKey) = CreateKeyPair(PublicKeyAlgorithmTag.RsaGeneral, GenerateRsaKeyPair());
            byte[] data = Encoding.UTF8.GetBytes("Scarlet.OpenPgp cross-validation: RSA detached signature.");
            string signatureArmor = SignDetached(PublicKeyAlgorithmTag.RsaGeneral, privateKey, data);

            // Act
            bool result = OpenPgpVerifier.VerifyDetached(data, signatureArmor, publicKeyArmor);

            // Assert
            Assert.True(result);
        }

        [Fact]
        public void VerifyDetached_WithBouncyCastleRsaSignature_AndWrongKey_ShouldReturnFalse()
        {
            // Arrange
            (string publicKeyArmor, PgpPrivateKey privateKey) = CreateKeyPair(PublicKeyAlgorithmTag.RsaGeneral, GenerateRsaKeyPair());
            (string wrongKeyArmor, _) = CreateKeyPair(PublicKeyAlgorithmTag.RsaGeneral, GenerateRsaKeyPair());
            byte[] data = Encoding.UTF8.GetBytes("Scarlet.OpenPgp cross-validation: RSA detached signature.");
            string signatureArmor = SignDetached(PublicKeyAlgorithmTag.RsaGeneral, privateKey, data);

            // Act
            bool result = OpenPgpVerifier.VerifyDetached(data, signatureArmor, wrongKeyArmor);

            // Assert
            Assert.False(result);
            _ = publicKeyArmor;
        }

        [Fact]
        public void VerifyClearsign_WithBouncyCastleRsaSignature_ShouldReturnTrue()
        {
            // Arrange
            (string publicKeyArmor, PgpPrivateKey privateKey) = CreateKeyPair(PublicKeyAlgorithmTag.RsaGeneral, GenerateRsaKeyPair());
            string[] lines = { "Scarlet.OpenPgp cross-validation.", "Second line of the clearsigned message." };
            string clearsignedMessage = SignClearsign(PublicKeyAlgorithmTag.RsaGeneral, privateKey, lines);

            // Act
            bool result = OpenPgpVerifier.VerifyClearsign(clearsignedMessage, publicKeyArmor, out _);

            // Assert
            Assert.True(result);
        }

        [Fact]
        public void VerifyClearsign_WithBouncyCastleRsaSignature_AndTamperedBody_ShouldReturnFalse()
        {
            // Arrange
            (string publicKeyArmor, PgpPrivateKey privateKey) = CreateKeyPair(PublicKeyAlgorithmTag.RsaGeneral, GenerateRsaKeyPair());
            string[] lines = { "Scarlet.OpenPgp cross-validation.", "Second line of the clearsigned message." };
            string clearsignedMessage = SignClearsign(PublicKeyAlgorithmTag.RsaGeneral, privateKey, lines);
            string tampered = clearsignedMessage.Replace("Second line", "Tampered line");

            // Act
            bool result = OpenPgpVerifier.VerifyClearsign(tampered, publicKeyArmor, out _);

            // Assert
            Assert.False(result);
        }

        [Fact]
        public void VerifyDetached_WithBouncyCastleEd25519Signature_ShouldReturnTrue()
        {
            // Arrange
            (string publicKeyArmor, PgpPrivateKey privateKey) = CreateKeyPair(PublicKeyAlgorithmTag.EdDsa, GenerateEd25519KeyPair());
            byte[] data = Encoding.UTF8.GetBytes("Scarlet.OpenPgp cross-validation: Ed25519 detached signature.");
            string signatureArmor = SignDetached(PublicKeyAlgorithmTag.EdDsa, privateKey, data);

            // Act
            bool result = OpenPgpVerifier.VerifyDetached(data, signatureArmor, publicKeyArmor);

            // Assert
            Assert.True(result);
        }

        [Fact]
        public void VerifyClearsign_WithBouncyCastleEd25519Signature_ShouldReturnTrue()
        {
            // Arrange
            (string publicKeyArmor, PgpPrivateKey privateKey) = CreateKeyPair(PublicKeyAlgorithmTag.EdDsa, GenerateEd25519KeyPair());
            string[] lines = { "Scarlet.OpenPgp Ed25519 clearsign cross-validation.", "- a line starting with a dash to exercise escaping." };
            string clearsignedMessage = SignClearsign(PublicKeyAlgorithmTag.EdDsa, privateKey, lines);

            // Act
            bool result = OpenPgpVerifier.VerifyClearsign(clearsignedMessage, publicKeyArmor, out _);

            // Assert
            Assert.True(result);
        }
    }
}
