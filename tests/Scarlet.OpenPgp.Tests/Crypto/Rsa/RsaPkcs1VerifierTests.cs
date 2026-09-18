using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using Scarlet.OpenPgp.Crypto.Rsa;
using Scarlet.OpenPgp.Hashing;
using Scarlet.OpenPgp.Packets;

namespace Scarlet.OpenPgp.Tests.Crypto.Rsa
{
    public class RsaPkcs1VerifierTests
    {
        // Cross-validated against .NET's own built-in RSA implementation (System.Security.Cryptography),
        // used here purely as an independent reference signer - never as a dependency of the
        // shipped library - to confirm this library's from-scratch EMSA-PKCS1-v1_5 padding/DigestInfo
        // check agrees with a trusted implementation.
        private static (RsaPublicKey PublicKey, byte[] Digest, BigInteger Signature) SignWithReferenceRsa(byte[] message)
        {
            using (RSA rsa = RSA.Create(2048))
            {
                byte[] digest = SHA256.HashData(message);
                byte[] signatureBytes = rsa.SignHash(digest, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

                RSAParameters parameters = rsa.ExportParameters(false);
                var publicKey = new RsaPublicKey(Mpi.ToUnsignedBigInteger(parameters.Modulus!), Mpi.ToUnsignedBigInteger(parameters.Exponent!));
                BigInteger signature = Mpi.ToUnsignedBigInteger(signatureBytes);

                return (publicKey, digest, signature);
            }
        }

        [Fact]
        public void Verify_WithReferenceRsaSignature_ShouldReturnTrue()
        {
            // Arrange
            (RsaPublicKey publicKey, byte[] digest, BigInteger signature) = SignWithReferenceRsa(Encoding.ASCII.GetBytes("Scarlet.OpenPgp RSA test message"));

            // Act
            bool result = RsaPkcs1Verifier.Verify(publicKey, HashAlgorithmId.Sha256, digest, signature);

            // Assert
            Assert.True(result);
        }

        [Fact]
        public void Verify_WithTamperedDigest_ShouldReturnFalse()
        {
            // Arrange
            (RsaPublicKey publicKey, byte[] digest, BigInteger signature) = SignWithReferenceRsa(Encoding.ASCII.GetBytes("Scarlet.OpenPgp RSA test message"));
            digest[0] ^= 0xFF;

            // Act
            bool result = RsaPkcs1Verifier.Verify(publicKey, HashAlgorithmId.Sha256, digest, signature);

            // Assert
            Assert.False(result);
        }

        [Fact]
        public void Verify_WithCorruptedSignature_ShouldReturnFalse()
        {
            // Arrange
            (RsaPublicKey publicKey, byte[] digest, BigInteger signature) = SignWithReferenceRsa(Encoding.ASCII.GetBytes("Scarlet.OpenPgp RSA test message"));

            // Act
            bool result = RsaPkcs1Verifier.Verify(publicKey, HashAlgorithmId.Sha256, digest, signature + 1);

            // Assert
            Assert.False(result);
        }

        [Fact]
        public void Verify_WithWrongPublicKey_ShouldReturnFalse()
        {
            // Arrange
            (RsaPublicKey publicKey, byte[] digest, BigInteger signature) = SignWithReferenceRsa(Encoding.ASCII.GetBytes("Scarlet.OpenPgp RSA test message"));
            (RsaPublicKey wrongPublicKey, _, _) = SignWithReferenceRsa(Encoding.ASCII.GetBytes("a different message, different key"));

            // Act
            bool result = RsaPkcs1Verifier.Verify(wrongPublicKey, HashAlgorithmId.Sha256, digest, signature);

            // Assert
            Assert.False(result);
        }

        [Fact]
        public void Verify_WithSignatureNotLessThanModulus_ShouldReturnFalse()
        {
            // Arrange
            (RsaPublicKey publicKey, byte[] digest, _) = SignWithReferenceRsa(Encoding.ASCII.GetBytes("Scarlet.OpenPgp RSA test message"));

            // Act
            bool result = RsaPkcs1Verifier.Verify(publicKey, HashAlgorithmId.Sha256, digest, publicKey.Modulus);

            // Assert
            Assert.False(result);
        }

        [Fact]
        public void Verify_WithMismatchedHashAlgorithm_ShouldReturnFalse()
        {
            // Arrange: signed as SHA-256, but verification asks for the SHA-384 DigestInfo prefix.
            (RsaPublicKey publicKey, byte[] digest, BigInteger signature) = SignWithReferenceRsa(Encoding.ASCII.GetBytes("Scarlet.OpenPgp RSA test message"));

            // Act
            bool result = RsaPkcs1Verifier.Verify(publicKey, HashAlgorithmId.Sha384, digest, signature);

            // Assert
            Assert.False(result);
        }
    }
}
