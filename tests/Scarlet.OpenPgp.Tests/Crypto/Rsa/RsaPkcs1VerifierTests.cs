using System.Numerics;
using System.Security.Cryptography;
using Scarlet.OpenPgp.Crypto.Rsa;
using Scarlet.OpenPgp.Hashing;
using Scarlet.OpenPgp.Internal;
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
            using RSA rsa = RSA.Create(2048);
            byte[] digest = SHA256.HashData(message);
            byte[] signatureBytes = rsa.SignHash(digest, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

            RSAParameters parameters = rsa.ExportParameters(false);
            Assert.NotNull(parameters.Modulus);
            Assert.NotNull(parameters.Exponent);
            var publicKey = new RsaPublicKey(Mpi.ToUnsignedBigInteger(parameters.Modulus), Mpi.ToUnsignedBigInteger(parameters.Exponent));
            BigInteger signature = Mpi.ToUnsignedBigInteger(signatureBytes);

            return (publicKey, digest, signature);
        }

        [Fact]
        public void Verify_WithReferenceRsaSignature_ShouldReturnTrue()
        {
            // Arrange
            (RsaPublicKey publicKey, byte[] digest, BigInteger signature) = SignWithReferenceRsa("Scarlet.OpenPgp RSA test message"u8.ToArray());

            // Act
            bool result = RsaPkcs1Verifier.Verify(publicKey, HashAlgorithmId.Sha256, digest, signature);

            // Assert
            Assert.True(result);
        }

        [Fact]
        public void Verify_WithTamperedDigest_ShouldReturnFalse()
        {
            // Arrange
            (RsaPublicKey publicKey, byte[] digest, BigInteger signature) = SignWithReferenceRsa("Scarlet.OpenPgp RSA test message"u8.ToArray());
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
            (RsaPublicKey publicKey, byte[] digest, BigInteger signature) = SignWithReferenceRsa("Scarlet.OpenPgp RSA test message"u8.ToArray());

            // Act
            bool result = RsaPkcs1Verifier.Verify(publicKey, HashAlgorithmId.Sha256, digest, signature + 1);

            // Assert
            Assert.False(result);
        }

        [Fact]
        public void Verify_WithWrongPublicKey_ShouldReturnFalse()
        {
            // Arrange
            (_, byte[] digest, BigInteger signature) = SignWithReferenceRsa("Scarlet.OpenPgp RSA test message"u8.ToArray());
            (RsaPublicKey wrongPublicKey, _, _) = SignWithReferenceRsa("a different message, different key"u8.ToArray());

            // Act
            bool result = RsaPkcs1Verifier.Verify(wrongPublicKey, HashAlgorithmId.Sha256, digest, signature);

            // Assert
            Assert.False(result);
        }

        [Fact]
        public void Verify_WithSignatureNotLessThanModulus_ShouldReturnFalse()
        {
            // Arrange
            (RsaPublicKey publicKey, byte[] digest, _) = SignWithReferenceRsa("Scarlet.OpenPgp RSA test message"u8.ToArray());

            // Act
            bool result = RsaPkcs1Verifier.Verify(publicKey, HashAlgorithmId.Sha256, digest, publicKey.Modulus);

            // Assert
            Assert.False(result);
        }

        [Fact]
        public void Verify_WithMismatchedHashAlgorithm_ShouldReturnFalse()
        {
            // Arrange: signed as SHA-256, but verification asks for the SHA-384 DigestInfo prefix.
            (RsaPublicKey publicKey, byte[] digest, BigInteger signature) = SignWithReferenceRsa("Scarlet.OpenPgp RSA test message"u8.ToArray());

            // Act
            bool result = RsaPkcs1Verifier.Verify(publicKey, HashAlgorithmId.Sha384, digest, signature);

            // Assert
            Assert.False(result);
        }

        [Fact]
        public void RsaPublicKey_WithModulusBelow2048Bits_ShouldFailClosed()
        {
            // Arrange
            using RSA rsa = RSA.Create(1024);
            RSAParameters parameters = rsa.ExportParameters(false);
            Assert.NotNull(parameters.Modulus);
            Assert.NotNull(parameters.Exponent);
            BigInteger modulus = Mpi.ToUnsignedBigInteger(parameters.Modulus);
            BigInteger exponent = Mpi.ToUnsignedBigInteger(parameters.Exponent);

            // Act & Assert
            Assert.Throws<FailClosedException>(() => new RsaPublicKey(modulus, exponent));
        }

        [Theory]
        [InlineData(1)] // signature == encoded message: trivially forgeable
        [InlineData(0)]
        [InlineData(65538)] // even
        public void RsaPublicKey_WithInvalidExponent_ShouldFailClosed(int exponent)
        {
            // Arrange
            using RSA rsa = RSA.Create(2048);
            byte[]? modulusBytes = rsa.ExportParameters(false).Modulus;
            Assert.NotNull(modulusBytes);
            BigInteger modulus = Mpi.ToUnsignedBigInteger(modulusBytes);

            // Act & Assert
            Assert.Throws<FailClosedException>(() => new RsaPublicKey(modulus, exponent));
        }

        [Fact]
        public void RsaPublicKey_WithEvenModulus_ShouldFailClosed()
        {
            // Arrange
            BigInteger evenModulus = BigInteger.One << 2048;

            // Act & Assert
            Assert.Throws<FailClosedException>(() => new RsaPublicKey(evenModulus, 65537));
        }
        [Fact]
        public void RsaPublicKey_WithAnExponentOver32Bits_ShouldBeUnsupported()
        {
            // Arrange: real keys use 65537, 17 or 3; a large exponent only makes every check slower.
            BigInteger modulus = (BigInteger.One << 2047) + 1;
            BigInteger exponent = (BigInteger.One << 32) + 1;

            // Act
            FailClosedException ex = Assert.Throws<FailClosedException>(() => new RsaPublicKey(modulus, exponent));

            // Assert
            Assert.True(ex.IsUnsupported);
        }

        [Fact]
        public void Verify_WithASignatureFarShorterThanTheModulus_ShouldReturnFalse()
        {
            // Arrange: a genuine signature value with its top 72 bits cleared - something a real
            // signature is with probability 2^-72, and a cheap way to buy a full exponentiation.
            (RsaPublicKey publicKey, byte[] digest, BigInteger signature) = SignWithReferenceRsa("Scarlet.OpenPgp RSA test message"u8.ToArray());
            BigInteger shortened = signature & ((BigInteger.One << (publicKey.ModulusBitLength - 72)) - 1);

            // Act
            bool result = RsaPkcs1Verifier.Verify(publicKey, HashAlgorithmId.Sha256, digest, shortened);

            // Assert
            Assert.False(result);
        }
    }
}
