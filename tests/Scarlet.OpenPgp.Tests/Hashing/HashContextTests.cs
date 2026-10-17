using Scarlet.OpenPgp.Hashing;
using Scarlet.OpenPgp.Internal;

namespace Scarlet.OpenPgp.Tests.Hashing
{
    public class HashContextTests
    {
        [Fact]
        public void Finish_WithSha256OfAbc_ShouldMatchTheKnownFips1804Vector()
        {
            // Arrange
            using HashContext hash = HashContext.Create(HashAlgorithmId.Sha256);
            hash.Update("abc"u8.ToArray());

            // Act
            byte[] digest = hash.Finish();

            // Assert: FIPS 180-4 short message test vector for SHA-256("abc").
            Assert.Equal("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", System.Convert.ToHexString(digest).ToLowerInvariant());
        }

        [Fact]
        public void Create_WithSha1ForADocumentSignature_ShouldFailClosed()
        {
            // Act & Assert
            Assert.Throws<FailClosedException>(() => HashContext.Create(HashAlgorithmId.Sha1));
        }
    }
}
