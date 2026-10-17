using System.Text;
using Scarlet.OpenPgp.Hashing;
using Scarlet.OpenPgp.Internal;

namespace Scarlet.OpenPgp.Tests.Hashing
{
    public class OpenPgpHashTests
    {
        [Fact]
        public void ComputeHash_WithSha256OfAbc_ShouldMatchTheKnownFips1804Vector()
        {
            // Arrange
            byte[] data = "abc"u8.ToArray();

            // Act
            byte[] hash = OpenPgpHash.ComputeHash(HashAlgorithmId.Sha256, data);

            // Assert: FIPS 180-4 short message test vector for SHA-256("abc").
            Assert.Equal("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", System.Convert.ToHexString(hash).ToLowerInvariant());
        }

        [Fact]
        public void ComputeHash_WithUnsupportedAlgorithm_ShouldFailClosed()
        {
            // Arrange
            byte[] data = "abc"u8.ToArray();

            // Act & Assert
            Assert.Throws<FailClosedException>(() => OpenPgpHash.ComputeHash(HashAlgorithmId.Sha1, data));
        }
    }
}
