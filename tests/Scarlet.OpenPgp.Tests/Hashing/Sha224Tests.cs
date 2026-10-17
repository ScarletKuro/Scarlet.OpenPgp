using System.Text;
using Org.BouncyCastle.Crypto.Digests;
using Scarlet.OpenPgp.Hashing;

namespace Scarlet.OpenPgp.Tests.Hashing
{
    public class Sha224Tests
    {
        private static byte[] Compute(byte[] data, int chunkSize, bool allowHardware = true)
        {
            var sha224 = new Sha224(allowHardware);
            for (int offset = 0; offset < data.Length; offset += chunkSize)
            {
                sha224.Update(data, offset, Math.Min(chunkSize, data.Length - offset));
            }

            return sha224.Finish();
        }

        [Theory]
        [InlineData("", "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f")]
        [InlineData("abc", "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7")]
        [InlineData("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", "75388b16512776cc5dba5da1fd890150b0c6455cb4f58b1952522525")]
        public void Finish_WithFips1804Vectors_ShouldMatch(string message, string expectedHex)
        {
            // Act
            byte[] digest = Compute(Encoding.ASCII.GetBytes(message), 64);

            // Assert
            Assert.Equal(expectedHex, Convert.ToHexString(digest).ToLowerInvariant());
        }

        [Fact]
        public void Finish_AcrossBlockBoundariesAndChunkSizes_ShouldMatchBouncyCastle()
        {
            // Arrange: both the portable compression and, where the CPU has it (ARM64), the
            // hardware one - so each CI runner checks whichever paths it can run.
            var random = new Random(224);
            foreach (int length in Enumerable.Range(0, 301).Concat([1000, 4096, 10007]))
            {
                byte[] data = new byte[length];
                random.NextBytes(data);
                var reference = new Sha224Digest();
                reference.BlockUpdate(data, 0, data.Length);
                byte[] expected = new byte[28];
                reference.DoFinal(expected, 0);

                foreach (int chunkSize in new[] { 1, 7, 55, 56, 63, 64, 65, 300, 4096 })
                {
                    foreach (bool allowHardware in new[] { false, true })
                    {
                        // Act
                        byte[] actual = Compute(data, chunkSize, allowHardware);

                        // Assert
                        Assert.Equal(expected, actual);
                    }
                }
            }
        }

        [Theory]
        [InlineData(false)]
        [InlineData(true)]
        public void Finish_WithFips1804VectorsOnEachPath_ShouldMatch(bool allowHardware)
        {
            // Act
            byte[] digest = Compute(Encoding.ASCII.GetBytes("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"), 64, allowHardware);

            // Assert
            Assert.Equal("75388b16512776cc5dba5da1fd890150b0c6455cb4f58b1952522525", Convert.ToHexString(digest).ToLowerInvariant());
        }

        [Fact]
        public void Finish_CalledTwice_ShouldThrow()
        {
            // Arrange
            var sha224 = new Sha224();
            sha224.Finish();

            // Act & Assert
            Assert.Throws<InvalidOperationException>(() => sha224.Finish());
        }

        [Fact]
        public void HashContext_ForSha1_ShouldOnlyBeAvailableForKeySignatures()
        {
            // Act & Assert
            Assert.Throws<Scarlet.OpenPgp.Internal.FailClosedException>(() => HashContext.Create(HashAlgorithmId.Sha1));
            using HashContext context = HashContext.Create(HashAlgorithmId.Sha1, allowSha1: true);
            context.Update("abc"u8.ToArray());
            Assert.Equal("a9993e364706816aba3e25717850c26c9cd0d89d", Convert.ToHexString(context.Finish()).ToLowerInvariant());
        }
    }
}
