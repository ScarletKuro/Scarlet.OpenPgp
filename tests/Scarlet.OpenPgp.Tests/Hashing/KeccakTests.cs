using System.Text;
using Org.BouncyCastle.Crypto.Digests;
using Scarlet.OpenPgp.Hashing;

namespace Scarlet.OpenPgp.Tests.Hashing
{
    public class KeccakTests
    {
        [Theory]
        [InlineData("", "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a")]
        [InlineData("abc", "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532")]
        public void Sha3_256_WithNistExampleMessages_ShouldMatchPublishedDigests(string message, string expectedHex)
        {
            // Arrange: NIST CSRC "Examples with Intermediate Values" for SHA3-256 (0-bit and "abc").
            byte[] data = Encoding.ASCII.GetBytes(message);

            // Act
            byte[] digest = KeccakHash.Sha3_256(data);

            // Assert
            Assert.Equal(expectedHex, ToHex(digest));
        }

        [Theory]
        [InlineData("", "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26")]
        [InlineData("abc", "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0")]
        public void Sha3_512_WithNistExampleMessages_ShouldMatchPublishedDigests(string message, string expectedHex)
        {
            // Arrange: NIST CSRC "Examples with Intermediate Values" for SHA3-512 (0-bit and "abc").
            byte[] data = Encoding.ASCII.GetBytes(message);

            // Act
            byte[] digest = KeccakHash.Sha3_512(data);

            // Assert
            Assert.Equal(expectedHex, ToHex(digest));
        }

        [Fact]
        public void Shake256_WithEmptyMessageAnd256ByteOutput_ShouldMatchPublishedAndBouncyCastleOutput()
        {
            // Arrange: 256 bytes spans two squeeze blocks (rate 136), so this exercises the
            // permutation between output blocks. The first 64 bytes are the widely published
            // SHAKE256("", 512 bits) value; the full 256 bytes were computed with BouncyCastle's
            // ShakeDigest(256) and agree with that published prefix.
            const string expectedHex =
                "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f" +
                "d75dc4ddd8c0f200cb05019d67b592f6fc821c49479ab48640292eacb3b7c4be" +
                "141e96616fb13957692cc7edd0b45ae3dc07223c8e92937bef84bc0eab862853" +
                "349ec75546f58fb7c2775c38462c5010d846c185c15111e595522a6bcd16cf86" +
                "f3d122109e3b1fdd943b6aec468a2d621a7c06c6a957c62b54dafc3be87567d6" +
                "77231395f6147293b68ceab7a9e0c58d864e8efde4e1b9a46cbe854713672f5c" +
                "aaae314ed9083dab4b099f8e300f01b8650f1f4b1d8fcf3f3cb53fb8e9eb2ea2" +
                "03bdc970f50ae55428a91f7f53ac266b28419c3778a15fd248d339ede785fb7f";

            // Act
            byte[] output = KeccakHash.Shake256([], 256);

            // Assert
            Assert.Equal(expectedHex, ToHex(output));
            Assert.Equal(ToHex(BouncyCastleShake256([], 256)), ToHex(output));
        }

        [Fact]
        public void Shake256_WithZeroOutputLength_ShouldReturnEmptyArray()
        {
            // Act
            byte[] output = KeccakHash.Shake256("abc"u8.ToArray(), 0);

            // Assert
            Assert.Empty(output);
        }

        [Fact]
        public void Shake256_WithShorterOutputLength_ShouldBeAPrefixOfLongerOutput()
        {
            // Arrange
            byte[] data = "abc"u8.ToArray();

            // Act
            byte[] shortOutput = KeccakHash.Shake256(data, 57);
            byte[] longOutput = KeccakHash.Shake256(data, 500);

            // Assert: SHAKE is an XOF - the output length does not affect the stream itself.
            Assert.Equal(ToHex(shortOutput), ToHex(longOutput).Substring(0, 57 * 2));
        }

        [Fact]
        public void Sha3_256_WithAllLengthsAcrossBlockBoundaries_ShouldMatchBouncyCastle()
        {
            for (int length = 0; length <= 300; length++)
            {
                // Arrange
                byte[] data = DeterministicBytes(length, seed: length);

                // Act
                byte[] digest = KeccakHash.Sha3_256(data);

                // Assert
                Assert.True(ToHex(BouncyCastleSha3(256, data)) == ToHex(digest), "SHA3-256 mismatch at length " + length);
            }
        }

        [Fact]
        public void Sha3_512_WithAllLengthsAcrossBlockBoundaries_ShouldMatchBouncyCastle()
        {
            for (int length = 0; length <= 300; length++)
            {
                // Arrange
                byte[] data = DeterministicBytes(length, seed: 1000 + length);

                // Act
                byte[] digest = KeccakHash.Sha3_512(data);

                // Assert
                Assert.True(ToHex(BouncyCastleSha3(512, data)) == ToHex(digest), "SHA3-512 mismatch at length " + length);
            }
        }

        [Fact]
        public void Shake256_WithAllLengthsAcrossBlockBoundaries_ShouldMatchBouncyCastle()
        {
            int[] outputLengths = [1, 32, 114, 135, 136, 137, 272, 300];
            for (int length = 0; length <= 300; length++)
            {
                // Arrange
                byte[] data = DeterministicBytes(length, seed: 2000 + length);
                int outputLength = outputLengths[length % outputLengths.Length];

                // Act
                byte[] output = KeccakHash.Shake256(data, outputLength);

                // Assert
                Assert.True(
                    ToHex(BouncyCastleShake256(data, outputLength)) == ToHex(output),
                    "SHAKE256 mismatch at input length " + length + ", output length " + outputLength);
            }
        }

        [Fact]
        public void Update_WithOddChunkSizes_ShouldMatchOneShotAndBouncyCastle()
        {
            // Arrange: chunk sizes chosen to straddle the 72- and 136-byte rates in every alignment.
            byte[] data = DeterministicBytes(1500, seed: 42);
            int[] chunkSizes = [1, 2, 3, 5, 7, 13, 71, 72, 73, 135, 136, 137, 271, 500];

            foreach (int chunkSize in chunkSizes)
            {
                KeccakHash sha256 = KeccakHash.CreateSha3_256();
                KeccakHash sha512 = KeccakHash.CreateSha3_512();
                KeccakHash shake = KeccakHash.CreateShake256(300);

                // Act
                for (int offset = 0; offset < data.Length; offset += chunkSize)
                {
                    int count = System.Math.Min(chunkSize, data.Length - offset);
                    sha256.Update(data, offset, count);
                    sha512.Update(data, offset, count);
                    shake.Update(data, offset, count);
                }

                // Assert
                Assert.True(ToHex(BouncyCastleSha3(256, data)) == ToHex(sha256.Finish()), "SHA3-256 mismatch with chunk size " + chunkSize);
                Assert.True(ToHex(BouncyCastleSha3(512, data)) == ToHex(sha512.Finish()), "SHA3-512 mismatch with chunk size " + chunkSize);
                Assert.True(ToHex(BouncyCastleShake256(data, 300)) == ToHex(shake.Finish()), "SHAKE256 mismatch with chunk size " + chunkSize);
            }
        }

        [Fact]
        public void Update_WithZeroCountAndNonZeroOffset_ShouldBeANoOp()
        {
            // Arrange
            byte[] data = "abc"u8.ToArray();
            KeccakHash hash = KeccakHash.CreateSha3_256();

            // Act
            hash.Update(data, 3, 0);
            hash.Update(data, 0, 3);
            byte[] digest = hash.Finish();

            // Assert
            Assert.Equal("3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532", ToHex(digest));
        }

        [Fact]
        public void Finish_WhenCalledTwice_ShouldThrowInvalidOperationException()
        {
            // Arrange
            KeccakHash hash = KeccakHash.CreateSha3_256();
            hash.Finish();

            // Act & Assert
            Assert.Throws<System.InvalidOperationException>(() => hash.Finish());
        }

        [Fact]
        public void Update_AfterFinish_ShouldThrowInvalidOperationException()
        {
            // Arrange
            KeccakHash hash = KeccakHash.CreateShake256(64);
            hash.Finish();

            // Act & Assert
            Assert.Throws<System.InvalidOperationException>(() => hash.Update(new byte[1], 0, 1));
        }

        [Theory]
        [InlineData(-1, 1)]
        [InlineData(0, -1)]
        [InlineData(0, 4)]
        [InlineData(3, 1)]
        [InlineData(4, 0)]
        public void Update_WithOutOfRangeOffsetOrCount_ShouldThrowArgumentOutOfRangeException(int offset, int count)
        {
            // Arrange
            KeccakHash hash = KeccakHash.CreateSha3_256();

            // Act & Assert
            Assert.Throws<System.ArgumentOutOfRangeException>(() => hash.Update(new byte[3], offset, count));
        }

        [Fact]
        public void CreateShake256_WithNegativeOutputLength_ShouldThrowArgumentOutOfRangeException()
        {
            // Act & Assert
            Assert.Throws<System.ArgumentOutOfRangeException>(() => KeccakHash.CreateShake256(-1));
        }

        private static byte[] BouncyCastleSha3(int bitLength, byte[] data)
        {
            var digest = new Sha3Digest(bitLength);
            digest.BlockUpdate(data, 0, data.Length);
            var output = new byte[digest.GetDigestSize()];
            digest.DoFinal(output, 0);
            return output;
        }

        private static byte[] BouncyCastleShake256(byte[] data, int outputLength)
        {
            var digest = new ShakeDigest(256);
            digest.BlockUpdate(data, 0, data.Length);
            var output = new byte[outputLength];
            digest.OutputFinal(output, 0, outputLength);
            return output;
        }

        private static byte[] DeterministicBytes(int length, int seed)
        {
            var bytes = new byte[length];
            new System.Random(seed).NextBytes(bytes);
            return bytes;
        }

        private static string ToHex(byte[] bytes) => System.Convert.ToHexString(bytes).ToLowerInvariant();
    }
}
