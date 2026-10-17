using Scarlet.OpenPgp.Crypto.Ed25519;

namespace Scarlet.OpenPgp.Tests.Crypto.Ed25519
{
    public class Ed25519VerifierTests
    {
        public static System.Collections.Generic.IEnumerable<object[]> OfficialRfc8032Vectors()
        {
            // RFC 8032 §7.1 official Ed25519 test vectors (TEST 1, TEST 2, TEST 3, TEST SHA(abc)).
            // These gate the entire Ed25519 implementation per SPEC.md - all must pass before this
            // path is trusted at all.
            yield return new object[]
            {
                "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
                "",
                "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
            };
            yield return new object[]
            {
                "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
                "72",
                "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
            };
            yield return new object[]
            {
                "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
                "af82",
                "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
            };
            yield return new object[]
            {
                "ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf",
                "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
                "dc2a4459e7369633a52b1bf277839a00201009a3efbf3ecb69bea2186c26b58909351fc9ac90b3ecfdfbc7c66431e0303dca179c138ac17ad9bef1177331a704",
            };
        }

        [Theory]
        [MemberData(nameof(OfficialRfc8032Vectors))]
        public void Verify_WithOfficialRfc8032Vectors_ShouldReturnTrue(string publicKeyHex, string messageHex, string signatureHex)
        {
            // Arrange
            var publicKey = new Ed25519PublicKey(System.Convert.FromHexString(publicKeyHex));
            byte[] message = System.Convert.FromHexString(messageHex);
            byte[] signature = System.Convert.FromHexString(signatureHex);

            // Act
            bool result = Ed25519Verifier.Verify(publicKey, message, signature);

            // Assert
            Assert.True(result);
        }

        [Fact]
        public void Verify_WithRealOpenPgpDraftVector_ShouldReturnTrue()
        {
            // Arrange: the draft-koch-eddsa-for-openpgp-04 Appendix A worked example. Critically,
            // EdDSA-in-OpenPGP feeds the SHA-256 *digest* of the signed data as the EdDSA "message" -
            // not the raw document - per the draft's own text ("the resulting digest value is used
            // verbatim as input to the EdDSA algorithm"). This exercises that exact wiring.
            var publicKey = new Ed25519PublicKey(
            [
                0x3f, 0x09, 0x89, 0x94, 0xbd, 0xd9, 0x16, 0xed, 0x40, 0x53, 0x19, 0x79, 0x34, 0xe4, 0xa8, 0x7c,
                0x80, 0x73, 0x3a, 0x12, 0x80, 0xd6, 0x2f, 0x80, 0x10, 0x99, 0x2e, 0x43, 0xee, 0x3b, 0x24, 0x06,
            ]);

            byte[] digest =
            [
                0xf6, 0x22, 0x0a, 0x3f, 0x75, 0x78, 0x14, 0xf4, 0xc2, 0x17, 0x6f, 0xfb, 0xb6, 0x8b, 0x00, 0x24,
                0x9c, 0xd4, 0xcc, 0xdc, 0x05, 0x9c, 0x4b, 0x34, 0xad, 0x87, 0x1f, 0x30, 0xb1, 0x74, 0x02, 0x80,
            ];

            byte[] signature =
            [
                0x56, 0xf9, 0x0c, 0xca, 0x98, 0xe2, 0x10, 0x26, 0x37, 0xbd, 0x98, 0x3f, 0xdb, 0x16, 0xc1, 0x31,
                0xdf, 0xd2, 0x7e, 0xd8, 0x2b, 0xf4, 0xdd, 0xe5, 0x60, 0x6e, 0x0d, 0x75, 0x6a, 0xed, 0x33, 0x66,
                0xd0, 0x9c, 0x4f, 0xa1, 0x15, 0x27, 0xf0, 0x38, 0xe0, 0xf5, 0x7f, 0x22, 0x01, 0xd8, 0x2f, 0x2e,
                0xa2, 0xc9, 0x03, 0x32, 0x65, 0xfa, 0x6c, 0xeb, 0x48, 0x9e, 0x85, 0x4b, 0xae, 0x61, 0xb4, 0x04,
            ];

            // Act
            bool result = Ed25519Verifier.Verify(publicKey, digest, signature);

            // Assert
            Assert.True(result);
        }

        [Fact]
        public void Verify_WithTamperedMessage_ShouldReturnFalse()
        {
            // Arrange
            var publicKey = new Ed25519PublicKey(System.Convert.FromHexString("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"));
            byte[] tamperedMessage = [0x00]; // TEST 1's message was empty; this is not
            byte[] signature = System.Convert.FromHexString(
                "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b");

            // Act
            bool result = Ed25519Verifier.Verify(publicKey, tamperedMessage, signature);

            // Assert
            Assert.False(result);
        }

        [Fact]
        public void Verify_WithWrongPublicKey_ShouldReturnFalse()
        {
            // Arrange: TEST 2's signature checked against TEST 1's public key.
            var wrongPublicKey = new Ed25519PublicKey(System.Convert.FromHexString("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"));
            byte[] message = System.Convert.FromHexString("72");
            byte[] signature = System.Convert.FromHexString(
                "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00");

            // Act
            bool result = Ed25519Verifier.Verify(wrongPublicKey, message, signature);

            // Assert
            Assert.False(result);
        }

        [Fact]
        public void Verify_WithCorruptedSignatureByte_ShouldReturnFalse()
        {
            // Arrange
            var publicKey = new Ed25519PublicKey(System.Convert.FromHexString("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"));
            byte[] message = [];
            byte[] signature = System.Convert.FromHexString(
                "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b");
            signature[0] ^= 0xFF;

            // Act
            bool result = Ed25519Verifier.Verify(publicKey, message, signature);

            // Assert
            Assert.False(result);
        }

        [Fact]
        public void Verify_WithWrongLengthSignature_ShouldReturnFalse()
        {
            // Arrange
            var publicKey = new Ed25519PublicKey(System.Convert.FromHexString("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"));

            // Act
            bool result = Ed25519Verifier.Verify(publicKey, [], new byte[63]);

            // Assert
            Assert.False(result);
        }

        [Fact]
        public void Verify_WithInvalidPublicKeyPoint_ShouldReturnFalse()
        {
            // Arrange: all-0xFF is not a valid compressed Ed25519 point (y >= p).
            var invalidPublicKey = new Ed25519PublicKey(
            [
                0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            ]);
            byte[] signature = new byte[64];

            // Act
            bool result = Ed25519Verifier.Verify(invalidPublicKey, [], signature);

            // Assert
            Assert.False(result);
        }
    }
}
