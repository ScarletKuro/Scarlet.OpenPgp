using System.Numerics;
using Scarlet.OpenPgp.Crypto.Ed25519;
using Scarlet.OpenPgp.Crypto.Ed448;

namespace Scarlet.OpenPgp.Tests.Crypto
{
    /// <summary>
    /// Regression: Edwards public keys of small order (the identity and the other low-order points)
    /// make the verification equation independent of the message, so R = identity, S = 0 used to
    /// "verify" anything - no private key needed. Such keys must be rejected outright.
    /// </summary>
    public class SmallOrderKeyTests
    {
        private static readonly byte[] Message = "any message at all"u8.ToArray();

        private static byte[] LittleEndian(BigInteger value, int length)
        {
            byte[] bytes = new byte[length];
            byte[] raw = value.ToByteArray();
            Array.Copy(raw, bytes, Math.Min(raw.Length, length));
            return bytes;
        }

        /// <summary>Ed25519 points of order 1, 2 and 4: y = 1 (identity), y = p - 1 (the point (0, -1)), and y = 0 (x = sqrt(-1)).</summary>
        public static TheoryData<string> Ed25519SmallOrderPoints => new TheoryData<string>
        {
            Convert.ToHexString(LittleEndian(BigInteger.One, 32)),
            Convert.ToHexString(LittleEndian(BigInteger.Pow(2, 255) - 19 - 1, 32)),
            Convert.ToHexString(new byte[32]),
        };

        /// <summary>Ed448 points of order 1, 2 and 4: y = 1 (identity), y = p - 1 (the point (0, -1)), and y = 0 (x = 1).</summary>
        public static TheoryData<string> Ed448SmallOrderPoints => new TheoryData<string>
        {
            Convert.ToHexString(LittleEndian(BigInteger.One, 57)),
            Convert.ToHexString(LittleEndian(BigInteger.Pow(2, 448) - BigInteger.Pow(2, 224) - 1 - 1, 57)),
            Convert.ToHexString(new byte[57]),
        };

        [Theory]
        [MemberData(nameof(Ed25519SmallOrderPoints))]
        public void Ed25519_WithASmallOrderPublicKey_ShouldRejectTheTrivialForgery(string publicKeyHex)
        {
            // Arrange: R = identity, S = 0.
            byte[] signature = new byte[64];
            signature[0] = 1;

            // Act
            bool result = Ed25519Verifier.Verify(new Ed25519PublicKey(Convert.FromHexString(publicKeyHex)), Message, signature);

            // Assert
            Assert.False(result);
        }

        [Theory]
        [MemberData(nameof(Ed448SmallOrderPoints))]
        public void Ed448_WithASmallOrderPublicKey_ShouldRejectTheTrivialForgery(string publicKeyHex)
        {
            // Arrange: R = identity, S = 0.
            byte[] signature = new byte[114];
            signature[0] = 1;

            // Act
            bool result = Ed448Verifier.Verify(Convert.FromHexString(publicKeyHex), Message, signature);

            // Assert
            Assert.False(result);
        }

        [Fact]
        public void PublicApi_WithAnIdentityPointEd25519Key_ShouldNotVerifyAForgedSignature()
        {
            // Arrange: a v4 native Ed25519 (alg 27) key whose point is the identity, and a document
            // signature with R = identity, S = 0 and a correct quick-check - built without any
            // private key.
            byte[] created = [0x67, 0x74, 0xC4, 0x00]; // 2025-01-01T00:00:00Z
            byte[] identity = new byte[32];
            identity[0] = 1;
            byte[] keyBody = [0x04, .. created, 27, .. identity];

            byte[] hashed = [0x04, 0x00, 27, 8, 0x00, 0x06, 0x05, 0x02, .. created];
            byte[] digest = System.Security.Cryptography.SHA256.HashData([.. Message, .. hashed, 0x04, 0xFF, 0x00, 0x00, 0x00, (byte)hashed.Length]);
            byte[] forgedValue = new byte[64];
            forgedValue[0] = 1;
            byte[] signatureBody = [.. hashed, 0x00, 0x00, digest[0], digest[1], .. forgedValue];

            byte[] keyPacket = [0xC6, (byte)keyBody.Length, .. keyBody];
            byte[] signaturePacket = [0xC2, (byte)signatureBody.Length, .. signatureBody];

            // Act
            VerificationResult result = OpenPgpVerifier.VerifyDetached(Message, signaturePacket, keyPacket, new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero));

            // Assert
            Assert.False(result.IsValid);
            Assert.Equal(VerificationStatus.BadSignature, result.Status);
        }
    }
}
