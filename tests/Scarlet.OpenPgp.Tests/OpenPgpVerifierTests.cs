using System;
using System.Text;
using Scarlet.OpenPgp.Armor;

namespace Scarlet.OpenPgp.Tests
{
    public class OpenPgpVerifierTests
    {
        /// <summary>
        /// Acceptance test per SPEC.md's Testing Requirements §5: verify against a real upstream
        /// project's actual release signature (Bun's SHASUMS256.txt + SHASUMS256.txt.asc, the
        /// original motivating example for this whole project - Ed25519, clearsigned).
        /// SHASUMS256.txt and SHASUMS256.txt.asc are Bun v1.4.2's real release artifacts, downloaded
        /// via `gh release download`. bun-public-key.asc is Bun's real signing key ("Robobun
        /// &lt;robobun@oven.sh&gt;", fingerprint F3DC C08A 8572 C074 9B3E 1888 8EAB 4D40 A7B2 2B59),
        /// fetched from keys.openpgp.org by the exact fingerprint this signature's own
        /// IssuerFingerprint subpacket names. Cross-checked against real `gpg --verify` (GnuPG
        /// 2.4.9) on the same two files, which reports "Good signature from Robobun
        /// &lt;robobun@oven.sh&gt;" - matching this library's result.
        /// </summary>
        [Fact]
        public void VerifyClearsign_AgainstRealBunReleaseSignature_ShouldSucceed()
        {
            // Arrange
            string clearsignedMessage = System.IO.File.ReadAllText("TestAssets/bun-release/SHASUMS256.txt.asc");
            string publicKeyArmor = System.IO.File.ReadAllText("TestAssets/bun-release/bun-public-key.asc");

            string expectedSignedText = System.IO.File.ReadAllText("TestAssets/bun-release/SHASUMS256.txt");

            // Act
            VerificationResult result = OpenPgpVerifier.VerifyClearsign(clearsignedMessage, publicKeyArmor);

            // Assert: the returned text is exactly the original SHASUMS256.txt, CRLF-separated.
            Assert.True(result.IsValid, result.ToString());
            Assert.Equal(VerificationStatus.Valid, result.Status);
            Assert.Equal("F3DCC08A8572C0749B3E18888EAB4D40A7B22B59", result.PrimaryKeyFingerprint);
            Assert.NotNull(result.SignedText);
            Assert.Equal(expectedSignedText.Replace("\r\n", "\n"), result.SignedText!.Replace("\r\n", "\n"));
            Assert.DoesNotContain("PGP", result.SignedText);
        }

        private const string InjectedLine = "deadbeef00000000000000000000000000000000000000000000000000000000  bun-linux-x64.zip";

        /// <summary>
        /// Regression: unsigned text placed around a genuine clearsigned message (or among its armor
        /// headers) used to verify, so a caller grepping the .asc for a checksum would trust it.
        /// </summary>
        [Theory]
        [InlineData("prefix")]
        [InlineData("suffix")]
        [InlineData("header")]
        public void VerifyClearsign_WithUnsignedTextInjectedAroundTheRealBunMessage_ShouldReturnFalse(string where)
        {
            // Arrange
            string original = System.IO.File.ReadAllText("TestAssets/bun-release/SHASUMS256.txt.asc").Replace("\r\n", "\n");
            string publicKeyArmor = System.IO.File.ReadAllText("TestAssets/bun-release/bun-public-key.asc");
            string tampered = where switch
            {
                "prefix" => InjectedLine + "\n" + original,
                "suffix" => original + InjectedLine + "\n",
                _ => original.Replace("Hash: SHA512\n", "Hash: SHA512\nInjected: " + InjectedLine + "\n"),
            };
            Assert.NotEqual(original, tampered);

            // Act
            VerificationResult result = OpenPgpVerifier.VerifyClearsign(tampered, publicKeyArmor);

            // Assert
            Assert.False(result.IsValid);
            Assert.Equal(VerificationStatus.MalformedInput, result.Status);
            Assert.Null(result.SignedText);
        }

        [Fact]
        public void VerifyClearsign_WithAWellFormedHashHeaderNamingADifferentAlgorithm_ShouldIgnoreIt()
        {
            // Arrange: Bun's signature uses SHA-512. RFC 9580 §6.2.2.3: a conformant Hash header's
            // contents MUST be ignored in favor of the signature's own hash algorithm.
            string original = System.IO.File.ReadAllText("TestAssets/bun-release/SHASUMS256.txt.asc").Replace("\r\n", "\n");
            string publicKeyArmor = System.IO.File.ReadAllText("TestAssets/bun-release/bun-public-key.asc");
            string relabeled = original.Replace("Hash: SHA512\n", "Hash: SHA256\n");

            // Act
            VerificationResult result = OpenPgpVerifier.VerifyClearsign(relabeled, publicKeyArmor);

            // Assert
            Assert.True(result.IsValid, result.ToString());
        }

        [Fact]
        public void VerifyClearsign_WithANonConformantHashHeader_ShouldReturnMalformedInput()
        {
            // Arrange: RFC 9580 §6.2.2.3 - decline anything but a list of known hash names.
            string original = System.IO.File.ReadAllText("TestAssets/bun-release/SHASUMS256.txt.asc").Replace("\r\n", "\n");
            string publicKeyArmor = System.IO.File.ReadAllText("TestAssets/bun-release/bun-public-key.asc");
            string tampered = original.Replace("Hash: SHA512\n", "Hash: SHA512 bun-linux-x64.zip\n");

            // Act
            VerificationResult result = OpenPgpVerifier.VerifyClearsign(tampered, publicKeyArmor);

            // Assert
            Assert.Equal(VerificationStatus.MalformedInput, result.Status);
        }

        [Fact]
        public void VerifyDetached_WithAKeyThatNeverExpires_ShouldVerifyAtAnyLaterTime()
        {
            // Arrange: the draft vector's key has no self-signature, so it never expires; the
            // signature (created 2015-09-16) has no expiration either - any clock verifies.
            byte[] data = Encoding.ASCII.GetBytes("OpenPGP");

            // Act
            bool result = OpenPgpVerifier.VerifyDetached(data, SignatureArmor, PublicKeyArmor, new DateTimeOffset(2100, 1, 1, 0, 0, 0, TimeSpan.Zero)).IsValid;

            // Assert
            Assert.True(result);
        }

        private static string Armor(string label, byte[] body)
        {
            int crc = Crc24.Compute(body);
            byte[] crcBytes = { (byte)(crc >> 16), (byte)(crc >> 8), (byte)crc };
            return "-----BEGIN PGP " + label + "-----\n"
                   + "\n"
                   + Convert.ToBase64String(body) + "\n"
                   + "=" + Convert.ToBase64String(crcBytes) + "\n"
                   + "-----END PGP " + label + "-----\n";
        }

        // The full worked example from draft-koch-eddsa-for-openpgp-04 Appendix A, wrapped as ASCII
        // armor: a real v4 Ed25519 public key and a real signature over the literal binary-document
        // message "OpenPGP" - an authoritative, independent-of-this-library end-to-end fixture that
        // needs no external tooling (BouncyCastle) to generate.
        private static readonly byte[] Ed25519PublicKeyPacketBytes =
        {
            0x98, 0x33, 0x04, 0x53, 0xf3, 0x5f, 0x0b, 0x16, 0x09, 0x2b, 0x06, 0x01, 0x04, 0x01, 0xda, 0x47,
            0x0f, 0x01, 0x01, 0x07, 0x40, 0x3f, 0x09, 0x89, 0x94, 0xbd, 0xd9, 0x16, 0xed, 0x40, 0x53, 0x19,
            0x79, 0x34, 0xe4, 0xa8, 0x7c, 0x80, 0x73, 0x3a, 0x12, 0x80, 0xd6, 0x2f, 0x80, 0x10, 0x99, 0x2e,
            0x43, 0xee, 0x3b, 0x24, 0x06,
        };

        private static readonly byte[] Ed25519SignaturePacketBytes =
        {
            0x88, 0x5e, 0x04, 0x00, 0x16, 0x08, 0x00, 0x06, 0x05, 0x02, 0x55, 0xf9, 0x5f, 0x95, 0x00, 0x0a,
            0x09, 0x10, 0x8c, 0xfd, 0xe1, 0x21, 0x97, 0x96, 0x5a, 0x9a, 0xf6, 0x22, 0x01, 0x00, 0x56, 0xf9,
            0x0c, 0xca, 0x98, 0xe2, 0x10, 0x26, 0x37, 0xbd, 0x98, 0x3f, 0xdb, 0x16, 0xc1, 0x31, 0xdf, 0xd2,
            0x7e, 0xd8, 0x2b, 0xf4, 0xdd, 0xe5, 0x60, 0x6e, 0x0d, 0x75, 0x6a, 0xed, 0x33, 0x66, 0x01, 0x00,
            0xd0, 0x9c, 0x4f, 0xa1, 0x15, 0x27, 0xf0, 0x38, 0xe0, 0xf5, 0x7f, 0x22, 0x01, 0xd8, 0x2f, 0x2e,
            0xa2, 0xc9, 0x03, 0x32, 0x65, 0xfa, 0x6c, 0xeb, 0x48, 0x9e, 0x85, 0x4b, 0xae, 0x61, 0xb4, 0x04,
        };

        private static readonly string PublicKeyArmor = Armor("PUBLIC KEY BLOCK", Ed25519PublicKeyPacketBytes);
        private static readonly string SignatureArmor = Armor("SIGNATURE", Ed25519SignaturePacketBytes);

        [Fact]
        public void VerifyDetached_WithRealEd25519DraftVector_ShouldReturnTrue()
        {
            // Arrange
            byte[] data = Encoding.ASCII.GetBytes("OpenPGP");

            // Act
            bool result = OpenPgpVerifier.VerifyDetached(data, SignatureArmor, PublicKeyArmor).IsValid;

            // Assert
            Assert.True(result);
        }

        [Fact]
        public void VerifyDetached_WithTamperedData_ShouldReturnFalse()
        {
            // Arrange
            byte[] data = Encoding.ASCII.GetBytes("OpenPGX");

            // Act
            bool result = OpenPgpVerifier.VerifyDetached(data, SignatureArmor, PublicKeyArmor).IsValid;

            // Assert
            Assert.False(result);
        }

        [Fact]
        public void VerifyDetached_WithTamperedLeftHashBytes_ShouldReturnFalse()
        {
            // Arrange: the two-byte quick-check field (index 26-27 in the raw packet: f6 22) isn't
            // itself signed material, but a mismatch against the real digest must still fail closed
            // rather than being silently ignored in favor of the (otherwise-valid) asymmetric check.
            byte[] tamperedSignaturePacket = (byte[])Ed25519SignaturePacketBytes.Clone();
            tamperedSignaturePacket[26] ^= 0xFF;
            string tamperedSignatureArmor = Armor("SIGNATURE", tamperedSignaturePacket);
            byte[] data = Encoding.ASCII.GetBytes("OpenPGP");

            // Act
            bool result = OpenPgpVerifier.VerifyDetached(data, tamperedSignatureArmor, PublicKeyArmor).IsValid;

            // Assert
            Assert.False(result);
        }

        [Fact]
        public void VerifyDetached_WithTwoSignaturePacketsInTheArmorBlock_ShouldVerifyEither()
        {
            // Arrange: a detached signature may hold several signatures (e.g. several release
            // managers signing the same file); any one valid signature by a supplied key suffices.
            byte[] doubled = new byte[Ed25519SignaturePacketBytes.Length * 2];
            Array.Copy(Ed25519SignaturePacketBytes, 0, doubled, 0, Ed25519SignaturePacketBytes.Length);
            Array.Copy(Ed25519SignaturePacketBytes, 0, doubled, Ed25519SignaturePacketBytes.Length, Ed25519SignaturePacketBytes.Length);
            string doubledSignatureArmor = Armor("SIGNATURE", doubled);
            byte[] data = Encoding.ASCII.GetBytes("OpenPGP");

            // Act
            bool result = OpenPgpVerifier.VerifyDetached(data, doubledSignatureArmor, PublicKeyArmor).IsValid;

            // Assert
            Assert.True(result);
        }

        [Fact]
        public void VerifyDetached_WithANonSignaturePacketInTheSignatureInput_ShouldReturnMalformedInput()
        {
            // Arrange: the signature followed by the public key packet - signature input holds
            // signatures only.
            byte[] mixed = new byte[Ed25519SignaturePacketBytes.Length + Ed25519PublicKeyPacketBytes.Length];
            Array.Copy(Ed25519SignaturePacketBytes, 0, mixed, 0, Ed25519SignaturePacketBytes.Length);
            Array.Copy(Ed25519PublicKeyPacketBytes, 0, mixed, Ed25519SignaturePacketBytes.Length, Ed25519PublicKeyPacketBytes.Length);
            byte[] data = Encoding.ASCII.GetBytes("OpenPGP");

            // Act
            VerificationResult result = OpenPgpVerifier.VerifyDetached(data, Armor("SIGNATURE", mixed), PublicKeyArmor);

            // Assert
            Assert.Equal(VerificationStatus.MalformedInput, result.Status);
        }

        [Fact]
        public void VerifyDetached_WithWrongPublicKey_ShouldReturnFalse()
        {
            // Arrange: flip a byte in the public key's point material.
            byte[] tamperedKey = (byte[])Ed25519PublicKeyPacketBytes.Clone();
            tamperedKey[25] ^= 0xFF;
            string wrongKeyArmor = Armor("PUBLIC KEY BLOCK", tamperedKey);
            byte[] data = Encoding.ASCII.GetBytes("OpenPGP");

            // Act
            bool result = OpenPgpVerifier.VerifyDetached(data, SignatureArmor, wrongKeyArmor).IsValid;

            // Assert
            Assert.False(result);
        }

        [Fact]
        public void VerifyDetached_WithPublicKeyArmorUnderTheWrongLabel_ShouldReturnFalse()
        {
            // Arrange: a real, otherwise-valid public key packet, but wrapped under a "SIGNATURE"
            // armor label instead of "PUBLIC KEY BLOCK" - the label must be checked, not just
            // whatever packet type happens to be found inside.
            string mislabeledKeyArmor = Armor("SIGNATURE", Ed25519PublicKeyPacketBytes);
            byte[] data = Encoding.ASCII.GetBytes("OpenPGP");

            // Act
            bool result = OpenPgpVerifier.VerifyDetached(data, SignatureArmor, mislabeledKeyArmor).IsValid;

            // Assert
            Assert.False(result);
        }

        [Fact]
        public void VerifyDetached_WithGarbageSignatureArmor_ShouldReturnFalseNotThrow()
        {
            // Arrange
            byte[] data = Encoding.ASCII.GetBytes("OpenPGP");

            // Act
            bool result = OpenPgpVerifier.VerifyDetached(data, "not armor at all", PublicKeyArmor).IsValid;

            // Assert
            Assert.False(result);
        }

        [Fact]
        public void VerifyDetached_WithGarbagePublicKeyArmor_ShouldReturnFalseNotThrow()
        {
            // Arrange
            byte[] data = Encoding.ASCII.GetBytes("OpenPGP");

            // Act
            bool result = OpenPgpVerifier.VerifyDetached(data, SignatureArmor, "not armor at all").IsValid;

            // Assert
            Assert.False(result);
        }

        [Fact]
        public void VerifyDetached_WithEmptyStrings_ShouldReturnFalseNotThrow()
        {
            // Act
            bool result = OpenPgpVerifier.VerifyDetached(Array.Empty<byte>(), string.Empty, string.Empty).IsValid;

            // Assert
            Assert.False(result);
        }

        [Fact]
        public void VerifyClearsign_WithGarbageInput_ShouldReturnFalseNotThrow()
        {
            // Act
            bool result = OpenPgpVerifier.VerifyClearsign("not a clearsigned message", PublicKeyArmor).IsValid;

            // Assert
            Assert.False(result);
        }
    }
}
