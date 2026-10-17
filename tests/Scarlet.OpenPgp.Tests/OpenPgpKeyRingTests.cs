using System.Text;

namespace Scarlet.OpenPgp.Tests
{
    public class OpenPgpKeyRingTests
    {
        private static readonly DateTimeOffset AssembledOn = new DateTimeOffset(2026, 10, 17, 0, 0, 0, TimeSpan.Zero);

        private static byte[] Bytes(string path) => File.ReadAllBytes(Path.Combine("TestAssets", path));

        [Fact]
        public void Parse_TorBrowserCertificate_ShouldExposeKeysUserIdsExpirationAndRevocation()
        {
            // Act
            OpenPgpKeyRing keyRing = OpenPgpKeyRing.Parse(Bytes("real-world/tor-browser-subkey/tor-browser-developers.asc"));

            // Assert
            OpenPgpCertificate certificate = Assert.Single(keyRing.Certificates);
            Assert.Equal("EF6E286DDA85EA2A4BA7DE684E2C6E8793298290", certificate.PrimaryKey.Fingerprint);
            Assert.Equal("4E2C6E8793298290", certificate.PrimaryKey.KeyId);
            Assert.Equal(4, certificate.PrimaryKey.Version);
            Assert.Equal("RSA 4096", certificate.PrimaryKey.Algorithm);
            Assert.Contains("Tor Browser Developers (signing key) <torbrowser@torproject.org>", certificate.UserIds);
            Assert.Equal(2030, certificate.PrimaryKey.ExpiresAt?.Year);
            Assert.False(certificate.PrimaryKey.IsRevoked);

            OpenPgpKey signingSubkey = certificate.Subkeys.Single(k => k.Fingerprint == "022DA248432D2A0E0F54E65E316C1FACD62D07D9");
            Assert.Equal(new DateTime(2026, 8, 11), signingSubkey.CreatedAt.UtcDateTime.Date);
            Assert.Equal(2028, signingSubkey.ExpiresAt?.Year);
            Assert.True(certificate.Subkeys.Single(k => k.Fingerprint == "05FA44253F6C19A8B7F518D42D000988589839A3").IsRevoked);
        }

        [Fact]
        public void Parse_GnuPgKeyring_ShouldReturnEveryCertificateWithItsAlgorithm()
        {
            // Act
            OpenPgpKeyRing keyRing = OpenPgpKeyRing.Parse(Bytes("real-world/gnupg-npth-multisig/gnupg-signature-keys.gpg"));

            // Assert
            Assert.Equal(6, keyRing.Certificates.Count);
            Assert.Equal(
                ["EdDSA Ed25519 (legacy)", "EdDSA Ed25519 (legacy)", "RSA 3072", "EdDSA Ed25519 (legacy)", "ECDSA brainpoolP256r1", "ECDSA brainpoolP384r1"],
                keyRing.Certificates.Select(c => c.PrimaryKey.Algorithm));
            // A UTF-8 User ID ("ö") must come through intact.
            Assert.Contains(keyRing.Certificates.SelectMany(c => c.UserIds), u => u.StartsWith("Ingo Klöcker", StringComparison.Ordinal));
        }

        [Fact]
        public void Parse_Rfc9580V6Certificate_ShouldExposeV6FingerprintsAndTheEncryptionSubkey()
        {
            // Act
            OpenPgpKeyRing keyRing = OpenPgpKeyRing.Parse(File.ReadAllText("TestAssets/rfc9580/a3-v6-certificate.asc"));

            // Assert
            OpenPgpCertificate certificate = Assert.Single(keyRing.Certificates);
            Assert.Equal(6, certificate.PrimaryKey.Version);
            Assert.Equal("CB186C4F0609A697E4D52DFA6C722B0C1F1E27C18A56708F6525EC27BAD9ACC9", certificate.PrimaryKey.Fingerprint);
            Assert.Equal("CB186C4F0609A697", certificate.PrimaryKey.KeyId); // v6 key IDs are the high 64 bits
            Assert.Equal("Ed25519", certificate.PrimaryKey.Algorithm);
            Assert.Empty(certificate.UserIds);

            OpenPgpKey subkey = Assert.Single(certificate.Subkeys);
            Assert.Equal("X25519", subkey.Algorithm);
            Assert.False(subkey.SupportsVerification);
        }

        [Fact]
        public void Parse_BareKeyWithoutSelfSignature_ShouldNeverExpire()
        {
            // Act
            OpenPgpKeyRing keyRing = OpenPgpKeyRing.Parse(Bytes("rfc9580/a1-v4-ed25519legacy-key.gpg"));

            // Assert
            Assert.Null(Assert.Single(keyRing.Certificates).PrimaryKey.ExpiresAt);
        }

        [Fact]
        public void Parse_WithGarbage_ShouldThrowOpenPgpFormatException()
        {
            // Act & Assert
            var exception = Assert.Throws<OpenPgpFormatException>(() => OpenPgpKeyRing.Parse("not a key"));
            Assert.Contains("unusable", exception.Message, StringComparison.Ordinal);
        }

        [Fact]
        public void TryParse_WithASignatureInsteadOfAKey_ShouldReportWhy()
        {
            // Act
            bool parsed = OpenPgpKeyRing.TryParse(Bytes("gnupg-generated/v4-rsa3072/data.txt.sig"), out OpenPgpKeyRing? keyRing, out string? error);

            // Assert
            Assert.False(parsed);
            Assert.Null(keyRing);
            Assert.NotNull(error);
        }

        [Fact]
        public void KeyRing_ParsedOnce_ShouldVerifyDetachedAndClearsignedSignaturesRepeatedly()
        {
            // Arrange
            OpenPgpKeyRing keyRing = OpenPgpKeyRing.Parse(Bytes("real-world/debian-trixie-release/debian-keyring.gpg"));
            byte[] release = Bytes("real-world/debian-trixie-release/Release");
            byte[] releaseSignature = Bytes("real-world/debian-trixie-release/Release.gpg");
            string inRelease = Encoding.UTF8.GetString(Bytes("real-world/debian-trixie-release/InRelease"));

            for (int i = 0; i < 3; i++)
            {
                // Act
                VerificationResult detached = OpenPgpVerifier.VerifyDetached(release, releaseSignature, keyRing, AssembledOn);
                VerificationResult clearsigned = OpenPgpVerifier.VerifyClearsign(inRelease, keyRing, AssembledOn);

                // Assert
                Assert.True(detached.IsValid, detached.ToString());
                Assert.True(clearsigned.IsValid, clearsigned.ToString());
            }
        }

        [Fact]
        public void KeyRing_ShouldStillJudgeExpirationAtVerificationTime()
        {
            // Arrange: parsed once; the key expired 2020-12-31.
            OpenPgpKeyRing keyRing = OpenPgpKeyRing.Parse(Bytes("gnupg-generated/v4-expired-key/public-key.gpg"));
            byte[] data = Bytes("gnupg-generated/v4-expired-key/data.txt");
            byte[] signature = Bytes("gnupg-generated/v4-expired-key/data.txt.while-valid.sig");

            // Act
            VerificationResult before = OpenPgpVerifier.VerifyDetached(data, signature, keyRing, new DateTimeOffset(2020, 7, 1, 0, 0, 0, TimeSpan.Zero));
            VerificationResult after = OpenPgpVerifier.VerifyDetached(data, signature, keyRing, AssembledOn);

            // Assert
            Assert.True(before.IsValid, before.ToString());
            Assert.Equal(VerificationStatus.KeyExpired, after.Status);
            Assert.Equal(new DateTimeOffset(2020, 12, 31, 0, 0, 0, TimeSpan.Zero), Assert.Single(keyRing.Certificates).PrimaryKey.ExpiresAt);
        }

        [Fact]
        public void KeyRing_SharedAcrossThreads_ShouldVerifyConsistently()
        {
            // Arrange
            OpenPgpKeyRing keyRing = OpenPgpKeyRing.Parse(Bytes("gnupg-generated/v4-multi-signer/keyring-both.gpg"));
            byte[] data = Bytes("gnupg-generated/v4-multi-signer/data.txt");
            byte[] signature = Bytes("gnupg-generated/v4-multi-signer/data.txt.sig");
            var results = new VerificationResult[32];

            // Act
            Parallel.For(0, results.Length, i => results[i] = OpenPgpVerifier.VerifyDetached(data, signature, keyRing, AssembledOn));

            // Assert
            Assert.All(results, r => Assert.True(r.IsValid, r.ToString()));
        }

        [Fact]
        public async Task KeyRing_WithTheStreamingAndAsyncOverloads_ShouldVerify()
        {
            // Arrange: the public overloads use the real clock; this certificate has no expiry.
            OpenPgpKeyRing keyRing = OpenPgpKeyRing.Parse(File.ReadAllText("TestAssets/gnupg-generated/v4-ecdsa-nistp384/public-key.asc"));
            byte[] signature = Bytes("gnupg-generated/v4-ecdsa-nistp384/data.txt.sig");

            // Act
            VerificationResult streamed;
            using (var data = new MemoryStream(Bytes("gnupg-generated/v4-ecdsa-nistp384/data.txt")))
            {
                streamed = OpenPgpVerifier.VerifyDetached(data, signature, keyRing);
            }

            VerificationResult asyncResult;
            using (var data = new MemoryStream(Bytes("gnupg-generated/v4-ecdsa-nistp384/data.txt")))
            {
                asyncResult = await OpenPgpVerifier.VerifyDetachedAsync(data, signature, keyRing, TestContext.Current.CancellationToken);
            }

            // Assert
            Assert.True(streamed.IsValid, streamed.ToString());
            Assert.True(asyncResult.IsValid, asyncResult.ToString());
        }

        [Theory]
        [InlineData("v4-revoked-key-hard", true)]
        [InlineData("v4-revoked-key-hard", false)]
        [InlineData("v4-revoked-subkey-hard", true)]
        [InlineData("v4-revoked-subkey-hard", false)]
        public void Parse_WithAStaleCopyOfARevokedCertificate_ShouldStillHonorTheRevocation(string folder, bool staleCopyFirst)
        {
            // Arrange: regression - an old export (no revocation) concatenated with the current one
            // (revoked) used to be a separate candidate, and verified. Both orders must merge.
            byte[] revoked = Bytes("gnupg-generated/" + folder + "/public-key.gpg");
            byte[] stale = Bytes("gnupg-generated/" + folder + "/public-key-unrevoked.gpg");
            byte[] combined = staleCopyFirst ? [.. stale, .. revoked] : [.. revoked, .. stale];
            byte[] data = Bytes("gnupg-generated/" + folder + "/data.txt");
            byte[] signature = Bytes("gnupg-generated/" + folder + "/data.txt.before-revocation.sig");

            // Act
            OpenPgpKeyRing keyRing = OpenPgpKeyRing.Parse(combined);
            VerificationResult result = OpenPgpVerifier.VerifyDetached(data, signature, keyRing, AssembledOn);

            // Assert
            Assert.Single(keyRing.Certificates);
            Assert.Equal(VerificationStatus.KeyRevoked, result.Status);
        }
    }
}
