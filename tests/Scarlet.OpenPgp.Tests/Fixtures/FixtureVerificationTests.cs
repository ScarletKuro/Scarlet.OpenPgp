using System.Text;

namespace Scarlet.OpenPgp.Tests.Fixtures
{
    /// <summary>
    /// End-to-end verification against the fixtures described in TestAssets/FIXTURES.md: real
    /// release artifacts, GnuPG 2.4.9 output for every algorithm and key scenario, and the RFC 9580
    /// Appendix A vectors. Each expectation is the manifest's "Expected (strict)" verdict. The clock
    /// is pinned so the time-sensitive ones (keys that expire) keep meaning the same thing.
    /// </summary>
    public class FixtureVerificationTests
    {
        /// <summary>The day the fixtures were assembled; every real-world signing key was valid then.</summary>
        private static readonly DateTimeOffset AssembledOn = new DateTimeOffset(2026, 10, 17, 0, 0, 0, TimeSpan.Zero);

        private static readonly UTF8Encoding StrictUtf8 = new UTF8Encoding(false, true);

        private static byte[] Bytes(string path) => File.ReadAllBytes(Path.Combine("TestAssets", path));

        private static string Text(string path) => StrictUtf8.GetString(Bytes(path));

        private static VerificationResult Detached(string folder, string data, string signature, string keys, DateTimeOffset? now = null)
        {
            return OpenPgpVerifier.VerifyDetached(Bytes(folder + "/" + data), Bytes(folder + "/" + signature), Bytes(folder + "/" + keys), now ?? AssembledOn);
        }

        private static VerificationResult Clearsign(string folder, string message, string keys, DateTimeOffset? now = null)
        {
            return OpenPgpVerifier.VerifyClearsign(Text(folder + "/" + message), Bytes(folder + "/" + keys), now ?? AssembledOn);
        }

        private static void AssertValid(VerificationResult result, string? signer = null, string? primary = null)
        {
            Assert.True(result.IsValid, result.ToString());
            if (signer is not null)
            {
                Assert.Equal(signer, result.SignerFingerprint);
            }

            if (primary is not null)
            {
                Assert.Equal(primary, result.PrimaryKeyFingerprint);
            }
        }

        // ---- Part 1: real-world release artifacts --------------------------------------------

        [Theory]
        [InlineData("tor-browser-developers.asc")]
        [InlineData("tor-browser-developers.gpg")]
        public void TorBrowser_SignedByARotatingSigningSubkey_ShouldVerifyAgainstTheCurrentSubkey(string keys)
        {
            // Act
            VerificationResult result = Detached("real-world/tor-browser-subkey", "sha256sums-signed-build.txt", "sha256sums-signed-build.txt.asc", keys);

            // Assert
            AssertValid(result, signer: "022DA248432D2A0E0F54E65E316C1FACD62D07D9", primary: "EF6E286DDA85EA2A4BA7DE684E2C6E8793298290");
            Assert.Equal(new DateTimeOffset(2026, 10, 12, 23, 14, 34, TimeSpan.Zero), result.SignatureCreationTime);
        }

        [Fact]
        public void TorBrowser_AfterTheSigningSubkeyExpires_ShouldReportKeyExpired()
        {
            // Act: the subkey expires 2028-11-28 (FIXTURES.md); the primary not until 2030.
            VerificationResult result = Detached("real-world/tor-browser-subkey", "sha256sums-signed-build.txt", "sha256sums-signed-build.txt.asc", "tor-browser-developers.asc", new DateTimeOffset(2029, 1, 1, 0, 0, 0, TimeSpan.Zero));

            // Assert
            Assert.Equal(VerificationStatus.KeyExpired, result.Status);
            Assert.Equal("022DA248432D2A0E0F54E65E316C1FACD62D07D9", result.SignerFingerprint);
        }

        [Fact]
        public void TorBrowser_WithTamperedData_ShouldReportBadSignature()
        {
            // Arrange
            byte[] data = Bytes("real-world/tor-browser-subkey/sha256sums-signed-build.txt");
            data[10] ^= 0x01;

            // Act
            VerificationResult result = OpenPgpVerifier.VerifyDetached(data, Bytes("real-world/tor-browser-subkey/sha256sums-signed-build.txt.asc"), Bytes("real-world/tor-browser-subkey/tor-browser-developers.asc"), AssembledOn);

            // Assert
            Assert.Equal(VerificationStatus.BadSignature, result.Status);
        }

        [Theory]
        [InlineData("gnupg-signature-keys.asc")]
        [InlineData("gnupg-signature-keys.gpg")]
        public void GnuPgNpth_BinarySignatureWithTwoSignersAndSixCertificateKeyring_ShouldVerify(string keys)
        {
            // Act
            VerificationResult result = Detached("real-world/gnupg-npth-multisig", "npth-1.8.tar.bz2", "npth-1.8.tar.bz2.sig", keys);

            // Assert: the first signature (Werner Koch) verifies.
            AssertValid(result, signer: "6DAA6E64A76D2840571B4902528897B826403ADA");
        }

        [Fact]
        public void GnuPgNpth_AfterOneSignersKeyExpires_ShouldStillVerifyWithTheOther()
        {
            // Act: Niibe Yutaka's key expires 2027-04-04, Werner Koch's not until 2030-06-30.
            VerificationResult result = Detached("real-world/gnupg-npth-multisig", "npth-1.8.tar.bz2", "npth-1.8.tar.bz2.sig", "gnupg-signature-keys.gpg", new DateTimeOffset(2028, 1, 1, 0, 0, 0, TimeSpan.Zero));

            // Assert
            AssertValid(result, signer: "6DAA6E64A76D2840571B4902528897B826403ADA");
        }

        [Fact]
        public void GnuPgNpth_AfterBothSignersKeysExpire_ShouldReportKeyExpired()
        {
            // Act
            VerificationResult result = Detached("real-world/gnupg-npth-multisig", "npth-1.8.tar.bz2", "npth-1.8.tar.bz2.sig", "gnupg-signature-keys.gpg", new DateTimeOffset(2031, 1, 1, 0, 0, 0, TimeSpan.Zero));

            // Assert
            Assert.Equal(VerificationStatus.KeyExpired, result.Status);
        }

        [Fact]
        public async System.Threading.Tasks.Task GnuPgNpth_StreamedAndAsync_ShouldMatchTheInMemoryResult()
        {
            // Arrange
            byte[] signature = Bytes("real-world/gnupg-npth-multisig/npth-1.8.tar.bz2.sig");
            byte[] keys = Bytes("real-world/gnupg-npth-multisig/gnupg-signature-keys.gpg");

            // Act
            VerificationResult streamed;
            using (FileStream data = File.OpenRead(Path.Combine("TestAssets", "real-world/gnupg-npth-multisig/npth-1.8.tar.bz2")))
            {
                streamed = OpenPgpVerifier.VerifyDetached(data, signature, keys, AssembledOn);
            }

            VerificationResult asyncResult;
            await using (FileStream data = File.OpenRead(Path.Combine("TestAssets", "real-world/gnupg-npth-multisig/npth-1.8.tar.bz2")))
            {
                // The public async API uses the real clock; Werner Koch's key is valid until 2030.
                asyncResult = await OpenPgpVerifier.VerifyDetachedAsync(data, signature, keys, TestContext.Current.CancellationToken);
            }

            // Assert
            AssertValid(streamed, signer: "6DAA6E64A76D2840571B4902528897B826403ADA");
            AssertValid(asyncResult, signer: "6DAA6E64A76D2840571B4902528897B826403ADA");
        }

        [Theory]
        [InlineData("richard-lau.asc")]
        [InlineData("richard-lau.gpg")]
        public void NodeJs_RsaClearsign_ShouldVerifyAndReturnTheChecksumFile(string keys)
        {
            // Act
            VerificationResult result = Clearsign("real-world/nodejs-clearsign-rsa", "SHASUMS256.txt.asc", keys);

            // Assert
            AssertValid(result, signer: "C82FA3AE1CBEDC6BE46B9360C43CEC45C17AB93C", primary: "C82FA3AE1CBEDC6BE46B9360C43CEC45C17AB93C");
            Assert.Equal(Text("real-world/nodejs-clearsign-rsa/SHASUMS256.txt").TrimEnd('\n'), result.SignedText!.Replace("\r\n", "\n"));
        }

        [Fact]
        public void NodeJs_BinaryDetachedSignature_ShouldVerify()
        {
            // Act
            VerificationResult result = Detached("real-world/nodejs-clearsign-rsa", "SHASUMS256.txt", "SHASUMS256.txt.sig", "richard-lau.gpg");

            // Assert
            AssertValid(result, signer: "C82FA3AE1CBEDC6BE46B9360C43CEC45C17AB93C");
        }

        [Fact]
        public void Debian_ArmoredDetachedSignatureWithThreeSigners_ShouldVerify()
        {
            // Act
            VerificationResult result = Detached("real-world/debian-trixie-release", "Release", "Release.gpg", "debian-keyring.gpg");

            // Assert: the first signature, by the bookworm archive key's signing subkey.
            AssertValid(result, signer: "4CB50190207B4758A3F73A796ED0E7B82643E131", primary: "B8B80B5B623EAB6AD8775C45B7C5D7D6350947F8");
        }

        [Fact]
        public void Debian_WithOnlyOneOfTheThreeSignersKeys_ShouldVerifyThatSignersSignature()
        {
            // Act: "any signature by a supplied key" - the other two signers are simply unknown.
            VerificationResult detached = Detached("real-world/debian-trixie-release", "Release", "Release.gpg", "archive-key-13-only.gpg");
            VerificationResult clearsigned = Clearsign("real-world/debian-trixie-release", "InRelease", "archive-key-13-only.gpg");

            // Assert
            AssertValid(detached, signer: "B8E5F13176D2A7A75220028078DBA3BC47EF2265", primary: "04B54C3CDCA79751B16BC6B5225629DF75B188BD");
            AssertValid(clearsigned, signer: "B8E5F13176D2A7A75220028078DBA3BC47EF2265");
        }

        [Fact]
        public void Debian_ClearsignWithThreeSignatures_ShouldVerifyAndReturnTheReleaseFile()
        {
            // Act
            VerificationResult result = Clearsign("real-world/debian-trixie-release", "InRelease", "debian-keyring.gpg");

            // Assert
            AssertValid(result);
            Assert.Equal(Text("real-world/debian-trixie-release/Release").TrimEnd('\n'), result.SignedText!.Replace("\r\n", "\n"));
        }

        [Fact]
        public void Debian_WithAKeyringOfOnlyUnrelatedKeys_ShouldReportNoMatchingKey()
        {
            // Act
            VerificationResult result = Detached("real-world/debian-trixie-release", "Release", "Release.gpg", "../../real-world/nodejs-clearsign-rsa/richard-lau.gpg");

            // Assert
            Assert.Equal(VerificationStatus.NoMatchingKey, result.Status);
        }

        // ---- Part 2.1: every algorithm GnuPG can sign with ------------------------------------

        [Theory]
        [InlineData("v4-rsa3072", "61E00ACDA21367249EBCFF8CC35ACCBC40F4CE54")]
        [InlineData("v4-dsa2048", "3BFC0236D528CB2B88825338ED8005C4CFDD2E2C")]
        [InlineData("v4-dsa3072", "99DA89BA18421DE078CB2EE4B825B73F1A8A48F4")]
        [InlineData("v4-ecdsa-nistp256", "227F94A7ECE5D9B722876D9458F417BCC59F56B4")]
        [InlineData("v4-ecdsa-nistp384", "62064211128E8D9969943641F6F407BCC7DBBDAE")]
        [InlineData("v4-ecdsa-nistp521", "EFCB8696145F9024EE2BFAD888AC494F4C6A15B2")]
        [InlineData("v4-ecdsa-brainpoolp256r1", "87F81D3CBF16A5EE36D9CC2DA0ED38FC69CAE187")]
        [InlineData("v4-ecdsa-brainpoolp384r1", "199F9E7E04F340CE7E4CE152A3C9142A7E15E0F0")]
        [InlineData("v4-ecdsa-brainpoolp512r1", "042C74706EBAFF3E5EFB151FF7673F1DF215896A")]
        [InlineData("v4-eddsa-ed25519-legacy", "F94DD31C085818C5887DD8C4F62AB74245BDF00E")]
        public void GnuPgGenerated_EachAlgorithm_ShouldVerifyArmoredBinaryAndClearsign(string folder, string fingerprint)
        {
            // Arrange
            folder = "gnupg-generated/" + folder;

            foreach (string keys in new[] { "public-key.asc", "public-key.gpg" })
            {
                // Act
                VerificationResult armored = Detached(folder, "data.txt", "data.txt.asc", keys);
                VerificationResult binary = Detached(folder, "data.txt", "data.txt.sig", keys);
                VerificationResult clearsigned = Clearsign(folder, "data.txt.clearsign.asc", keys);

                // Assert
                AssertValid(armored, signer: fingerprint, primary: fingerprint);
                AssertValid(binary, signer: fingerprint);
                AssertValid(clearsigned, signer: fingerprint);
            }
        }

        [Theory]
        [InlineData("v4-rsa3072")]
        [InlineData("v4-dsa2048")]
        [InlineData("v4-ecdsa-nistp256")]
        [InlineData("v4-ecdsa-brainpoolp512r1")]
        [InlineData("v4-eddsa-ed25519-legacy")]
        public void GnuPgGenerated_EachAlgorithm_WithTamperedData_ShouldReportBadSignature(string folder)
        {
            // Arrange
            byte[] data = Bytes("gnupg-generated/" + folder + "/data.txt");
            data[0] ^= 0x20;

            // Act
            VerificationResult result = OpenPgpVerifier.VerifyDetached(data, Bytes("gnupg-generated/" + folder + "/data.txt.sig"), Bytes("gnupg-generated/" + folder + "/public-key.gpg"), AssembledOn);

            // Assert
            Assert.Equal(VerificationStatus.BadSignature, result.Status);
        }

        [Theory]
        [InlineData("v4-rsa3072", "data.txt.sha224.sig")]
        [InlineData("v4-rsa3072", "data.txt.sha384.sig")]
        [InlineData("v4-rsa3072", "data.txt.sha512.sig")]
        [InlineData("v4-eddsa-ed25519-legacy", "data.txt.sha512.sig")]
        public void GnuPgGenerated_OtherSha2Hashes_ShouldVerify(string folder, string signature)
        {
            // Act
            VerificationResult result = Detached("gnupg-generated/" + folder, "data.txt", signature, "public-key.gpg");

            // Assert
            AssertValid(result);
        }

        [Fact]
        public void GnuPgGenerated_Sha1Signature_ShouldBeRejectedAsUnsupported()
        {
            // Act: RFC 9580 §9.5 - MUST NOT validate a recent signature that depends on SHA-1.
            VerificationResult result = Detached("gnupg-generated/v4-rsa3072", "data.txt", "data.txt.sha1.sig", "public-key.gpg");

            // Assert
            Assert.Equal(VerificationStatus.UnsupportedAlgorithm, result.Status);
        }

        // ---- Part 2.2-2.4: subkeys, text mode, several signers --------------------------------

        [Theory]
        [InlineData("data.txt.asc")]
        [InlineData("data.txt.sig")]
        public void GnuPgGenerated_SigningSubkey_ShouldVerifyAsTheSubkey(string signature)
        {
            // Act
            VerificationResult result = Detached("gnupg-generated/v4-signing-subkey", "data.txt", signature, "public-key.gpg");

            // Assert
            AssertValid(result, signer: "CC4D3084176105CC24EB67687B8B6791D30CB959", primary: "9DB4A83ABF3FF7BAE1E205862DEEF822DFBFB6CB");
        }

        [Fact]
        public void GnuPgGenerated_SigningSubkey_Clearsign_ShouldVerify()
        {
            // Act
            VerificationResult result = Clearsign("gnupg-generated/v4-signing-subkey", "data.txt.clearsign.asc", "public-key.asc");

            // Assert
            AssertValid(result, signer: "CC4D3084176105CC24EB67687B8B6791D30CB959");
        }

        [Theory]
        [InlineData("data-lf.txt.textmode.sig", "data-lf.txt", true)]
        [InlineData("data-lf.txt.textmode.asc", "data-lf.txt", true)]
        [InlineData("data-crlf.txt.textmode.sig", "data-crlf.txt", true)]
        [InlineData("data-lf.txt.textmode.sig", "data-crlf.txt", true)]
        [InlineData("data-crlf.txt.textmode.sig", "data-lf.txt", true)]
        [InlineData("data-lf.txt.textmode.sig", "data-lf-trailing-ws-stripped.txt", false)]
        [InlineData("data-lf.txt.binary.sig", "data-lf.txt", true)]
        [InlineData("data-crlf.txt.binary.sig", "data-crlf.txt", true)]
        [InlineData("data-lf.txt.binary.sig", "data-crlf.txt", false)]
        [InlineData("data-crlf.txt.binary.sig", "data-lf.txt", false)]
        public void GnuPgGenerated_TextModeSignatures_ShouldCanonicalizeLineEndingsOnly(string signature, string data, bool expectedValid)
        {
            // Act
            VerificationResult result = Detached("gnupg-generated/v4-textmode", data, signature, "public-key.gpg");

            // Assert
            Assert.True(result.IsValid == expectedValid, result.ToString());
            if (!expectedValid)
            {
                Assert.Equal(VerificationStatus.BadSignature, result.Status);
            }
        }

        [Fact]
        public void GnuPgGenerated_TextModeSignature_StreamedInTinyChunks_ShouldStillCanonicalizeAcrossChunkBoundaries()
        {
            // Arrange: a stream that returns one byte at a time, so every CR/LF pair is split.
            byte[] data = Bytes("gnupg-generated/v4-textmode/data-crlf.txt");

            // Act
            VerificationResult result;
            using (var stream = new OneByteAtATimeStream(data))
            {
                result = OpenPgpVerifier.VerifyDetached(stream, Bytes("gnupg-generated/v4-textmode/data-lf.txt.textmode.sig"), Bytes("gnupg-generated/v4-textmode/public-key.gpg"), AssembledOn);
            }

            // Assert
            AssertValid(result);
        }

        [Theory]
        [InlineData("keyring-both.asc", "6DB026C45610A2FDE7F5FB52D848DB657D349208")]
        [InlineData("keyring-both.gpg", "6DB026C45610A2FDE7F5FB52D848DB657D349208")]
        [InlineData("keyring-a-only.gpg", "6DB026C45610A2FDE7F5FB52D848DB657D349208")]
        [InlineData("keyring-b-only.asc", "A020E82754904E60FDAA1EA10972DC74CD762769")]
        [InlineData("keyring-b-only.gpg", "A020E82754904E60FDAA1EA10972DC74CD762769")]
        public void GnuPgGenerated_TwoSigners_ShouldVerifyWithWhicheverKeyIsSupplied(string keys, string expectedSigner)
        {
            // Act
            VerificationResult armored = Detached("gnupg-generated/v4-multi-signer", "data.txt", "data.txt.asc", keys);
            VerificationResult binary = Detached("gnupg-generated/v4-multi-signer", "data.txt", "data.txt.sig", keys);
            VerificationResult clearsigned = Clearsign("gnupg-generated/v4-multi-signer", "data.txt.clearsign.asc", keys);

            // Assert
            AssertValid(armored, signer: expectedSigner);
            AssertValid(binary, signer: expectedSigner);
            AssertValid(clearsigned, signer: expectedSigner);
        }

        // ---- Part 2.5-2.9: expiration and revocation -----------------------------------------

        [Theory]
        [InlineData("v4-expired-key", "data.txt.while-valid")]
        [InlineData("v4-expired-subkey", "data.txt.while-valid")]
        public void GnuPgGenerated_ExpiredKeyOrSubkey_ShouldBeValidBeforeExpiryAndExpiredAfter(string folder, string baseName)
        {
            // Arrange: both expire on 2020-12-31.
            DateTimeOffset before = new DateTimeOffset(2020, 7, 1, 0, 0, 0, TimeSpan.Zero);

            // Act
            VerificationResult then = Detached("gnupg-generated/" + folder, "data.txt", baseName + ".sig", "public-key.gpg", before);
            VerificationResult now = Detached("gnupg-generated/" + folder, "data.txt", baseName + ".sig", "public-key.gpg");
            VerificationResult clearsignedNow = Clearsign("gnupg-generated/" + folder, baseName + ".clearsign.asc", "public-key.asc");

            // Assert
            AssertValid(then);
            Assert.Equal(VerificationStatus.KeyExpired, now.Status);
            Assert.Equal(VerificationStatus.KeyExpired, clearsignedNow.Status);
        }

        [Fact]
        public void GnuPgGenerated_ExpiredSubkey_ShouldBlameTheSubkeyNotThePrimary()
        {
            // Act
            VerificationResult result = Detached("gnupg-generated/v4-expired-subkey", "data.txt", "data.txt.while-valid.sig", "public-key.gpg");

            // Assert
            Assert.Equal(VerificationStatus.KeyExpired, result.Status);
            Assert.Contains("subkey", result.Message);
            Assert.Equal("DE2992042C99BF46FCEB89C2546143853CEA7B81", result.SignerFingerprint);
        }

        [Theory]
        [InlineData("data.txt.expired-1d.sig", VerificationStatus.SignatureExpired)]
        [InlineData("data.txt.expired-1d.asc", VerificationStatus.SignatureExpired)]
        [InlineData("data.txt.expires-2099.sig", VerificationStatus.Valid)]
        [InlineData("data.txt.expires-2099.asc", VerificationStatus.Valid)]
        public void GnuPgGenerated_SignatureExpiration_ShouldBeEnforced(string signature, VerificationStatus expected)
        {
            // Act
            VerificationResult result = Detached("gnupg-generated/v4-expired-signature", "data.txt", signature, "public-key.gpg");

            // Assert
            Assert.Equal(expected, result.Status);
        }

        [Theory]
        [InlineData("data.txt.expired-1d.clearsign.asc", VerificationStatus.SignatureExpired)]
        [InlineData("data.txt.expires-2099.clearsign.asc", VerificationStatus.Valid)]
        public void GnuPgGenerated_SignatureExpiration_Clearsign_ShouldBeEnforced(string message, VerificationStatus expected)
        {
            // Act
            VerificationResult result = Clearsign("gnupg-generated/v4-expired-signature", message, "public-key.asc");

            // Assert
            Assert.Equal(expected, result.Status);
        }

        [Theory]
        [InlineData("v4-revoked-key-hard", "before-revocation", VerificationStatus.KeyRevoked)]
        [InlineData("v4-revoked-key-hard", "after-revocation", VerificationStatus.KeyRevoked)]
        [InlineData("v4-revoked-key-soft", "before-revocation", VerificationStatus.Valid)]
        [InlineData("v4-revoked-key-soft", "after-revocation", VerificationStatus.KeyRevoked)]
        [InlineData("v4-revoked-subkey-hard", "before-revocation", VerificationStatus.KeyRevoked)]
        [InlineData("v4-revoked-subkey-hard", "after-revocation", VerificationStatus.KeyRevoked)]
        [InlineData("v4-revoked-subkey-soft", "before-revocation", VerificationStatus.Valid)]
        [InlineData("v4-revoked-subkey-soft", "after-revocation", VerificationStatus.KeyRevoked)]
        public void GnuPgGenerated_Revocations_ShouldDistinguishHardFromSoft(string folder, string when, VerificationStatus expected)
        {
            // Arrange
            string folderPath = "gnupg-generated/" + folder;
            string baseName = "data.txt." + when;

            // Act
            VerificationResult detached = Detached(folderPath, "data.txt", baseName + ".sig", "public-key.gpg");
            VerificationResult armored = Detached(folderPath, "data.txt", baseName + ".asc", "public-key.asc");
            VerificationResult clearsigned = Clearsign(folderPath, baseName + ".clearsign.asc", "public-key.asc");
            VerificationResult unrevoked = Detached(folderPath, "data.txt", baseName + ".sig", "public-key-unrevoked.gpg");

            // Assert
            Assert.Equal(expected, detached.Status);
            Assert.Equal(expected, armored.Status);
            Assert.Equal(expected, clearsigned.Status);
            AssertValid(unrevoked);
        }

        // ---- Part 2.10: LibrePGP v5 (not RFC 9580) -------------------------------------------

        [Fact]
        public void LibrePgpV5_ShouldBeRejectedCleanly()
        {
            // Arrange
            const string folder = "gnupg-generated/librepgp-v5-ed448-unsupported";

            // Act
            VerificationResult detached = Detached(folder, "data.txt", "data.txt.sig", "public-key.gpg");
            VerificationResult armored = Detached(folder, "data.txt", "data.txt.asc", "public-key.asc");
            VerificationResult clearsigned = Clearsign(folder, "data.txt.clearsign.asc", "public-key.asc");

            // Assert: v5 keys aren't usable keys, so the key input itself is reported unusable.
            Assert.Equal(VerificationStatus.InvalidPublicKey, detached.Status);
            Assert.Equal(VerificationStatus.InvalidPublicKey, armored.Status);
            Assert.Equal(VerificationStatus.InvalidPublicKey, clearsigned.Status);
        }

        // ---- Part 3: RFC 9580 Appendix A ------------------------------------------------------

        [Theory]
        [InlineData("a1-v4-ed25519legacy-key.asc", "a2-v4-ed25519legacy-sig.asc")]
        [InlineData("a1-v4-ed25519legacy-key.gpg", "a2-v4-ed25519legacy-sig.sig")]
        public void Rfc9580_A1A2_BareV4KeyMatchedByKeyIdOnly_ShouldVerify(string keys, string signature)
        {
            // Act
            VerificationResult result = Detached("rfc9580", "a2-signed-data.txt", signature, keys);

            // Assert
            AssertValid(result, signer: "C959BDBAFA32A2F89A153B678CFDE12197965A9A");
        }

        [Theory]
        [InlineData("a3-v6-certificate.asc")]
        [InlineData("a3-v6-certificate.gpg")]
        public void Rfc9580_A6_V6CleartextSignatureWithEd25519_ShouldVerify(string keys)
        {
            // Act
            VerificationResult result = Clearsign("rfc9580", "a6-cleartext-signed.asc", keys);

            // Assert
            AssertValid(result, signer: "CB186C4F0609A697E4D52DFA6C722B0C1F1E27C18A56708F6525EC27BAD9ACC9", primary: "CB186C4F0609A697E4D52DFA6C722B0C1F1E27C18A56708F6525EC27BAD9ACC9");
            Assert.Equal(new DateTimeOffset(2022, 12, 13, 16, 8, 3, TimeSpan.Zero), result.SignatureCreationTime);
            Assert.Equal(Text("rfc9580/a6-a7-message.txt").Replace("\n", "\r\n"), result.SignedText);
        }

        [Fact]
        public void Rfc9580_A6_WithTamperedText_ShouldReportBadSignature()
        {
            // Arrange
            string tampered = Text("rfc9580/a6-cleartext-signed.asc").Replace("- - tofu", "- - beef");

            // Act
            VerificationResult result = OpenPgpVerifier.VerifyClearsign(tampered, Bytes("rfc9580/a3-v6-certificate.asc"), AssembledOn);

            // Assert
            Assert.Equal(VerificationStatus.BadSignature, result.Status);
        }

        /// <summary>A read-only stream that hands out one byte per Read call.</summary>
        private sealed class OneByteAtATimeStream : MemoryStream
        {
            public OneByteAtATimeStream(byte[] data)
                : base(data, writable: false)
            {
            }

            public override int Read(byte[] buffer, int offset, int count) => base.Read(buffer, offset, Math.Min(count, 1));
        }
    }
}
