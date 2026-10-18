using System.Numerics;
using System.Text.Json;
using Scarlet.OpenPgp.Crypto.Dsa;
using Scarlet.OpenPgp.Crypto.Ecdsa;
using Scarlet.OpenPgp.Crypto.Ed25519;
using Scarlet.OpenPgp.Crypto.Ed448;
using Scarlet.OpenPgp.Crypto.Rsa;
using Scarlet.OpenPgp.Hashing;
using Scarlet.OpenPgp.Internal;
using Scarlet.OpenPgp.Packets;

namespace Scarlet.OpenPgp.Tests.Crypto
{
    /// <summary>
    /// Project Wycheproof's signature-verification vectors (C2SP/wycheproof, testvectors_v1, Apache
    /// 2.0 - see TestAssets/wycheproof/LICENSE) run against each verifier. They are curated edge
    /// cases - malleability, out-of-range values, small-order points, wrong encodings, arithmetic
    /// corner cases - aimed at exactly the bugs that make a verifier accept a forgery.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The rule: an "invalid" vector must never verify; a "valid" one must verify, unless its key is
    /// one this library refuses by policy (e.g. a DSA or RSA size outside its limits), which is
    /// reported, not silently skipped; "acceptable" may go either way.
    /// </para>
    /// <para>
    /// The verifiers take integers and digests, as OpenPGP hands them over, rather than Wycheproof's
    /// fixed-width byte encodings. A vector whose signature isn't even representable that way
    /// (wrong length) is treated as rejected - in OpenPGP its MPIs would never reach the verifier.
    /// Parsed with JsonDocument, which needs no reflection, so the test still runs under Native AOT.
    /// </para>
    /// </remarks>
    public class WycheproofTests
    {
        private const string Folder = "TestAssets/wycheproof/";

        [Theory]
        [InlineData("ed25519_test.json")]
        public void Ed25519_ShouldAgreeWithWycheproof(string file)
        {
            AssertAgrees(file, group =>
            {
                byte[] publicKey = Hex(group.GetProperty("publicKey").GetProperty("pk"));
                var key = new Ed25519PublicKey(publicKey);
                return (message, signature) => Ed25519Verifier.Verify(key, message, signature);
            });
        }

        [Theory]
        [InlineData("ed448_test.json")]
        public void Ed448_ShouldAgreeWithWycheproof(string file)
        {
            AssertAgrees(file, group =>
            {
                byte[] publicKey = Hex(group.GetProperty("publicKey").GetProperty("pk"));
                return (message, signature) => Ed448Verifier.Verify(publicKey, message, signature);
            });
        }

        [Theory]
        [InlineData("ecdsa_secp256r1_sha256_p1363_test.json")]
        [InlineData("ecdsa_secp384r1_sha384_p1363_test.json")]
        [InlineData("ecdsa_secp521r1_sha512_p1363_test.json")]
        [InlineData("ecdsa_brainpoolP256r1_sha256_p1363_test.json")]
        [InlineData("ecdsa_brainpoolP384r1_sha384_p1363_test.json")]
        [InlineData("ecdsa_brainpoolP512r1_sha512_p1363_test.json")]
        public void Ecdsa_ShouldAgreeWithWycheproof(string file)
        {
            AssertAgrees(file, group =>
            {
                JsonElement publicKey = group.GetProperty("publicKey");
                EcCurve curve = Curve(publicKey.GetProperty("curve").GetString());
                byte[] point = Hex(publicKey.GetProperty("uncompressed"));
                HashAlgorithmId hash = Hash(group);
                int half = curve.FieldByteLength;
                return (message, signature) =>
                    signature.Length == 2 * half
                    && EcdsaVerifier.Verify(curve, point, Digest(hash, message), Unsigned(signature.AsSpan(0, half)), Unsigned(signature.AsSpan(half)));
            });
        }

        [Theory]
        [InlineData("dsa_2048_224_sha224_p1363_test.json")]
        [InlineData("dsa_2048_224_sha256_p1363_test.json")]
        [InlineData("dsa_2048_256_sha256_p1363_test.json")]
        [InlineData("dsa_3072_256_sha256_p1363_test.json")]
        public void Dsa_ShouldAgreeWithWycheproof(string file)
        {
            AssertAgrees(file, group =>
            {
                JsonElement publicKey = group.GetProperty("publicKey");
                var key = new DsaPublicKey(
                    Unsigned(Hex(publicKey.GetProperty("p"))),
                    Unsigned(Hex(publicKey.GetProperty("q"))),
                    Unsigned(Hex(publicKey.GetProperty("g"))),
                    Unsigned(Hex(publicKey.GetProperty("y"))));
                HashAlgorithmId hash = Hash(group);
                int half = (key.QBitLength + 7) / 8;
                return (message, signature) =>
                    signature.Length == 2 * half
                    && DsaVerifier.Verify(key, Digest(hash, message), Unsigned(signature.AsSpan(0, half)), Unsigned(signature.AsSpan(half)));
            });
        }

        [Theory]
        [InlineData("rsa_signature_2048_sha224_test.json")]
        [InlineData("rsa_signature_2048_sha256_test.json")]
        [InlineData("rsa_signature_2048_sha384_test.json")]
        [InlineData("rsa_signature_2048_sha512_test.json")]
        [InlineData("rsa_signature_2048_sha3_256_test.json")]
        [InlineData("rsa_signature_2048_sha3_512_test.json")]
        [InlineData("rsa_signature_3072_sha256_test.json")]
        [InlineData("rsa_signature_3072_sha384_test.json")]
        [InlineData("rsa_signature_3072_sha512_test.json")]
        [InlineData("rsa_signature_3072_sha3_256_test.json")]
        [InlineData("rsa_signature_3072_sha3_512_test.json")]
        [InlineData("rsa_signature_4096_sha256_test.json")]
        [InlineData("rsa_signature_4096_sha384_test.json")]
        [InlineData("rsa_signature_4096_sha512_test.json")]
        public void RsaPkcs1_ShouldAgreeWithWycheproof(string file)
        {
            AssertAgrees(file, group =>
            {
                JsonElement publicKey = group.GetProperty("publicKey");
                var key = new RsaPublicKey(Unsigned(Hex(publicKey.GetProperty("modulus"))), Unsigned(Hex(publicKey.GetProperty("publicExponent"))));
                HashAlgorithmId hash = Hash(group);
                return (message, signature) =>
                    signature.Length == key.ModulusByteLength
                    && RsaPkcs1Verifier.Verify(key, hash, Digest(hash, message), Unsigned(signature));
            }, rejectedByPolicy: "SmallSignature");
        }

        /// <param name="file">The vector file.</param>
        /// <param name="verifierFor">Builds a verifier from a test group's key; throws <see cref="FailClosedException"/> for a key this library refuses.</param>
        /// <param name="rejectedByPolicy">
        /// A Wycheproof flag marking "valid" vectors this library rejects on purpose. RSA's "SmallSignature" is a
        /// key crafted so a valid signature is tiny; a real signature is that short with probability
        /// 2^-64, and accepting them let tiny inputs buy full-size exponentiations (see
        /// <see cref="RsaPkcs1Verifier.MaxSignatureShortfallBits"/>).
        /// </param>
        private static void AssertAgrees(string file, Func<JsonElement, Func<byte[], byte[], bool>> verifierFor, string? rejectedByPolicy = null)
        {
            using JsonDocument document = JsonDocument.Parse(File.ReadAllBytes(Folder + file));
            var disagreements = new List<string>();
            int checkedVectors = 0;

            foreach (JsonElement group in document.RootElement.GetProperty("testGroups").EnumerateArray())
            {
                Func<byte[], byte[], bool>? verify;
                try
                {
                    verify = verifierFor(group);
                }
                catch (FailClosedException ex)
                {
                    verify = null; // a key refused by policy: nothing may verify under it
                    if (group.GetProperty("tests").EnumerateArray().Any(t => t.GetProperty("result").GetString() == "valid"))
                    {
                        disagreements.Add("group key refused (" + ex.Message + ") although it has valid vectors");
                    }
                }

                foreach (JsonElement test in group.GetProperty("tests").EnumerateArray())
                {
                    checkedVectors++;
                    string expected = test.GetProperty("result").GetString()!;
                    bool accepted = verify is not null && verify(Hex(test.GetProperty("msg")), Hex(test.GetProperty("sig")));
                    bool policyRejection = rejectedByPolicy is not null && test.GetProperty("flags").EnumerateArray().Any(f => f.GetString() == rejectedByPolicy);
                    if ((expected == "invalid" && accepted) || (expected == "valid" && !accepted && verify is not null && !policyRejection))
                    {
                        disagreements.Add(
                            "tcId " + test.GetProperty("tcId").GetInt32() + " expected " + expected + " got " + (accepted ? "accepted" : "rejected")
                            + " (" + test.GetProperty("comment").GetString() + "; " + string.Join(", ", test.GetProperty("flags").EnumerateArray().Select(f => f.GetString())) + ")");
                    }
                }
            }

            Assert.True(checkedVectors > 0, "No vectors in " + file);
            Assert.True(disagreements.Count == 0, file + ": " + disagreements.Count + " disagreement(s) out of " + checkedVectors + ":\n" + string.Join("\n", disagreements));
        }

        private static EcCurve Curve(string? name) => name switch
        {
            "secp256r1" => EcCurve.NistP256,
            "secp384r1" => EcCurve.NistP384,
            "secp521r1" => EcCurve.NistP521,
            "brainpoolP256r1" => EcCurve.BrainpoolP256r1,
            "brainpoolP384r1" => EcCurve.BrainpoolP384r1,
            "brainpoolP512r1" => EcCurve.BrainpoolP512r1,
            _ => throw new ArgumentOutOfRangeException(nameof(name), name, null),
        };

        private static HashAlgorithmId Hash(JsonElement group) => group.GetProperty("sha").GetString() switch
        {
            "SHA-224" => HashAlgorithmId.Sha224,
            "SHA-256" => HashAlgorithmId.Sha256,
            "SHA-384" => HashAlgorithmId.Sha384,
            "SHA-512" => HashAlgorithmId.Sha512,
            "SHA3-256" => HashAlgorithmId.Sha3_256,
            "SHA3-512" => HashAlgorithmId.Sha3_512,
            { } other => throw new ArgumentOutOfRangeException(nameof(group), other, null),
            null => throw new ArgumentNullException(nameof(group)),
        };

        private static byte[] Digest(HashAlgorithmId algorithm, byte[] message)
        {
            using HashContext hash = HashContext.Create(algorithm);
            hash.Update(message);
            return hash.Finish();
        }

        private static byte[] Hex(JsonElement element) => Convert.FromHexString(element.GetString() ?? "");

        private static BigInteger Unsigned(ReadOnlySpan<byte> bigEndian) => Mpi.ToUnsignedBigInteger(bigEndian.ToArray());
    }
}
