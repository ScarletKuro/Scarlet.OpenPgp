using System.Numerics;
using System.Text;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Security;
using Scarlet.OpenPgp.Crypto.Dsa;
using Scarlet.OpenPgp.Internal;
using Scarlet.OpenPgp.Packets;
using BcBigInteger = Org.BouncyCastle.Math.BigInteger;

namespace Scarlet.OpenPgp.Tests.Crypto.Dsa
{
    public class DsaVerifierTests
    {
        // FIPS 186-4 domain-parameter generation (probable primes, A.1.1.2) is the slow part, so each
        // (L, N) size is generated at most once per test run and shared by every test via Lazy<T>.
        // Fresh parameters every run - rather than hard-coded ones - mean the verifier is checked
        // against many different groups over time, not one fixed fixture.
        private static readonly Lazy<DsaParameters> Parameters2048x224 = new Lazy<DsaParameters>(() => GenerateParameters(2048, 224));
        private static readonly Lazy<DsaParameters> Parameters2048x256 = new Lazy<DsaParameters>(() => GenerateParameters(2048, 256));
        private static readonly Lazy<DsaParameters> Parameters3072x256 = new Lazy<DsaParameters>(() => GenerateParameters(3072, 256));
        private static readonly Lazy<DsaParameters> Parameters1024x160 = new Lazy<DsaParameters>(() => GenerateLegacyParameters());

        private static readonly byte[] Message = Encoding.ASCII.GetBytes("Scarlet.OpenPgp DSA test message");

        private sealed class ReferenceSignature
        {
            public ReferenceSignature(DsaPublicKey key, byte[] digest, BigInteger r, BigInteger s)
            {
                Key = key;
                Digest = digest;
                R = r;
                S = s;
            }

            public DsaPublicKey Key { get; }

            public byte[] Digest { get; }

            public BigInteger R { get; }

            public BigInteger S { get; }
        }

        private static DsaParameters GenerateParameters(int l, int n)
        {
            var generator = new DsaParametersGenerator(new Sha256Digest());
            generator.Init(new DsaParameterGenerationParameters(l, n, 80, new SecureRandom()));
            return generator.GenerateParameters();
        }

        private static DsaParameters GenerateLegacyParameters()
        {
            // FIPS 186-2 style DSA-1024/160 - the size this library deliberately refuses.
            var generator = new DsaParametersGenerator();
            generator.Init(1024, 80, new SecureRandom());
            return generator.GenerateParameters();
        }

        private static DsaParameters GetParameters(int l, int n)
        {
            switch ((l, n))
            {
                case (2048, 224):
                    return Parameters2048x224.Value;
                case (2048, 256):
                    return Parameters2048x256.Value;
                case (3072, 256):
                    return Parameters3072x256.Value;
                default:
                    throw new ArgumentOutOfRangeException(nameof(l));
            }
        }

        private static BigInteger ToNumerics(BcBigInteger value) => Mpi.ToUnsignedBigInteger(value.ToByteArrayUnsigned());

        private static DsaPublicKey ToPublicKey(DsaParameters parameters, BcBigInteger y) =>
            new DsaPublicKey(ToNumerics(parameters.P), ToNumerics(parameters.Q), ToNumerics(parameters.G), ToNumerics(y));

        private static ReferenceSignature SignWithBouncyCastle(int l, int n, byte[] digest)
        {
            DsaParameters parameters = GetParameters(l, n);
            var keyGenerator = new DsaKeyPairGenerator();
            keyGenerator.Init(new DsaKeyGenerationParameters(new SecureRandom(), parameters));
            AsymmetricCipherKeyPair keyPair = keyGenerator.GenerateKeyPair();

            var signer = new DsaSigner();
            signer.Init(true, keyPair.Private);
            BcBigInteger[] signature = signer.GenerateSignature(digest);

            return new ReferenceSignature(
                ToPublicKey(parameters, ((DsaPublicKeyParameters)keyPair.Public).Y),
                digest,
                ToNumerics(signature[0]),
                ToNumerics(signature[1]));
        }

        private static byte[] Hash(string hashName, byte[] data)
        {
            IDigest digest;
            switch (hashName)
            {
                case "SHA-1":
                    digest = new Sha1Digest();
                    break;
                case "SHA-224":
                    digest = new Sha224Digest();
                    break;
                case "SHA-256":
                    digest = new Sha256Digest();
                    break;
                case "SHA-384":
                    digest = new Sha384Digest();
                    break;
                case "SHA-512":
                    digest = new Sha512Digest();
                    break;
                default:
                    throw new ArgumentOutOfRangeException(nameof(hashName), hashName, null);
            }

            digest.BlockUpdate(data, 0, data.Length);
            var result = new byte[digest.GetDigestSize()];
            digest.DoFinal(result, 0);
            return result;
        }

        [Theory]
        [InlineData(2048, 224, "SHA-224")]
        [InlineData(2048, 224, "SHA-256")] // truncated to 224 bits
        [InlineData(2048, 224, "SHA-512")]
        [InlineData(2048, 256, "SHA-256")]
        [InlineData(2048, 256, "SHA-384")]
        [InlineData(2048, 256, "SHA-512")]
        [InlineData(3072, 256, "SHA-256")]
        [InlineData(3072, 256, "SHA-512")]
        public void Verify_WithBouncyCastleSignature_ShouldReturnTrue(int l, int n, string hashName)
        {
            for (int i = 0; i < 3; i++)
            {
                // Arrange
                ReferenceSignature reference = SignWithBouncyCastle(l, n, Hash(hashName, Encoding.ASCII.GetBytes("message #" + i)));

                // Act
                bool result = DsaVerifier.Verify(reference.Key, reference.Digest, reference.R, reference.S);

                // Assert
                Assert.True(result);
            }
        }

        [Theory]
        [InlineData(2048, 224, 29)] // 232 bits: 8-bit shift
        [InlineData(2048, 256, 33)]
        [InlineData(2048, 224, 28)] // exactly N bits
        public void Verify_WithArbitraryLengthDigest_ShouldTruncateLikeBouncyCastle(int l, int n, int digestLength)
        {
            // Arrange
            byte[] digest = System.Security.Cryptography.RandomNumberGenerator.GetBytes(digestLength);
            digest[0] |= 0x80;
            ReferenceSignature reference = SignWithBouncyCastle(l, n, digest);

            // Act
            bool result = DsaVerifier.Verify(reference.Key, reference.Digest, reference.R, reference.S);

            // Assert
            Assert.True(result);
        }

        [Theory]
        [InlineData(2048, 224, "SHA-1")]
        [InlineData(2048, 256, "SHA-224")]
        public void Verify_WithDigestShorterThanQ_ShouldReturnFalse(int l, int n, string hashName)
        {
            // Arrange: BouncyCastle will happily sign a short digest, but RFC 9580 §5.2.3.2 says a
            // DSA signature MUST use a hash at least as long as q - fail closed on anything weaker.
            ReferenceSignature reference = SignWithBouncyCastle(l, n, Hash(hashName, Message));

            // Act
            bool result = DsaVerifier.Verify(reference.Key, reference.Digest, reference.R, reference.S);

            // Assert
            Assert.False(result);
        }

        [Fact]
        public void Verify_WithTamperedDigest_ShouldReturnFalse()
        {
            // Arrange
            ReferenceSignature reference = SignWithBouncyCastle(2048, 256, Hash("SHA-256", Message));
            byte[] digest = (byte[])reference.Digest.Clone();
            digest[^1] ^= 0x01;

            // Act
            bool result = DsaVerifier.Verify(reference.Key, digest, reference.R, reference.S);

            // Assert
            Assert.False(result);
        }

        [Fact]
        public void Verify_WithTamperedDigestBitsBeyondTruncation_ShouldReturnTrue()
        {
            // Arrange: only the leftmost N = 224 bits of a SHA-256 digest count.
            ReferenceSignature reference = SignWithBouncyCastle(2048, 224, Hash("SHA-256", Message));
            byte[] digest = (byte[])reference.Digest.Clone();
            digest[^1] ^= 0x01;

            // Act
            bool result = DsaVerifier.Verify(reference.Key, digest, reference.R, reference.S);

            // Assert
            Assert.True(result);
        }

        [Fact]
        public void Verify_WithTamperedRorS_ShouldReturnFalse()
        {
            // Arrange
            ReferenceSignature reference = SignWithBouncyCastle(2048, 224, Hash("SHA-224", Message));

            // Act
            bool rPlusOne = DsaVerifier.Verify(reference.Key, reference.Digest, reference.R + 1, reference.S);
            bool sPlusOne = DsaVerifier.Verify(reference.Key, reference.Digest, reference.R, reference.S + 1);
            bool swapped = DsaVerifier.Verify(reference.Key, reference.Digest, reference.S, reference.R);
            bool negatedS = DsaVerifier.Verify(reference.Key, reference.Digest, reference.R, reference.Key.Q - reference.S);

            // Assert
            Assert.False(rPlusOne);
            Assert.False(sPlusOne);
            Assert.False(swapped);
            Assert.False(negatedS); // unlike ECDSA, DSA has no (r, q - s) malleability
        }

        [Fact]
        public void Verify_WithWrongPublicKey_ShouldReturnFalse()
        {
            // Arrange: same domain parameters, different key pair.
            ReferenceSignature reference = SignWithBouncyCastle(2048, 256, Hash("SHA-256", Message));
            ReferenceSignature other = SignWithBouncyCastle(2048, 256, Hash("SHA-256", Message));

            // Act
            bool result = DsaVerifier.Verify(other.Key, reference.Digest, reference.R, reference.S);

            // Assert
            Assert.False(result);
        }

        [Theory]
        [InlineData("zero-r")]
        [InlineData("zero-s")]
        [InlineData("negative-r")]
        [InlineData("negative-s")]
        [InlineData("r-equals-q")]
        [InlineData("s-equals-q")]
        [InlineData("r-plus-q")]
        [InlineData("s-plus-q")]
        public void Verify_WithOutOfRangeScalar_ShouldReturnFalse(string variant)
        {
            // Arrange: r + q and s + q are congruent to the valid values mod q, so they would
            // verify if the 0 < r, s < q check were missing.
            ReferenceSignature reference = SignWithBouncyCastle(2048, 256, Hash("SHA-256", Message));
            BigInteger q = reference.Key.Q;
            BigInteger r = reference.R;
            BigInteger s = reference.S;
            switch (variant)
            {
                case "zero-r": r = 0; break;
                case "zero-s": s = 0; break;
                case "negative-r": r = -r; break;
                case "negative-s": s = -s; break;
                case "r-equals-q": r = q; break;
                case "s-equals-q": s = q; break;
                case "r-plus-q": r += q; break;
                case "s-plus-q": s += q; break;
            }

            // Act
            bool result = DsaVerifier.Verify(reference.Key, reference.Digest, r, s);

            // Assert
            Assert.False(result);
        }

        [Fact]
        public void Verify_WithEmptyOrNullInputs_ShouldReturnFalse()
        {
            // Arrange
            ReferenceSignature reference = SignWithBouncyCastle(2048, 256, Hash("SHA-256", Message));

            // Act
            bool emptyDigest = DsaVerifier.Verify(reference.Key, [], reference.R, reference.S);
            bool nullDigest = DsaVerifier.Verify(reference.Key, null!, reference.R, reference.S);
            bool nullKey = DsaVerifier.Verify(null!, reference.Digest, reference.R, reference.S);

            // Assert
            Assert.False(emptyDigest);
            Assert.False(nullDigest);
            Assert.False(nullKey);
        }

        [Theory]
        [InlineData(2048, 224)]
        [InlineData(2048, 256)]
        [InlineData(3072, 256)]
        public void Constructor_WithValidParameters_ShouldExposeValues(int l, int n)
        {
            // Arrange
            DsaParameters parameters = GetParameters(l, n);
            BigInteger y = BigInteger.ModPow(ToNumerics(parameters.G), 12345, ToNumerics(parameters.P));

            // Act
            var key = new DsaPublicKey(ToNumerics(parameters.P), ToNumerics(parameters.Q), ToNumerics(parameters.G), y);

            // Assert
            Assert.Equal(n, key.QBitLength);
            Assert.Equal(ToNumerics(parameters.P), key.P);
            Assert.Equal(ToNumerics(parameters.Q), key.Q);
            Assert.Equal(ToNumerics(parameters.G), key.G);
            Assert.Equal(y, key.Y);
        }

        [Fact]
        public void Constructor_WithLegacy1024BitParameters_ShouldThrow()
        {
            // Arrange: a genuine, internally consistent DSA-1024/160 key.
            DsaParameters parameters = Parameters1024x160.Value;
            BigInteger p = ToNumerics(parameters.P);
            BigInteger g = ToNumerics(parameters.G);
            BigInteger y = BigInteger.ModPow(g, 12345, p);

            // Act
            Action act = () => _ = new DsaPublicKey(p, ToNumerics(parameters.Q), g, y);

            // Assert
            Assert.Equal(1024, Scarlet.OpenPgp.Crypto.BigIntegerMath.BitLength(p));
            Assert.Throws<FailClosedException>(act);
        }

        [Theory]
        [InlineData("q-160-bits")]
        [InlineData("q-255-bits")]
        [InlineData("q-257-bits")]
        [InlineData("q-one")]
        [InlineData("q-zero")]
        [InlineData("q-negative")]
        [InlineData("q-not-dividing-p-minus-1")]
        [InlineData("p-even")]
        [InlineData("p-1024-bits")]
        [InlineData("g-zero")]
        [InlineData("g-one")]
        [InlineData("g-equals-p")]
        [InlineData("g-plus-p")]
        [InlineData("g-negative")]
        [InlineData("g-outside-subgroup")]
        [InlineData("y-zero")]
        [InlineData("y-one")]
        [InlineData("y-p-minus-one")]
        [InlineData("y-equals-p")]
        [InlineData("y-plus-p")]
        [InlineData("y-outside-subgroup")]
        public void Constructor_WithInvalidParameters_ShouldThrow(string variant)
        {
            // Arrange
            DsaParameters parameters = Parameters2048x256.Value;
            BigInteger p = ToNumerics(parameters.P);
            BigInteger q = ToNumerics(parameters.Q);
            BigInteger g = ToNumerics(parameters.G);
            BigInteger y = BigInteger.ModPow(g, 987654321, p);

            // An element almost certainly outside the order-q subgroup: the subgroup holds only
            // q of the p - 1 nonzero residues, so a random-looking value lands in it with
            // probability ~2^-1792. (p - 1 itself has order 2 and is covered separately.)
            BigInteger outsideSubgroup = 3;
            while (BigInteger.ModPow(outsideSubgroup, q, p).IsOne)
            {
                outsideSubgroup++;
            }

            switch (variant)
            {
                case "q-160-bits": q = BigInteger.Pow(2, 159) + 7; break;
                case "q-255-bits": q >>= 1; break;
                case "q-257-bits": q <<= 1; break;
                case "q-one": q = 1; break;
                case "q-zero": q = 0; break;
                case "q-negative": q = -q; break;
                case "q-not-dividing-p-minus-1": q += 2; break;
                case "p-even": p += 1; break;
                case "p-1024-bits": p >>= 1024; break;
                case "g-zero": g = 0; break;
                case "g-one": g = 1; break;
                case "g-equals-p": g = p; break;
                case "g-plus-p": g += p; break; // congruent to a valid g, but not canonical
                case "g-negative": g = -g; break;
                case "g-outside-subgroup": g = outsideSubgroup; break;
                case "y-zero": y = 0; break;
                case "y-one": y = 1; break; // would make every signature verify against g^u1 alone
                case "y-p-minus-one": y = p - 1; break; // order 2
                case "y-equals-p": y = p; break;
                case "y-plus-p": y += p; break;
                case "y-outside-subgroup": y = outsideSubgroup; break;
            }

            // Act
            Action act = () => _ = new DsaPublicKey(p, q, g, y);

            // Assert
            Assert.Throws<FailClosedException>(act);
        }
    }
}
