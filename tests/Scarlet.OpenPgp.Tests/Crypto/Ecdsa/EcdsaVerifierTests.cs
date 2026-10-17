using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Security;
using Scarlet.OpenPgp.Crypto.Ecdsa;
using Scarlet.OpenPgp.Packets;
using BcBigInteger = Org.BouncyCastle.Math.BigInteger;

namespace Scarlet.OpenPgp.Tests.Crypto.Ecdsa
{
    public class EcdsaVerifierTests
    {
        private static readonly byte[] Message = "Scarlet.OpenPgp ECDSA test message"u8.ToArray();

        private sealed class ReferenceSignature
        {
            public ReferenceSignature(EcCurve curve, byte[] publicPoint, byte[] compressedPoint, byte[] digest, BigInteger r, BigInteger s)
            {
                Curve = curve;
                PublicPoint = publicPoint;
                CompressedPoint = compressedPoint;
                Digest = digest;
                R = r;
                S = s;
            }

            public EcCurve Curve { get; }

            public byte[] PublicPoint { get; }

            public byte[] CompressedPoint { get; }

            public byte[] Digest { get; }

            public BigInteger R { get; }

            public BigInteger S { get; }
        }

        // BouncyCastle's ECDsaSigner is the independent reference: it implements the same
        // FIPS 186 / SEC 1 algorithm (including the leftmost-bitlen(n)-bits digest truncation),
        // so any disagreement points at a bug in this library's from-scratch arithmetic.
        private static ReferenceSignature SignWithBouncyCastle(string curveName, byte[] digest)
        {
            ECDomainParameters domain = EcTestCurves.GetReferenceDomain(curveName);
            var generator = new ECKeyPairGenerator();
            generator.Init(new ECKeyGenerationParameters(domain, new SecureRandom()));
            AsymmetricCipherKeyPair keyPair = generator.GenerateKeyPair();

            var signer = new ECDsaSigner();
            signer.Init(true, keyPair.Private);
            BcBigInteger[] signature = signer.GenerateSignature(digest);

            var publicKey = (ECPublicKeyParameters)keyPair.Public;
            return new ReferenceSignature(
                EcTestCurves.Get(curveName),
                publicKey.Q.GetEncoded(false),
                publicKey.Q.GetEncoded(true),
                digest,
                EcTestCurves.ToNumerics(signature[0]),
                EcTestCurves.ToNumerics(signature[1]));
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
                    throw new System.ArgumentOutOfRangeException(nameof(hashName), hashName, null);
            }

            digest.BlockUpdate(data, 0, data.Length);
            var result = new byte[digest.GetDigestSize()];
            digest.DoFinal(result, 0);
            return result;
        }

        [Theory]
        [InlineData("P-256", "SHA-256")]
        [InlineData("P-256", "SHA-384")] // digest longer than n: truncated
        [InlineData("P-256", "SHA-512")]
        [InlineData("P-384", "SHA-256")] // digest shorter than n: used whole
        [InlineData("P-384", "SHA-384")]
        [InlineData("P-384", "SHA-512")]
        [InlineData("P-521", "SHA-256")]
        [InlineData("P-521", "SHA-384")]
        [InlineData("P-521", "SHA-512")] // 512 bits < bitlen(n) = 521: NOT truncated
        [InlineData("brainpoolP256r1", "SHA-256")]
        [InlineData("brainpoolP256r1", "SHA-384")]
        [InlineData("brainpoolP256r1", "SHA-512")]
        [InlineData("brainpoolP384r1", "SHA-256")]
        [InlineData("brainpoolP384r1", "SHA-384")]
        [InlineData("brainpoolP384r1", "SHA-512")]
        [InlineData("brainpoolP512r1", "SHA-256")]
        [InlineData("brainpoolP512r1", "SHA-384")]
        [InlineData("brainpoolP512r1", "SHA-512")]
        public void Verify_WithBouncyCastleSignature_ShouldReturnTrue(string curveName, string hashName)
        {
            for (int i = 0; i < 3; i++)
            {
                // Arrange
                ReferenceSignature reference = SignWithBouncyCastle(curveName, Hash(hashName, Encoding.ASCII.GetBytes("message #" + i)));

                // Act
                bool result = EcdsaVerifier.Verify(reference.Curve, reference.PublicPoint, reference.Digest, reference.R, reference.S);

                // Assert
                Assert.True(result);
            }
        }

        [Theory]
        [InlineData("P-256", 33)] // 264 bits: 8-bit right shift
        [InlineData("P-521", 66)] // 528 bits vs 521-bit n: a 7-bit, non-byte-aligned shift
        [InlineData("P-521", 67)]
        [InlineData("brainpoolP384r1", 64)]
        [InlineData("brainpoolP512r1", 20)]
        [InlineData("P-256", 1)]
        public void Verify_WithArbitraryLengthDigest_ShouldTruncateLikeBouncyCastle(string curveName, int digestLength)
        {
            for (int i = 0; i < 3; i++)
            {
                // Arrange: random bytes with the top bit forced on, so a byte- instead of a
                // bit-granular truncation (or none at all) would produce a different e.
                byte[] digest = RandomNumberGenerator.GetBytes(digestLength);
                digest[0] |= 0x80;
                ReferenceSignature reference = SignWithBouncyCastle(curveName, digest);

                // Act
                bool result = EcdsaVerifier.Verify(reference.Curve, reference.PublicPoint, reference.Digest, reference.R, reference.S);

                // Assert
                Assert.True(result);
            }
        }

        [Fact]
        public void Verify_WithAllOnesDigestExceedingOrder_ShouldReturnTrue()
        {
            // Arrange: e = 2^256 - 1 > n for P-256; e is used mod n via u1 = e·w mod n.
            byte[] digest = Enumerable.Repeat((byte)0xFF, 32).ToArray();
            ReferenceSignature reference = SignWithBouncyCastle("P-256", digest);

            // Act
            bool result = EcdsaVerifier.Verify(reference.Curve, reference.PublicPoint, reference.Digest, reference.R, reference.S);

            // Assert
            Assert.True(result);
        }

        [Theory]
        [InlineData("nistP256", "SHA-256")]
        [InlineData("nistP256", "SHA-512")]
        [InlineData("nistP384", "SHA-384")]
        [InlineData("nistP384", "SHA-256")]
        [InlineData("nistP521", "SHA-512")]
        [InlineData("nistP521", "SHA-256")]
        public void Verify_WithSystemSecurityCryptographySignature_ShouldReturnTrue(string curveName, string hashName)
        {
            // Arrange: .NET's platform ECDSA (CNG on Windows) as a second, unrelated reference.
            ECCurve dotnetCurve;
            EcCurve curve;
            switch (curveName)
            {
                case "nistP256":
                    dotnetCurve = ECCurve.NamedCurves.nistP256;
                    curve = EcCurve.NistP256;
                    break;
                case "nistP384":
                    dotnetCurve = ECCurve.NamedCurves.nistP384;
                    curve = EcCurve.NistP384;
                    break;
                default:
                    dotnetCurve = ECCurve.NamedCurves.nistP521;
                    curve = EcCurve.NistP521;
                    break;
            }

            using ECDsa ecdsa = ECDsa.Create(dotnetCurve);
            byte[] digest = Hash(hashName, Message);
            byte[] signature = ecdsa.SignHash(digest); // IEEE P1363: r || s, each ceil(bitlen(n)/8) bytes
            int half = signature.Length / 2;
            BigInteger r = Mpi.ToUnsignedBigInteger(signature[..half]);
            BigInteger s = Mpi.ToUnsignedBigInteger(signature[half..]);

            ECParameters parameters = ecdsa.ExportParameters(false);
            byte[] publicPoint = [0x04, .. parameters.Q.X!, .. parameters.Q.Y!];

            // Act
            bool result = EcdsaVerifier.Verify(curve, publicPoint, digest, r, s);

            // Assert
            Assert.Equal(curve.FieldByteLength * 2, signature.Length);
            Assert.True(result);
        }

        [Fact]
        public void Verify_WithTamperedDigest_ShouldReturnFalse()
        {
            // Arrange
            ReferenceSignature reference = SignWithBouncyCastle("P-256", Hash("SHA-256", Message));
            byte[] digest = (byte[])reference.Digest.Clone();
            digest[^1] ^= 0x01;

            // Act
            bool result = EcdsaVerifier.Verify(reference.Curve, reference.PublicPoint, digest, reference.R, reference.S);

            // Assert
            Assert.False(result);
        }

        [Fact]
        public void Verify_WithTamperedDigestBitsBeyondTruncation_ShouldReturnTrue()
        {
            // Arrange: for P-256 only the leftmost 256 bits of a SHA-512 digest count, so flipping
            // a bit in the discarded tail must not change the outcome. This pins the truncation
            // direction (leftmost bits, not rightmost).
            ReferenceSignature reference = SignWithBouncyCastle("P-256", Hash("SHA-512", Message));
            byte[] digest = (byte[])reference.Digest.Clone();
            digest[^1] ^= 0x01;

            // Act
            bool result = EcdsaVerifier.Verify(reference.Curve, reference.PublicPoint, digest, reference.R, reference.S);

            // Assert
            Assert.True(result);
        }

        [Theory]
        [InlineData("P-256")]
        [InlineData("P-521")]
        [InlineData("brainpoolP384r1")]
        public void Verify_WithTamperedRorS_ShouldReturnFalse(string curveName)
        {
            // Arrange
            ReferenceSignature reference = SignWithBouncyCastle(curveName, Hash("SHA-256", Message));

            // Act
            bool rPlusOne = EcdsaVerifier.Verify(reference.Curve, reference.PublicPoint, reference.Digest, reference.R + 1, reference.S);
            bool sPlusOne = EcdsaVerifier.Verify(reference.Curve, reference.PublicPoint, reference.Digest, reference.R, reference.S + 1);
            bool swapped = EcdsaVerifier.Verify(reference.Curve, reference.PublicPoint, reference.Digest, reference.S, reference.R);

            // Assert
            Assert.False(rPlusOne);
            Assert.False(sPlusOne);
            Assert.False(swapped);
        }

        [Fact]
        public void Verify_WithNegatedS_ShouldReturnTrue()
        {
            // Arrange: ECDSA is inherently malleable - (r, n - s) is equally valid because -R and R
            // share an x coordinate. Pinned here so nobody mistakes it for a bug; OpenPGP does not
            // rely on signature uniqueness.
            ReferenceSignature reference = SignWithBouncyCastle("P-256", Hash("SHA-256", Message));

            // Act
            bool result = EcdsaVerifier.Verify(reference.Curve, reference.PublicPoint, reference.Digest, reference.R, reference.Curve.N - reference.S);

            // Assert
            Assert.True(result);
        }

        [Fact]
        public void Verify_WithWrongPublicKey_ShouldReturnFalse()
        {
            // Arrange
            ReferenceSignature reference = SignWithBouncyCastle("brainpoolP256r1", Hash("SHA-256", Message));
            ReferenceSignature other = SignWithBouncyCastle("brainpoolP256r1", Hash("SHA-256", Message));

            // Act
            bool result = EcdsaVerifier.Verify(reference.Curve, other.PublicPoint, reference.Digest, reference.R, reference.S);

            // Assert
            Assert.False(result);
        }

        [Fact]
        public void Verify_WithWrongCurveOfSameSize_ShouldReturnFalse()
        {
            // Arrange: a P-256 point has the right length for brainpoolP256r1 but is not on it.
            ReferenceSignature reference = SignWithBouncyCastle("P-256", Hash("SHA-256", Message));

            // Act
            bool result = EcdsaVerifier.Verify(EcCurve.BrainpoolP256r1, reference.PublicPoint, reference.Digest, reference.R, reference.S);

            // Assert
            Assert.False(result);
        }

        [Fact]
        public void Verify_WithWrongCurveOfDifferentSize_ShouldReturnFalse()
        {
            // Arrange
            ReferenceSignature reference = SignWithBouncyCastle("P-384", Hash("SHA-384", Message));

            // Act
            bool result = EcdsaVerifier.Verify(EcCurve.NistP256, reference.PublicPoint, reference.Digest, reference.R, reference.S);

            // Assert
            Assert.False(result);
        }

        [Theory]
        [InlineData("zero-r")]
        [InlineData("zero-s")]
        [InlineData("negative-r")]
        [InlineData("negative-s")]
        [InlineData("r-equals-n")]
        [InlineData("s-equals-n")]
        [InlineData("r-plus-n")]
        [InlineData("s-plus-n")]
        public void Verify_WithOutOfRangeScalar_ShouldReturnFalse(string variant)
        {
            // Arrange: r + n and s + n are congruent to valid values mod n, so these would verify
            // if the [1, n-1] range check were missing.
            ReferenceSignature reference = SignWithBouncyCastle("P-256", Hash("SHA-256", Message));
            BigInteger n = reference.Curve.N;
            BigInteger r = reference.R;
            BigInteger s = reference.S;
            switch (variant)
            {
                case "zero-r": r = 0; break;
                case "zero-s": s = 0; break;
                case "negative-r": r = -r; break;
                case "negative-s": s = -s; break;
                case "r-equals-n": r = n; break;
                case "s-equals-n": s = n; break;
                case "r-plus-n": r += n; break;
                case "s-plus-n": s += n; break;
            }

            // Act
            bool result = EcdsaVerifier.Verify(reference.Curve, reference.PublicPoint, reference.Digest, r, s);

            // Assert
            Assert.False(result);
        }

        [Fact]
        public void Verify_WithOffCurvePoint_ShouldReturnFalse()
        {
            // Arrange
            ReferenceSignature reference = SignWithBouncyCastle("P-256", Hash("SHA-256", Message));
            byte[] point = (byte[])reference.PublicPoint.Clone();
            point[^1] ^= 0x01;

            // Act
            bool result = EcdsaVerifier.Verify(reference.Curve, point, reference.Digest, reference.R, reference.S);

            // Assert
            Assert.False(result);
        }

        [Fact]
        public void Verify_WithCompressedPoint_ShouldReturnFalse()
        {
            // Arrange
            ReferenceSignature reference = SignWithBouncyCastle("P-256", Hash("SHA-256", Message));

            // Act
            bool result = EcdsaVerifier.Verify(reference.Curve, reference.CompressedPoint, reference.Digest, reference.R, reference.S);

            // Assert
            Assert.Equal(33, reference.CompressedPoint.Length);
            Assert.False(result);
        }

        [Theory]
        [InlineData(0x00)]
        [InlineData(0x02)]
        [InlineData(0x03)]
        [InlineData(0x06)] // hybrid encodings
        [InlineData(0x07)]
        [InlineData(0x40)] // native/prefixed (RFC 9580 §11.2.2) - not valid for these curves
        public void Verify_WithWrongPointPrefix_ShouldReturnFalse(int prefix)
        {
            // Arrange
            ReferenceSignature reference = SignWithBouncyCastle("P-256", Hash("SHA-256", Message));
            byte[] point = (byte[])reference.PublicPoint.Clone();
            point[0] = (byte)prefix;

            // Act
            bool result = EcdsaVerifier.Verify(reference.Curve, point, reference.Digest, reference.R, reference.S);

            // Assert
            Assert.False(result);
        }

        [Theory]
        [InlineData("drop-last")]
        [InlineData("append-zero")]
        [InlineData("strip-leading-zero-pad")]
        [InlineData("infinity")]
        [InlineData("empty")]
        public void Verify_WithWrongPointLength_ShouldReturnFalse(string variant)
        {
            // Arrange
            ReferenceSignature reference = SignWithBouncyCastle("P-521", Hash("SHA-512", Message));
            byte[] point = reference.PublicPoint;
            switch (variant)
            {
                case "drop-last": point = point[..^1]; break;
                case "append-zero": point = [.. point, 0x00]; break;
                case "strip-leading-zero-pad": point = [0x04, .. point[2..]]; break; // X is 66 bytes, top byte <= 0x01
                case "infinity": point = [0x00]; break;
                case "empty": point = []; break;
            }

            // Act
            bool result = EcdsaVerifier.Verify(reference.Curve, point, reference.Digest, reference.R, reference.S);

            // Assert
            Assert.Equal(1 + (2 * 66), reference.PublicPoint.Length);
            Assert.False(result);
        }

        [Fact]
        public void Verify_WithCoordinateNotReducedModP_ShouldReturnFalse()
        {
            // Arrange: replace X with X + p where that still fits in the field length. For
            // brainpoolP256r1 (p ≈ 0.66·2^256) any X < 2^256 - p can be shifted up this way, and
            // the curve equation still holds mod p - only the explicit "< p" check rejects it.
            EcCurve curve = EcCurve.BrainpoolP256r1;
            ReferenceSignature reference;
            BigInteger x;
            do
            {
                reference = SignWithBouncyCastle("brainpoolP256r1", Hash("SHA-256", Message));
                x = Mpi.ToUnsignedBigInteger(reference.PublicPoint[1..33]);
            }
            while (x + curve.P >= BigInteger.Pow(2, 256));

            byte[] point = (byte[])reference.PublicPoint.Clone();
            Mpi.ToFixedLengthUnsignedBytes(x + curve.P, 32).CopyTo(point, 1);

            // Act
            bool result = EcdsaVerifier.Verify(curve, point, reference.Digest, reference.R, reference.S);

            // Assert
            Assert.True(EcdsaVerifier.Verify(curve, reference.PublicPoint, reference.Digest, reference.R, reference.S));
            Assert.False(result);
        }

        [Fact]
        public void Verify_WithEmptyDigest_ShouldReturnFalse()
        {
            // Arrange
            ReferenceSignature reference = SignWithBouncyCastle("P-256", Hash("SHA-256", Message));

            // Act
            bool emptyDigest = EcdsaVerifier.Verify(reference.Curve, reference.PublicPoint, [], reference.R, reference.S);

            // Assert
            Assert.False(emptyDigest);
        }

        [Fact]
        public void Verify_WithBasePointAsPublicKeyAndForgedValues_ShouldReturnFalse()
        {
            // Arrange: a sanity check that arbitrary (r, s) in range do not verify by accident.
            EcCurve curve = EcCurve.NistP256;
            byte[] point = [0x04, .. Mpi.ToFixedLengthUnsignedBytes(curve.Gx, 32), .. Mpi.ToFixedLengthUnsignedBytes(curve.Gy, 32)];
            byte[] digest = Hash("SHA-256", Message);

            // Act
            bool result = EcdsaVerifier.Verify(curve, point, digest, 1, 1);

            // Assert
            Assert.False(result);
        }
    }
}
