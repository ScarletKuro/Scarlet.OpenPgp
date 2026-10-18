using System.Numerics;
using Scarlet.OpenPgp.Hashing;
using Scarlet.OpenPgp.Internal;

namespace Scarlet.OpenPgp.Crypto.Rsa
{
    /// <summary>An RSA public key's modulus and public exponent, as parsed from a v4 public-key packet.</summary>
    internal sealed class RsaPublicKey : VerificationKey
    {
        /// <summary>The smallest modulus accepted. 1024-bit RSA is within reach of well-funded attackers, and NIST has disallowed anything below 2048 bits for signatures since 2013.</summary>
        public const int MinimumModulusBitLength = 2048;

        /// <summary>The largest modulus accepted - GnuPG's own limit. Bigger moduli serve no security purpose and make each verification take minutes.</summary>
        public const int MaximumModulusBitLength = 16384;

        /// <summary>The largest public exponent accepted, in bits. Real keys use small exponents (65537, 17, 3); a huge one only makes every verification slower.</summary>
        public const int MaximumExponentBitLength = 32;

        public RsaPublicKey(BigInteger modulus, BigInteger exponent)
        {
            Modulus = modulus;
            Exponent = exponent;

            // Fail closed on structurally weak or nonsensical keys rather than "verifying" against
            // them: with e = 1 the signature *is* the encoded message, so anyone can forge one, and
            // an even modulus or exponent can never be a real RSA key.
            // Sizes outside the policy are "unsupported" (a well-formed key this library declines);
            // impossible values are malformed. A key ring skips the former and rejects the latter.
            if (modulus.IsEven)
            {
                throw new FailClosedException("RSA modulus must be odd.");
            }

            // Computed once: verification needs the byte length on every call, and finding it by
            // shifting the modulus a bit at a time allocated a fresh BigInteger per bit.
            ModulusBitLength = BigIntegerMath.BitLength(modulus);
            ModulusByteLength = (ModulusBitLength + 7) / 8;
            if (ModulusBitLength < MinimumModulusBitLength || ModulusBitLength > MaximumModulusBitLength)
            {
                throw FailClosedException.Unsupported("RSA modulus must be between " + MinimumModulusBitLength + " and " + MaximumModulusBitLength + " bits.");
            }

            if (exponent.IsEven || exponent < 3 || exponent >= modulus)
            {
                throw new FailClosedException("RSA public exponent must be odd, at least 3, and smaller than the modulus.");
            }

            if (BigIntegerMath.BitLength(exponent) > MaximumExponentBitLength)
            {
                throw FailClosedException.Unsupported("RSA public exponent must be at most " + MaximumExponentBitLength + " bits.");
            }

            double scale = (double)ModulusBitLength / 1024;
            CheckCost = (int)System.Math.Ceiling(BigIntegerMath.BitLength(exponent) * scale * scale / 200);
        }

        public BigInteger Modulus { get; }

        public BigInteger Exponent { get; }

        public int ModulusBitLength { get; }

        /// <summary>The modulus size in octets, i.e. the fixed width used to render the recovered EMSA-PKCS1-v1_5 block.</summary>
        public int ModulusByteLength { get; }

        public override string Description => "RSA " + ModulusBitLength.ToString(System.Globalization.CultureInfo.InvariantCulture);

        /// <summary>RFC 9580 sets no minimum for RSA; the hash policy itself rejects MD5, RIPEMD-160 and (for documents) SHA-1.</summary>
        public override int MinimumHashBits => 0;

        /// <summary>One modular squaring per exponent bit, each quadratic in the modulus size: about 0.23 ms for RSA-3072 with e = 65537, 12 ms for RSA-16384 with a 32-bit exponent.</summary>
        public override int CheckCost { get; }

        public override bool Verify(HashAlgorithmId hashAlgorithm, byte[] digest, SignatureValue signature) =>
            signature is RsaSignatureValue rsa && RsaPkcs1Verifier.Verify(this, hashAlgorithm, digest, rsa.Value);
    }
}
