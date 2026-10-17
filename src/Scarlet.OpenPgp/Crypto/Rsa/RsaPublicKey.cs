using System.Numerics;
using Scarlet.OpenPgp.Internal;

namespace Scarlet.OpenPgp.Crypto.Rsa
{
    /// <summary>An RSA public key's modulus and public exponent, as parsed from a v4 public-key packet.</summary>
    internal sealed class RsaPublicKey
    {
        /// <summary>The smallest modulus accepted. 1024-bit RSA is within reach of well-funded attackers, and NIST has disallowed anything below 2048 bits for signatures since 2013.</summary>
        public const int MinimumModulusBitLength = 2048;

        public RsaPublicKey(BigInteger modulus, BigInteger exponent)
        {
            Modulus = modulus;
            Exponent = exponent;

            // Fail closed on structurally weak or nonsensical keys rather than "verifying" against
            // them: with e = 1 the signature *is* the encoded message, so anyone can forge one, and
            // an even modulus or exponent can never be a real RSA key.
            if (modulus.IsEven || ModulusBitLength < MinimumModulusBitLength)
            {
                throw new FailClosedException("RSA modulus must be odd and at least " + MinimumModulusBitLength + " bits.");
            }

            if (exponent.IsEven || exponent < 3 || exponent >= modulus)
            {
                throw new FailClosedException("RSA public exponent must be odd, at least 3, and smaller than the modulus.");
            }
        }

        public BigInteger Modulus { get; }

        public BigInteger Exponent { get; }

        /// <summary>The modulus size in octets, i.e. the fixed width used to render the recovered EMSA-PKCS1-v1_5 block.</summary>
        public int ModulusByteLength => (ModulusBitLength + 7) / 8;

        private int ModulusBitLength
        {
            get
            {
                int bits = 0;
                BigInteger value = Modulus;
                while (value > 0)
                {
                    value >>= 1;
                    bits++;
                }

                return bits;
            }
        }
    }
}
