using System.Numerics;

namespace Scarlet.OpenPgp.Crypto.Rsa
{
    /// <summary>An RSA public key's modulus and public exponent, as parsed from a v4 public-key packet.</summary>
    internal sealed class RsaPublicKey
    {
        public RsaPublicKey(BigInteger modulus, BigInteger exponent)
        {
            Modulus = modulus;
            Exponent = exponent;
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
