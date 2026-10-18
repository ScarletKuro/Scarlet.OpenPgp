using System.Numerics;
using Scarlet.OpenPgp.Hashing;
using Scarlet.OpenPgp.Packets;

namespace Scarlet.OpenPgp.Crypto.Rsa
{
    /// <summary>RSA signature verification per RFC 8017 §8.2.2 / §9.2 (EMSA-PKCS1-v1_5): recover the padded block via modular exponentiation, then check its structure byte-for-byte.</summary>
    internal static class RsaPkcs1Verifier
    {
        /// <summary>How many bits shorter than the modulus a signature value may be.</summary>
        public const int MaxSignatureShortfallBits = 64;

        public static bool Verify(RsaPublicKey key, HashAlgorithmId hashAlgorithm, byte[] digest, BigInteger signature)
        {
            if (signature.Sign < 0 || signature >= key.Modulus)
            {
                return false;
            }

            // A real signature is a random-looking value below the modulus: the chance it is more
            // than 64 bits shorter is 2^-64. Rejecting those costs nothing legitimate, and stops a
            // 4-byte "signature" buying a full exponentiation modulo a 16384-bit key - which made a
            // small file of them cost minutes of work.
            if (BigIntegerMath.BitLength(signature) < key.ModulusBitLength - MaxSignatureShortfallBits)
            {
                return false;
            }

            int k = key.ModulusByteLength;
            BigInteger recovered = BigInteger.ModPow(signature, key.Exponent, key.Modulus);

            byte[] em;
            try
            {
                em = Mpi.ToFixedLengthUnsignedBytes(recovered, k);
            }
            catch (Internal.FailClosedException)
            {
                return false;
            }

            byte[] prefix;
            try
            {
                prefix = DigestInfoPrefixes.Get(hashAlgorithm);
            }
            catch (Internal.FailClosedException)
            {
                return false;
            }

            byte[] expected = BuildExpectedBlock(k, prefix, digest);
            if (expected.Length != em.Length)
            {
                return false;
            }

            for (int i = 0; i < em.Length; i++)
            {
                if (em[i] != expected[i])
                {
                    return false;
                }
            }

            return true;
        }

        private static byte[] BuildExpectedBlock(int k, byte[] digestInfoPrefix, byte[] digest)
        {
            // EM = 0x00 || 0x01 || PS (0xFF, at least 8 bytes) || 0x00 || DigestInfoPrefix || digest
            int fixedLength = 3 + digestInfoPrefix.Length + digest.Length;
            int padLength = k - fixedLength;
            if (padLength < 8)
            {
                return []; // signals "does not fit"; will never byte-match em
            }

            var em = new byte[k];
            em[0] = 0x00;
            em[1] = 0x01;
            for (int i = 0; i < padLength; i++)
            {
                em[2 + i] = 0xFF;
            }

            int offset = 2 + padLength;
            em[offset] = 0x00;
            offset += 1;
            System.Array.Copy(digestInfoPrefix, 0, em, offset, digestInfoPrefix.Length);
            offset += digestInfoPrefix.Length;
            System.Array.Copy(digest, 0, em, offset, digest.Length);
            return em;
        }
    }
}
