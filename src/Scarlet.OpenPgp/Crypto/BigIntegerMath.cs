using System.Numerics;

namespace Scarlet.OpenPgp.Crypto
{
    /// <summary>
    /// Small <see cref="BigInteger"/> helpers shared by the ECDSA and DSA verifiers that
    /// netstandard2.0's <see cref="BigInteger"/> lacks (no <c>GetBitLength</c>, no modular inverse,
    /// and a <c>%</c> operator that keeps the dividend's sign rather than returning a canonical
    /// residue).
    /// </summary>
    internal static class BigIntegerMath
    {
        /// <summary>
        /// The number of bits needed to represent a non-negative <paramref name="value"/>: 0 for
        /// zero, otherwise the 1-based position of its highest set bit.
        /// </summary>
        public static int BitLength(BigInteger value)
        {
            if (value.Sign <= 0)
            {
                return 0;
            }

            // ToByteArray is little-endian two's complement; for a positive value the top byte may
            // be a 0x00 sign guard, which the scan below skips naturally.
            byte[] bytes = value.ToByteArray();
            int top = bytes.Length - 1;
            while (bytes[top] == 0)
            {
                top--;
            }

            int bits = top * 8;
            int topByte = bytes[top];
            while (topByte != 0)
            {
                topByte >>= 1;
                bits++;
            }

            return bits;
        }

        /// <summary>The canonical residue of <paramref name="value"/> modulo a positive <paramref name="modulus"/>, always in [0, modulus).</summary>
        public static BigInteger Mod(BigInteger value, BigInteger modulus)
        {
            BigInteger r = BigInteger.Remainder(value, modulus);
            return r.Sign < 0 ? r + modulus : r;
        }

        /// <summary>
        /// The multiplicative inverse of <paramref name="value"/> modulo <paramref name="modulus"/>,
        /// via the extended Euclidean algorithm. Returns <c>false</c> when no inverse exists
        /// (gcd ≠ 1). Euclid rather than Fermat's a^(m-2) because the DSA subgroup order q comes from
        /// an untrusted key packet and is never primality-tested: with a composite q, Fermat would
        /// silently compute a wrong "inverse" instead of reporting that none exists.
        /// </summary>
        public static bool TryModInverse(BigInteger value, BigInteger modulus, out BigInteger inverse)
        {
            inverse = BigInteger.Zero;
            if (modulus.Sign <= 0)
            {
                return false;
            }

            BigInteger oldR = Mod(value, modulus);
            BigInteger r = modulus;
            BigInteger oldS = BigInteger.One;
            BigInteger s = BigInteger.Zero;

            while (!r.IsZero)
            {
                BigInteger quotient = BigInteger.Divide(oldR, r);
                BigInteger nextR = oldR - (quotient * r);
                oldR = r;
                r = nextR;

                BigInteger nextS = oldS - (quotient * s);
                oldS = s;
                s = nextS;
            }

            if (!oldR.IsOne)
            {
                return false;
            }

            inverse = Mod(oldS, modulus);
            return true;
        }

        /// <summary>
        /// Interprets <paramref name="digest"/> as a big-endian unsigned integer and keeps only its
        /// leftmost <paramref name="maxBits"/> bits - the hash-truncation rule shared by DSA
        /// (FIPS 186-4 §4.6: "z = the leftmost min(N, outlen) bits of Hash(M)") and ECDSA
        /// (FIPS 186-5 §6.4.1 step 3 / SEC 1 v2 §4.1.4 step 5). Truncation is by whole bits on the
        /// left; a digest no longer than <paramref name="maxBits"/> is used whole, without padding.
        /// </summary>
        public static BigInteger LeftmostBits(byte[] digest, int maxBits)
        {
            BigInteger value = Packets.Mpi.ToUnsignedBigInteger(digest);
            long digestBits = (long)digest.Length * 8;
            if (digestBits > maxBits)
            {
                value >>= (int)(digestBits - maxBits);
            }

            return value;
        }
    }
}
