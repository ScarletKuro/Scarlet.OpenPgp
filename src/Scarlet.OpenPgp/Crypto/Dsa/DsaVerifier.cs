using System.Numerics;

namespace Scarlet.OpenPgp.Crypto.Dsa
{
    /// <summary>
    /// DSA signature verification per FIPS 186-4 §4.7, as used by OpenPGP public-key algorithm 17
    /// (RFC 9580 §5.2.3.2: the signature is the two MPIs r and s).
    /// </summary>
    /// <remarks>
    /// Every malformed or out-of-range input yields <c>false</c> rather than an exception, so no
    /// error path can be mistaken for success.
    /// </remarks>
    internal static class DsaVerifier
    {
        /// <summary>Verifies DSA signature (r, s) over an already-computed message digest.</summary>
        /// <param name="key">The validated public key.</param>
        /// <param name="digest">
        /// The hash of the signed data. Must be at least N = bitlen(q) bits long: RFC 9580 §5.2.3.2
        /// says a DSA signature "MUST use a hash algorithm with a digest size of at least the number
        /// of bits of q", and accepting a shorter one would let a weak hash undercut the key. A
        /// longer digest is truncated to its leftmost N bits.
        /// </param>
        /// <param name="r">The signature's r value.</param>
        /// <param name="s">The signature's s value.</param>
        public static bool Verify(DsaPublicKey key, byte[] digest, BigInteger r, BigInteger s)
        {
            if ((long)digest.Length * 8 < key.QBitLength)
            {
                return false;
            }

            // FIPS 186-4 §4.7 step 1: reject unless 0 < r < q and 0 < s < q. r = 0 or s = 0 would
            // otherwise make v trivially predictable.
            BigInteger q = key.Q;
            if (r.Sign <= 0 || r >= q || s.Sign <= 0 || s >= q)
            {
                return false;
            }

            // Step 2: z = the leftmost min(N, outlen) bits of Hash(M).
            BigInteger z = BigIntegerMath.LeftmostBits(digest, key.QBitLength);

            // Step 3: w = s⁻¹ mod q. q is not primality-tested (see DsaPublicKey), so the inverse
            // may genuinely not exist; that is a failed verification, not a crash.
            if (!BigIntegerMath.TryModInverse(s, q, out BigInteger w))
            {
                return false;
            }

            // Steps 4-5: u1 = z·w mod q, u2 = r·w mod q, v = ((g^u1 · y^u2) mod p) mod q.
            BigInteger u1 = (z * w) % q;
            BigInteger u2 = (r * w) % q;
            BigInteger p = key.P;
            BigInteger v = ((BigInteger.ModPow(key.G, u1, p) * BigInteger.ModPow(key.Y, u2, p)) % p) % q;

            // Step 6: valid iff v == r.
            return v == r;
        }
    }
}
