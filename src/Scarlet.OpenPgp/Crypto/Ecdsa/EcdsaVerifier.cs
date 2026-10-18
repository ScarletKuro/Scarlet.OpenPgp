using System;
using System.Numerics;
using Scarlet.OpenPgp.Packets;

namespace Scarlet.OpenPgp.Crypto.Ecdsa
{
    /// <summary>
    /// ECDSA signature verification over a prime-field <see cref="EcCurve"/>, per FIPS 186-5
    /// §6.4.2 / SEC 1 v2 §4.1.4, as used by OpenPGP public-key algorithm 19 (RFC 9580 §5.2.3.2:
    /// the signature is the two MPIs r and s; the key is an SEC 1 point in an MPI, §5.5.5.4).
    /// </summary>
    /// <remarks>
    /// Every malformed or out-of-range input yields <c>false</c> rather than an exception: a
    /// signature that cannot even be parsed is simply not a valid signature, and keeping all such
    /// paths on the same return value means a caller cannot accidentally treat one as success.
    /// </remarks>
    internal static class EcdsaVerifier
    {
        /// <summary>The SEC 1 v2 §2.3.3 prefix of an uncompressed point, 0x04 || X || Y.</summary>
        private const byte UncompressedPointPrefix = 0x04;

        /// <summary>Verifies ECDSA signature (r, s) over an already-computed message digest.</summary>
        /// <param name="curve">The curve named by the key's OID.</param>
        /// <param name="publicPoint">
        /// The public key Q as an SEC 1 uncompressed point, 0x04 || X || Y, with X and Y each exactly
        /// <see cref="EcCurve.FieldByteLength"/> bytes. Compressed (0x02/0x03), hybrid (0x06/0x07),
        /// and the one-byte infinity encoding (0x00) are all rejected: RFC 9580 §11.2.1 only
        /// defines the uncompressed form for these curves, so anything else is malformed.
        /// </param>
        /// <param name="digest">The hash of the signed data. Truncated to the leftmost bitlen(n) bits if longer.</param>
        /// <param name="r">The signature's r value.</param>
        /// <param name="s">The signature's s value.</param>
        public static bool Verify(EcCurve curve, byte[] publicPoint, byte[] digest, BigInteger r, BigInteger s) =>
            TryDecodePublicPoint(curve, publicPoint, out JacobianPoint q) && Verify(curve, q, digest, r, s);

        /// <summary>Verifies against a public point already decoded and validated by <see cref="TryDecodePublicPoint"/> (cached per key by <see cref="EcdsaPublicKey"/>).</summary>
        /// <param name="curve">The curve.</param>
        /// <param name="q">The validated public point, in affine form (Z = 1).</param>
        /// <param name="digest">The hash of the signed data.</param>
        /// <param name="r">The signature's r value.</param>
        /// <param name="s">The signature's s value.</param>
        public static bool Verify(EcCurve curve, JacobianPoint q, byte[] digest, BigInteger r, BigInteger s)
        {
            if (digest.Length == 0)
            {
                return false;
            }

            // FIPS 186-5 §6.4.2 step 1 / SEC 1 §4.1.4 step 1: r, s in [1, n-1]. Without this,
            // r = 0 or s = 0 (or values ≡ those mod n) open the door to trivial forgeries.
            BigInteger n = curve.N;
            if (r.Sign <= 0 || r >= n || s.Sign <= 0 || s >= n)
            {
                return false;
            }

            // Step 3: e = the leftmost bitlen(n) bits of the digest. Note the truncation is to n's
            // bit length, not its byte length - that differs for P-521 (521-bit n, SHA-512's 512
            // bits are used whole) and is a recurring interoperability bug.
            BigInteger e = BigIntegerMath.LeftmostBits(digest, curve.OrderBitLength);

            // Steps 4-5: w = s⁻¹ mod n, u1 = e·w mod n, u2 = r·w mod n. n is prime and s in [1, n-1],
            // so the inverse always exists.
            if (!BigIntegerMath.TryModInverse(s, n, out BigInteger w))
            {
                return false;
            }

            BigInteger u1 = (e * w) % n;
            BigInteger u2 = (r * w) % n;

            // Step 5-6: R = u1·G + u2·Q; reject if R = O.
            JacobianPoint g = JacobianPoint.FromAffine(curve.Gx, curve.Gy);
            JacobianPoint point = JacobianPoint.MultiplyAdd(curve, u1, g, u2, q);
            if (!point.TryToAffine(curve, out BigInteger x, out _))
            {
                return false;
            }

            // Steps 7-8: v = x_R mod n; valid iff v == r. x_R is in [0, p) and p can exceed n,
            // so the reduction is required.
            BigInteger v = x % n;
            return v == r;
        }

        /// <summary>
        /// Decodes and fully validates an uncompressed SEC 1 point (SEC 1 v2 §2.3.4 and the public
        /// key validation of §3.2.2.1): exact length, 0x04 prefix, each coordinate &lt; p, and the
        /// curve equation. The point at infinity has no uncompressed encoding, so it is excluded
        /// by construction. Skipping the on-curve check would enable invalid-curve attacks.
        /// </summary>
        internal static bool TryDecodePublicPoint(EcCurve curve, byte[] encoded, out JacobianPoint point)
        {
            point = JacobianPoint.Infinity;
            int fieldLength = curve.FieldByteLength;
            if (encoded.Length != 1 + (2 * fieldLength) || encoded[0] != UncompressedPointPrefix)
            {
                return false;
            }

            var xBytes = new byte[fieldLength];
            var yBytes = new byte[fieldLength];
            Array.Copy(encoded, 1, xBytes, 0, fieldLength);
            Array.Copy(encoded, 1 + fieldLength, yBytes, 0, fieldLength);
            BigInteger x = Mpi.ToUnsignedBigInteger(xBytes);
            BigInteger y = Mpi.ToUnsignedBigInteger(yBytes);

            if (!curve.IsOnCurve(x, y))
            {
                return false;
            }

            point = JacobianPoint.FromAffine(x, y);
            return true;
        }
    }
}
