using System;
using System.Numerics;
using System.Security.Cryptography;

namespace Scarlet.OpenPgp.Crypto.Ed25519
{
    /// <summary>
    /// Ed25519 signature verification (RFC 8032 §5.1.7), using the primary verification equation
    /// [S]B = R + [k]A - the RFC explicitly states this is "sufficient, but not required" versus
    /// the cofactor-multiplied [8][S]B = [8]R + [8][k]A form some implementations use to reject
    /// small-order-subgroup signatures; the simpler form is what this library implements.
    /// </summary>
    internal static class Ed25519Verifier
    {
        /// <summary>The curve's cofactor h: the full group has order h * L (RFC 8032 §5.1).</summary>
        public const int Cofactor = 8;

        private static readonly BigInteger GroupOrderL =
            BigInteger.Pow(2, 252) + BigInteger.Parse("27742317777372353535851937790883648493", System.Globalization.CultureInfo.InvariantCulture);

        public static bool Verify(Ed25519PublicKey publicKey, byte[] message, byte[] signature)
        {
            if (signature.Length != 64)
            {
                return false;
            }

            // Decoded once per key; small-order keys fail here (see Ed25519PublicKey.TryGetValidPoint).
            if (!publicKey.TryGetValidPoint(out EdwardsPoint a))
            {
                return false;
            }

            var rBytes = new byte[32];
            var sBytes = new byte[32];
            Array.Copy(signature, 0, rBytes, 0, 32);
            Array.Copy(signature, 32, sBytes, 0, 32);

            if (!PointDecoder.TryDecode(rBytes, out EdwardsPoint r))
            {
                return false;
            }

            BigInteger s = PointDecoder.LittleEndianToBigInteger(sBytes);
            if (s >= GroupOrderL)
            {
                return false;
            }

            byte[] hash = ComputeSha512(Concat(rBytes, publicKey.CompressedPoint, message));
            BigInteger k = PointDecoder.LittleEndianToBigInteger(hash) % GroupOrderL;

            // [S]B = R + [k]A, checked as [S]B + [k](-A) = R so both scalar multiplications share
            // one doubling chain.
            return EdwardsPoint.MultiplyAdd(s, EdwardsPoint.B, k, a.Negate()).Equals(r);
        }

        private static byte[] ComputeSha512(byte[] data)
        {
            using SHA512 sha512 = SHA512.Create();
            return sha512.ComputeHash(data);
        }

        private static byte[] Concat(byte[] a, byte[] b, byte[] c)
        {
            var result = new byte[a.Length + b.Length + c.Length];
            Array.Copy(a, 0, result, 0, a.Length);
            Array.Copy(b, 0, result, a.Length, b.Length);
            Array.Copy(c, 0, result, a.Length + b.Length, c.Length);
            return result;
        }
    }
}
