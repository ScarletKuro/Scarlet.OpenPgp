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
        private static readonly BigInteger GroupOrderL =
            BigInteger.Pow(2, 252) + BigInteger.Parse("27742317777372353535851937790883648493");

        public static bool Verify(Ed25519PublicKey publicKey, byte[] message, byte[] signature)
        {
            if (signature.Length != 64)
            {
                return false;
            }

            if (!PointDecoder.TryDecode(publicKey.CompressedPoint, out EdwardsPoint a))
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

            BigInteger s = LittleEndianToBigInteger(sBytes);
            if (s >= GroupOrderL)
            {
                return false;
            }

            byte[] hash = ComputeSha512(Concat(rBytes, publicKey.CompressedPoint, message));
            BigInteger k = LittleEndianToBigInteger(hash) % GroupOrderL;

            EdwardsPoint sB = EdwardsPoint.B.ScalarMultiply(s);
            EdwardsPoint kA = a.ScalarMultiply(k);
            EdwardsPoint rPlusKA = r.Add(kA);

            return sB.Equals(rPlusKA);
        }

        private static byte[] ComputeSha512(byte[] data)
        {
            using (SHA512 sha512 = SHA512.Create())
            {
                return sha512.ComputeHash(data);
            }
        }

        private static byte[] Concat(byte[] a, byte[] b, byte[] c)
        {
            var result = new byte[a.Length + b.Length + c.Length];
            Array.Copy(a, 0, result, 0, a.Length);
            Array.Copy(b, 0, result, a.Length, b.Length);
            Array.Copy(c, 0, result, a.Length + b.Length, c.Length);
            return result;
        }

        private static BigInteger LittleEndianToBigInteger(byte[] littleEndian)
        {
            var buffer = new byte[littleEndian.Length + 1];
            Array.Copy(littleEndian, buffer, littleEndian.Length);
            buffer[buffer.Length - 1] = 0; // guard byte forces a non-negative BigInteger
            return new BigInteger(buffer);
        }
    }
}
