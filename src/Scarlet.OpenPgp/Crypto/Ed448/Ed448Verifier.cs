using System;
using System.Numerics;
using Scarlet.OpenPgp.Hashing;

namespace Scarlet.OpenPgp.Crypto.Ed448
{
    /// <summary>
    /// Ed448 (PureEdDSA, empty context) signature verification per RFC 8032 §5.2.7. Like
    /// <see cref="Ed25519.Ed25519Verifier"/>, this checks the cofactorless equation [S]B = R + [k]A;
    /// RFC 8032 §5.2.7 explicitly allows it ("sufficient, but not required") instead of the
    /// cofactor-multiplied [4][S]B = [4]R + [4][k]A, and using the same form for both curves keeps
    /// the library's acceptance behaviour consistent.
    /// </summary>
    internal static class Ed448Verifier
    {
        public const int PublicKeyLength = 57;
        public const int SignatureLength = 114;

        private const int ScalarLength = 57;
        private const int HashLength = 114;

        /// <summary>The prime order of the base point, L = 2^446 - 13818066809895115352007386748515426880336692474882178609894547503885 (RFC 8032 §5.2).</summary>
        public static readonly BigInteger GroupOrderL =
            BigInteger.Pow(2, 446) - BigInteger.Parse("13818066809895115352007386748515426880336692474882178609894547503885");

        /// <summary>
        /// dom4(0, "") from RFC 8032 §5.2: "SigEd448" || octet(phflag = 0) || octet(len(context) = 0).
        /// Unlike Ed25519 (whose dom2 is empty for the pure variant), Ed448 always prefixes this.
        /// </summary>
        private static readonly byte[] Dom4PureEmptyContext =
        {
            (byte)'S', (byte)'i', (byte)'g', (byte)'E', (byte)'d', (byte)'4', (byte)'4', (byte)'8', 0x00, 0x00,
        };

        public static bool Verify(byte[] publicKey, byte[] message, byte[] signature)
        {
            if (publicKey == null || message == null || signature == null)
            {
                return false;
            }

            if (publicKey.Length != PublicKeyLength || signature.Length != SignatureLength)
            {
                return false;
            }

            if (!Ed448PointDecoder.TryDecode(publicKey, out Ed448Point a))
            {
                return false;
            }

            var rBytes = new byte[Ed448PointDecoder.EncodedLength];
            var sBytes = new byte[ScalarLength];
            Array.Copy(signature, 0, rBytes, 0, rBytes.Length);
            Array.Copy(signature, rBytes.Length, sBytes, 0, sBytes.Length);

            if (!Ed448PointDecoder.TryDecode(rBytes, out Ed448Point r))
            {
                return false;
            }

            BigInteger s = Ed448PointDecoder.LittleEndianToBigInteger(sBytes);
            if (s >= GroupOrderL)
            {
                return false; // RFC 8032 §5.2.7 step 1: reject non-canonical S (signature malleability)
            }

            // k = SHAKE256(dom4(0, "") || R || A || M, 114), interpreted little-endian and reduced mod L.
            KeccakHash shake = KeccakHash.CreateShake256(HashLength);
            shake.Update(Dom4PureEmptyContext, 0, Dom4PureEmptyContext.Length);
            shake.Update(rBytes, 0, rBytes.Length);
            shake.Update(publicKey, 0, publicKey.Length);
            shake.Update(message, 0, message.Length);
            BigInteger k = Ed448PointDecoder.LittleEndianToBigInteger(shake.Finish()) % GroupOrderL;

            Ed448Point sB = Ed448Point.B.ScalarMultiply(s);
            Ed448Point rPlusKA = r.Add(a.ScalarMultiply(k));

            return sB.Equals(rPlusKA);
        }
    }
}
