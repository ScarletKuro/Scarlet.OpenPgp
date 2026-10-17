using System.Numerics;

namespace Scarlet.OpenPgp.Crypto.Ed25519
{
    /// <summary>Recovers a point's x-coordinate from its y-coordinate and sign bit (RFC 8032 §5.1.3), and decompresses a 32-byte encoded Ed25519 point.</summary>
    internal static class PointDecoder
    {
        // p is prime and p = 5 (mod 8), so a square root of a quadratic residue a can be computed
        // as a^((p+3)/8); if that candidate is off by a factor of sqrt(-1), multiplying by
        // 2^((p-1)/4) (a square root of -1 mod p) fixes it. Both exponents per RFC 8032 §5.1.3.
        private static readonly BigInteger SqrtCandidateExponent = (FieldElement.P + 3) / 8;
        private static readonly BigInteger SqrtMinusOneExponent = (FieldElement.P - 1) / 4;

        /// <summary>sqrt(-1) mod p = 2^((p-1)/4): a constant, so computed once rather than on every point decode.</summary>
        private static readonly FieldElement SqrtMinusOne = new FieldElement(2).Pow(SqrtMinusOneExponent);

        public static bool TryDecode(byte[] compressed32, out EdwardsPoint point)
        {
            point = default;
            if (compressed32.Length != 32)
            {
                return false;
            }

            bool xSignBit = (compressed32[31] & 0x80) != 0;

            var yBytes = new byte[32];
            System.Array.Copy(compressed32, yBytes, 32);
            yBytes[31] &= 0x7F; // clear the sign bit to isolate the 255-bit y value

            BigInteger yValue = LittleEndianToBigInteger(yBytes);
            if (yValue >= FieldElement.P)
            {
                return false; // RFC 8032 §5.1.3: decoding fails if y >= p
            }

            var y = new FieldElement(yValue);
            if (!TryRecoverX(y, xSignBit, out FieldElement x))
            {
                return false;
            }

            point = new EdwardsPoint(x, y);
            return point.IsOnCurve;
        }

        /// <summary>Recovers x from y and the desired sign bit x_0 (RFC 8032 §5.1.3).</summary>
        public static bool TryRecoverX(FieldElement y, bool xSignBit, out FieldElement x)
        {
            x = FieldElement.Zero;

            FieldElement ySquared = y * y;
            FieldElement u = ySquared - FieldElement.One;
            FieldElement v = (EdwardsPoint.D * ySquared) + FieldElement.One;

            FieldElement x2 = u * v.Invert();
            FieldElement candidate = x2.Pow(SqrtCandidateExponent);

            FieldElement vCandidateSquared = v * candidate * candidate;
            if (vCandidateSquared == u)
            {
                // candidate is already a square root of x2.
            }
            else if (vCandidateSquared == -u)
            {
                candidate = candidate * SqrtMinusOne;
            }
            else
            {
                return false; // x2 is not a quadratic residue: no valid x for this y.
            }

            if (candidate.IsZero && xSignBit)
            {
                return false; // RFC 8032 §5.1.3: x = 0 is only valid with sign bit 0.
            }

            if (candidate.IsOdd != xSignBit)
            {
                candidate = -candidate;
            }

            x = candidate;
            return true;
        }


        /// <summary>Interprets a little-endian byte sequence (Ed25519's native encoding for y-coordinates, scalars, and hash outputs) as an unsigned integer. Shared with <see cref="Ed25519Verifier"/> rather than duplicated.</summary>
        public static BigInteger LittleEndianToBigInteger(byte[] littleEndian)
        {
            var buffer = new byte[littleEndian.Length + 1];
            System.Array.Copy(littleEndian, buffer, littleEndian.Length);
            buffer[buffer.Length - 1] = 0; // guard byte forces a non-negative BigInteger
            return new BigInteger(buffer);
        }
    }
}
