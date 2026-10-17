using System.Numerics;

namespace Scarlet.OpenPgp.Crypto.Ed448
{
    /// <summary>Decompresses a 57-byte encoded Ed448 point (RFC 8032 §5.2.3), rejecting every non-canonical or off-curve encoding.</summary>
    internal static class Ed448PointDecoder
    {
        public const int EncodedLength = 57;

        // p = 3 (mod 4), so a square root of a quadratic residue a is a^((p+1)/4). RFC 8032 §5.2.3
        // folds the division u/v into the same exponentiation: (u/v)^((p+1)/4) = u^3 v (u^5 v^3)^((p-3)/4).
        private static readonly BigInteger SqrtRatioExponent = (Ed448FieldElement.P - 3) / 4;

        public static bool TryDecode(byte[] encoded, out Ed448Point point)
        {
            point = default;
            if (encoded.Length != EncodedLength)
            {
                return false;
            }

            byte lastByte = encoded[EncodedLength - 1];
            bool xSignBit = (lastByte & 0x80) != 0;

            // RFC 8032 §5.2.2: the final octet of the y encoding "is always zero"; only its top bit
            // carries x_0. Any of the other seven bits set would make y >= 2^448 > p, which the
            // range check below rejects anyway - this check just makes the rule explicit.
            if ((lastByte & 0x7F) != 0)
            {
                return false;
            }

            var yBytes = new byte[EncodedLength];
            System.Array.Copy(encoded, yBytes, EncodedLength);
            yBytes[EncodedLength - 1] = 0; // clear bit 455 (x_0) to isolate y

            BigInteger yValue = LittleEndianToBigInteger(yBytes);
            if (yValue >= Ed448FieldElement.P)
            {
                return false; // RFC 8032 §5.2.3 step 1: decoding fails if y >= p
            }

            var y = new Ed448FieldElement(yValue);
            if (!TryRecoverX(y, xSignBit, out Ed448FieldElement x))
            {
                return false;
            }

            point = Ed448Point.FromAffine(x, y);
            return point.IsOnCurve;
        }

        /// <summary>Recovers x from y and the desired sign bit x_0 (RFC 8032 §5.2.3 steps 2-4).</summary>
        public static bool TryRecoverX(Ed448FieldElement y, bool xSignBit, out Ed448FieldElement x)
        {
            x = Ed448FieldElement.Zero;

            // From x^2 + y^2 = 1 + d x^2 y^2: x^2 = (y^2 - 1) / (d y^2 - 1). The denominator is never
            // zero because d is not a square mod p.
            Ed448FieldElement ySquared = y.Square();
            Ed448FieldElement u = ySquared - Ed448FieldElement.One;
            Ed448FieldElement v = (Ed448Point.D * ySquared) - Ed448FieldElement.One;

            Ed448FieldElement u2 = u.Square();
            Ed448FieldElement u3 = u2 * u;
            Ed448FieldElement u5 = u3 * u2;
            Ed448FieldElement v3 = v.Square() * v;
            Ed448FieldElement candidate = u3 * v * (u5 * v3).Pow(SqrtRatioExponent);

            if (v * candidate.Square() != u)
            {
                return false; // step 3: u/v is not a quadratic residue, so no x exists for this y
            }

            if (candidate.IsZero && xSignBit)
            {
                return false; // step 4: x = 0 is only valid with sign bit 0
            }

            if (candidate.IsOdd != xSignBit)
            {
                candidate = -candidate;
            }

            x = candidate;
            return true;
        }

        /// <summary>Interprets a little-endian byte sequence (Ed448's native encoding for coordinates, scalars and hash outputs) as an unsigned integer.</summary>
        public static BigInteger LittleEndianToBigInteger(byte[] littleEndian)
        {
            var buffer = new byte[littleEndian.Length + 1];
            System.Array.Copy(littleEndian, buffer, littleEndian.Length);
            buffer[buffer.Length - 1] = 0; // guard byte forces a non-negative BigInteger
            return new BigInteger(buffer);
        }
    }
}
