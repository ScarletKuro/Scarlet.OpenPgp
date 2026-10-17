using Scarlet.OpenPgp.Internal;

namespace Scarlet.OpenPgp.Crypto.Ed25519
{
    /// <summary>A compressed 32-byte Ed25519 public point, in its native RFC 8032 §5.1.2 encoding.</summary>
    internal sealed class Ed25519PublicKey
    {
        public const int EncodedLength = 32;

        private DecodedPoint? _decoded;

        public Ed25519PublicKey(byte[] compressedPoint)
        {
            if (compressedPoint.Length != EncodedLength)
            {
                throw new FailClosedException("Ed25519 public key must be exactly 32 bytes.");
            }

            CompressedPoint = compressedPoint;
        }

        public byte[] CompressedPoint { get; }

        /// <summary>
        /// The decoded point, or <see langword="false"/> if it doesn't decode or has small order.
        /// Computed on first use and kept, so a key reused from a parsed key ring pays for the
        /// square root and the small-order check once rather than on every signature.
        /// </summary>
        public bool TryGetValidPoint(out EdwardsPoint point)
        {
            // Racing threads compute the same immutable result; publishing a reference is atomic.
            DecodedPoint decoded = _decoded ??= DecodedPoint.From(CompressedPoint);
            point = decoded.Point;
            return decoded.IsValid;
        }

        private sealed class DecodedPoint
        {
            private DecodedPoint(bool isValid, EdwardsPoint point)
            {
                IsValid = isValid;
                Point = point;
            }

            public bool IsValid { get; }

            public EdwardsPoint Point { get; }

            public static DecodedPoint From(byte[] compressedPoint)
            {
                // Reject small-order public keys ([8]A = identity, which includes the identity itself).
                // No real key is one, and with such an A the equation [S]B = R + [k]A no longer depends
                // on the message - e.g. A = R = identity, S = 0 "verifies" anything.
                bool isValid = PointDecoder.TryDecode(compressedPoint, out EdwardsPoint point)
                    && !point.ScalarMultiply(Ed25519Verifier.Cofactor).Equals(EdwardsPoint.Identity);
                return new DecodedPoint(isValid, point);
            }
        }
    }
}
