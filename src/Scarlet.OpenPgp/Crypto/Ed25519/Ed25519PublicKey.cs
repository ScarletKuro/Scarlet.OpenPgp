using Scarlet.OpenPgp.Hashing;
using Scarlet.OpenPgp.Internal;

namespace Scarlet.OpenPgp.Crypto.Ed25519
{
    /// <summary>A compressed 32-byte Ed25519 public point, in its native RFC 8032 §5.1.2 encoding.</summary>
    internal sealed class Ed25519PublicKey : VerificationKey
    {
        public const int EncodedLength = 32;

        private readonly bool _legacy;
        private DecodedPoint? _decoded;

        /// <param name="compressedPoint">The 32-byte encoded point.</param>
        /// <param name="legacy">The key came from an EdDSALegacy (algorithm 22) packet rather than a native Ed25519 (27) one; it only changes the description.</param>
        public Ed25519PublicKey(byte[] compressedPoint, bool legacy = false)
        {
            if (compressedPoint.Length != EncodedLength)
            {
                throw new FailClosedException("Ed25519 public key must be exactly 32 bytes.");
            }

            CompressedPoint = compressedPoint;
            _legacy = legacy;
        }

        public byte[] CompressedPoint { get; }

        public override string Description => _legacy ? "EdDSA Ed25519 (legacy)" : "Ed25519";

        /// <summary>RFC 9580 §5.2.3.4-5: Ed25519 signatures need at least a 256-bit digest.</summary>
        public override int MinimumHashBits => 256;

        public override int CheckCost => 1;

        public override bool Verify(HashAlgorithmId hashAlgorithm, byte[] digest, SignatureValue signature) =>
            signature is EdDsaSignatureValue eddsa && Ed25519Verifier.Verify(this, digest, eddsa.Value);

        /// <summary>
        /// The decoded point, or <see langword="false"/> if it doesn't decode or has small order.
        /// Computed on first use and kept - including a failure - so a key reused from a parsed key
        /// ring pays for the square root and the small-order check once rather than per signature.
        /// </summary>
        /// <remarks>
        /// Only the point is kept, not the table of its odd multiples that verification builds from
        /// it: that table would hold about 2.5 KB per key for the key ring's lifetime, to save about
        /// 2% of a verification. Memory a key ring holds matters more here than that time.
        /// </remarks>
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
