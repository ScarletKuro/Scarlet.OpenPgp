using Scarlet.OpenPgp.Hashing;
using Scarlet.OpenPgp.Internal;

namespace Scarlet.OpenPgp.Crypto.Ed448
{
    /// <summary>A 57-octet Ed448 public key, in its native RFC 8032 §5.2.2 encoding.</summary>
    internal sealed class Ed448PublicKey : VerificationKey
    {
        private DecodedPoint? _decoded;

        public Ed448PublicKey(byte[] encoded)
        {
            if (encoded.Length != Ed448Verifier.PublicKeyLength)
            {
                throw new FailClosedException("Ed448 public key must be exactly " + Ed448Verifier.PublicKeyLength + " bytes.");
            }

            Encoded = encoded;
        }

        public byte[] Encoded { get; }

        public override string Description => "Ed448";

        /// <summary>RFC 9580 §5.2.3.5: Ed448 signatures need at least a 512-bit digest.</summary>
        public override int MinimumHashBits => 512;

        /// <summary>About 4.6 ms.</summary>
        public override int CheckCost => 16;

        public override bool Verify(HashAlgorithmId hashAlgorithm, byte[] digest, SignatureValue signature) =>
            signature is EdDsaSignatureValue eddsa && Ed448Verifier.Verify(this, digest, eddsa.Value);

        /// <summary>
        /// The decoded point, or <see langword="false"/> if it doesn't decode or has small order.
        /// Computed on first use and kept - including a failure - so a key reused from a parsed key
        /// ring pays for the square root and the small-order check once rather than on every signature.
        /// </summary>
        public bool TryGetValidPoint(out Ed448Point point)
        {
            // Racing threads compute the same immutable result; publishing a reference is atomic.
            DecodedPoint decoded = _decoded ??= DecodedPoint.From(Encoded);
            point = decoded.Point;
            return decoded.IsValid;
        }

        private sealed class DecodedPoint
        {
            private DecodedPoint(bool isValid, Ed448Point point)
            {
                IsValid = isValid;
                Point = point;
            }

            public bool IsValid { get; }

            public Ed448Point Point { get; }

            public static DecodedPoint From(byte[] encoded)
            {
                // Reject small-order public keys ([4]A = identity, which includes the identity itself).
                // No real key is one, and with such an A the verification equation no longer depends on
                // the message - e.g. A = R = identity, S = 0 "verifies" anything.
                bool isValid = Ed448PointDecoder.TryDecode(encoded, out Ed448Point point)
                    && !point.Double().Double().Equals(Ed448Point.Identity);
                return new DecodedPoint(isValid, point);
            }
        }
    }
}
