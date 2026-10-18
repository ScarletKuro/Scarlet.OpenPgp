using System;
using Scarlet.OpenPgp.Hashing;

namespace Scarlet.OpenPgp.Crypto.Ecdsa
{
    /// <summary>An ECDSA public key (RFC 9580 §5.5.5.4): a supported curve and its SEC 1 uncompressed point.</summary>
    internal sealed class EcdsaPublicKey(EcCurve curve, byte[] point) : VerificationKey
    {
        private DecodedPoint? _decoded;

        public EcCurve Curve { get; } = curve;

        /// <summary>The SEC 1 uncompressed point, 0x04 || X || Y. Validated on first use: a point off the curve verifies nothing.</summary>
        public byte[] Point { get; } = point;

        public override string Description => "ECDSA " + Curve.Name;

        /// <summary>RFC 9580 §5.2.3.2: at least the curve's field size, except P-521, which needs at least 512 bits.</summary>
        public override int MinimumHashBits => Math.Min(BigIntegerMath.BitLength(Curve.P), 512);

        /// <summary>
        /// P-256 has its own fixed-width arithmetic (about 0.7 ms); the other curves use the generic
        /// path, whose cost grows with the square of the field size and is about twice as high for
        /// brainpool curves (a ≠ -3): about 7 ms for P-521, 14 ms for brainpoolP512r1.
        /// </summary>
        public override int CheckCost
        {
            get
            {
                if (ReferenceEquals(Curve, EcCurve.NistP256))
                {
                    return 2;
                }

                double scale = (double)Curve.FieldByteLength / 32;
                return (int)Math.Ceiling((Curve.IsAMinus3 ? 6 : 12) * scale * scale);
            }
        }

        public override bool Verify(HashAlgorithmId hashAlgorithm, byte[] digest, SignatureValue signature)
        {
            if (signature is not RsSignatureValue rs)
            {
                return false;
            }

            // Decoded and checked to be on the curve once, then reused - including a failure - so a
            // key from a parsed key ring doesn't redo that work for every signature. Racing threads
            // compute the same immutable result; publishing a reference is atomic.
            DecodedPoint decoded = _decoded ??= new DecodedPoint(EcdsaVerifier.TryDecodePublicPoint(Curve, Point, out JacobianPoint q), q);
            return decoded.IsValid && EcdsaVerifier.Verify(Curve, decoded.Point, digest, rs.R, rs.S);
        }

        private sealed class DecodedPoint(bool isValid, JacobianPoint point)
        {
            public bool IsValid { get; } = isValid;

            public JacobianPoint Point { get; } = point;
        }
    }
}
