using System;
using Scarlet.OpenPgp.Hashing;

namespace Scarlet.OpenPgp.Crypto.Ecdsa
{
    /// <summary>An ECDSA public key (RFC 9580 §5.5.5.4): a supported curve and its SEC 1 uncompressed point.</summary>
    internal sealed class EcdsaPublicKey(EcCurve curve, byte[] point) : VerificationKey
    {
        public EcCurve Curve { get; } = curve;

        /// <summary>The SEC 1 uncompressed point, 0x04 || X || Y. Validated on use: a point off the curve verifies nothing.</summary>
        public byte[] Point { get; } = point;

        public override string Description => "ECDSA " + Curve.Name;

        /// <summary>RFC 9580 §5.2.3.2: at least the curve's field size, except P-521, which needs at least 512 bits.</summary>
        public override int MinimumHashBits => Math.Min(BigIntegerMath.BitLength(Curve.P), 512);

        public override bool Verify(HashAlgorithmId hashAlgorithm, byte[] digest, SignatureValue signature) =>
            signature is RsSignatureValue rs && EcdsaVerifier.Verify(Curve, Point, digest, rs.R, rs.S);
    }
}
