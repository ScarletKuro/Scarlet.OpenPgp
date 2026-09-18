using Scarlet.OpenPgp.Internal;

namespace Scarlet.OpenPgp.Crypto.Ed25519
{
    /// <summary>A compressed 32-byte Ed25519 public point, in its native RFC 8032 §5.1.2 encoding.</summary>
    internal sealed class Ed25519PublicKey
    {
        public const int EncodedLength = 32;

        public Ed25519PublicKey(byte[] compressedPoint)
        {
            if (compressedPoint.Length != EncodedLength)
            {
                throw new FailClosedException("Ed25519 public key must be exactly 32 bytes.");
            }

            CompressedPoint = compressedPoint;
        }

        public byte[] CompressedPoint { get; }
    }
}
