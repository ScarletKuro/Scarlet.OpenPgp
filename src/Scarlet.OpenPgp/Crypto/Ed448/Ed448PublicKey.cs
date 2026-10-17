using Scarlet.OpenPgp.Hashing;
using Scarlet.OpenPgp.Internal;

namespace Scarlet.OpenPgp.Crypto.Ed448
{
    /// <summary>A 57-octet Ed448 public key, in its native RFC 8032 §5.2.2 encoding.</summary>
    internal sealed class Ed448PublicKey : VerificationKey
    {
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

        public override bool Verify(HashAlgorithmId hashAlgorithm, byte[] digest, SignatureValue signature) =>
            signature is EdDsaSignatureValue eddsa && Ed448Verifier.Verify(Encoded, digest, eddsa.Value);
    }
}
