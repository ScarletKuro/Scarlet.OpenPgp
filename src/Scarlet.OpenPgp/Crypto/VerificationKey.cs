using Scarlet.OpenPgp.Hashing;

namespace Scarlet.OpenPgp.Crypto
{
    /// <summary>
    /// The key material of a public key whose algorithm this library can verify signatures with.
    /// Each signing algorithm is one subclass, which holds everything algorithm-specific: how the
    /// key describes itself, which hashes are strong enough for it, and how it checks a signature.
    /// </summary>
    internal abstract class VerificationKey
    {
        /// <summary>A human-readable algorithm description, e.g. "RSA 4096", "ECDSA NIST P-256", "Ed25519".</summary>
        public abstract string Description { get; }

        /// <summary>The smallest digest, in bits, RFC 9580 allows for signatures by this key (§5.2.3.2-5).</summary>
        public abstract int MinimumHashBits { get; }

        /// <summary>
        /// Whether <paramref name="signature"/> is this key's signature over <paramref name="digest"/>,
        /// the finished hash of the signed content. A signature value of another algorithm's shape is
        /// simply not a valid signature.
        /// </summary>
        public abstract bool Verify(HashAlgorithmId hashAlgorithm, byte[] digest, SignatureValue signature);
    }
}
