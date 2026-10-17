using System;
using Scarlet.OpenPgp.Crypto.Ed25519;
using Scarlet.OpenPgp.Crypto.Rsa;
using Scarlet.OpenPgp.Hashing;
using Scarlet.OpenPgp.Internal;
using Scarlet.OpenPgp.Packets;

namespace Scarlet.OpenPgp.Signing
{
    /// <summary>
    /// Checks one v4 signature against one public key: the asymmetric check over the signed content,
    /// and the signature's own validity period. Shared by document verification and by the
    /// self-signature checks in <see cref="PublicKeyBlock"/>.
    /// </summary>
    internal static class SignatureVerifier
    {
        /// <summary>
        /// Verifies <paramref name="signature"/> over <paramref name="signedContent"/> (the bytes
        /// that precede the signature's own hashed portion: the document, or the key/User ID prefix
        /// for a key signature). Unsupported algorithms fail closed.
        /// </summary>
        public static bool VerifyCryptographic(PublicKeyPacket publicKey, SignaturePacket signature, byte[] signedContent)
        {
            if (publicKey.Algorithm != signature.PublicKeyAlgorithm)
            {
                return false;
            }

            byte[] dataToHash = SignatureHashBuilder.BuildDataToHash(signedContent, signature);
            byte[] digest = OpenPgpHash.ComputeHash(signature.HashAlgorithm, dataToHash);

            // The packet's own 2-byte quick-check (RFC 4880 §5.2.3) isn't itself signed material,
            // so it can't be used as a substitute for the real asymmetric check below - but a
            // mismatch here means the packet is inconsistent with the content it claims to cover,
            // which fails closed the same as any other malformed-input case.
            if (signature.LeftHashBytes16[0] != digest[0] || signature.LeftHashBytes16[1] != digest[1])
            {
                return false;
            }

            switch (publicKey.Algorithm)
            {
                case PublicKeyAlgorithm.RsaEncryptOrSign:
                case PublicKeyAlgorithm.RsaSignOnly:
                    if (publicKey.Rsa is null || signature.RsaSignatureValue is null)
                    {
                        return false;
                    }

                    return RsaPkcs1Verifier.Verify(publicKey.Rsa, signature.HashAlgorithm, digest, signature.RsaSignatureValue.Value);

                case PublicKeyAlgorithm.EdDsaLegacy:
                    if (publicKey.EdDsa is null || signature.EdDsaSignatureValue is null)
                    {
                        return false;
                    }

                    return Ed25519Verifier.Verify(publicKey.EdDsa, digest, signature.EdDsaSignatureValue);

                default:
                    return false;
            }
        }

        /// <summary>
        /// The signature's creation time. RFC 4880 §5.2.3.4 requires it in the hashed area; a
        /// signature without one can't be placed in time, so it fails closed.
        /// </summary>
        public static DateTimeOffset GetCreationTime(SignaturePacket signature)
        {
            if (!signature.TryGetHashedTime(SignatureSubpacketType.SignatureCreationTime, out uint seconds))
            {
                throw new FailClosedException("Signature has no hashed signature-creation-time subpacket.");
            }

            return DateTimeOffset.FromUnixTimeSeconds(seconds);
        }

        /// <summary>
        /// Whether the signature is within its own validity period at <paramref name="now"/>: not
        /// past its hashed signature-expiration time (RFC 4880 §5.2.3.10; zero means it never
        /// expires).
        /// </summary>
        public static bool IsUnexpired(SignaturePacket signature, DateTimeOffset now)
        {
            DateTimeOffset createdAt = GetCreationTime(signature);
            if (signature.TryGetHashedTime(SignatureSubpacketType.SignatureExpirationTime, out uint lifetimeSeconds)
                && lifetimeSeconds != 0
                && now >= createdAt.AddSeconds(lifetimeSeconds))
            {
                return false;
            }

            return true;
        }
    }
}
