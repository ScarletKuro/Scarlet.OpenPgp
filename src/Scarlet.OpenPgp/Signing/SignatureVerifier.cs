using System;
using Scarlet.OpenPgp.Crypto;
using Scarlet.OpenPgp.Crypto.Dsa;
using Scarlet.OpenPgp.Crypto.Ecdsa;
using Scarlet.OpenPgp.Crypto.Ed25519;
using Scarlet.OpenPgp.Crypto.Ed448;
using Scarlet.OpenPgp.Crypto.Rsa;
using Scarlet.OpenPgp.Hashing;
using Scarlet.OpenPgp.Internal;
using Scarlet.OpenPgp.Packets;

namespace Scarlet.OpenPgp.Signing
{
    /// <summary>
    /// Checks one v4/v6 signature against one public key: the asymmetric check over an
    /// already-computed digest, plus the signature's own validity period. Shared by document
    /// verification and by the self-signature checks in <see cref="Certificate"/>.
    /// </summary>
    internal static class SignatureVerifier
    {
        /// <summary>
        /// Why <paramref name="signature"/> can't be checked with <paramref name="key"/> at all, or
        /// <c>null</c> when the combination is acceptable: matching versions (RFC 9580 binds a
        /// signature's version to its key's), matching algorithms, verifiable key material, and a
        /// hash at least as strong as the algorithm requires (RFC 9580 §5.2.3.2-5).
        /// </summary>
        public static string? GetIncompatibility(PublicKeyPacket key, SignaturePacket signature)
        {
            if (key.Version != signature.Version)
            {
                return "a v" + signature.Version + " signature cannot be made by a v" + key.Version + " key";
            }

            if (!key.CanVerify)
            {
                return "the key's algorithm (" + key.Algorithm + ") is not supported for signatures";
            }

            if (key.Algorithm != signature.PublicKeyAlgorithm)
            {
                return "the signature's algorithm (" + signature.PublicKeyAlgorithm + ") does not match the key's (" + key.Algorithm + ")";
            }

            int minimumHashBits = MinimumHashBits(key);
            if (HashContext.IsSupported(signature.HashAlgorithm) && HashContext.DigestBits(signature.HashAlgorithm) < minimumHashBits)
            {
                return signature.HashAlgorithm + " is too weak for " + key.Algorithm + " (at least " + minimumHashBits + " bits required)";
            }

            return null;
        }

        /// <summary>
        /// Verifies <paramref name="signature"/> given <paramref name="digest"/>, the finished hash
        /// of the signed content (see <see cref="SignatureDigest"/>). Call
        /// <see cref="GetIncompatibility"/> first; incompatible combinations simply return
        /// <c>false</c> here.
        /// </summary>
        public static bool VerifyDigest(PublicKeyPacket key, SignaturePacket signature, byte[] digest)
        {
            if (GetIncompatibility(key, signature) is not null)
            {
                return false;
            }

            // The packet's own 2-byte quick-check (RFC 9580 §5.2.3) isn't itself signed material,
            // so it can't substitute for the real asymmetric check below - but a mismatch means the
            // packet is inconsistent with the content it claims to cover, and RFC 9580 §5.2.3.6
            // requires rejecting a v6 signature for it. Treated the same for v4.
            if (signature.LeftHashBytes16[0] != digest[0] || signature.LeftHashBytes16[1] != digest[1])
            {
                return false;
            }

            switch (key.Algorithm)
            {
                case PublicKeyAlgorithm.RsaEncryptOrSign:
                case PublicKeyAlgorithm.RsaSignOnly:
                    return key.Rsa is not null && signature.RsaSignatureValue is not null
                           && RsaPkcs1Verifier.Verify(key.Rsa, signature.HashAlgorithm, digest, signature.RsaSignatureValue.Value);

                case PublicKeyAlgorithm.Dsa:
                    return signature.R is not null && signature.S is not null
                           && key.Dsa is not null && DsaVerifier.Verify(key.Dsa, digest, signature.R.Value, signature.S.Value);

                case PublicKeyAlgorithm.Ecdsa:
                    return signature.R is not null && signature.S is not null
                           && key.EcdsaCurve is not null && key.EcdsaPoint is not null
                           && EcdsaVerifier.Verify(key.EcdsaCurve, key.EcdsaPoint, digest, signature.R.Value, signature.S.Value);

                case PublicKeyAlgorithm.EdDsaLegacy:
                case PublicKeyAlgorithm.Ed25519:
                    return key.Ed25519 is not null && signature.EdDsaSignatureValue is not null
                           && Ed25519Verifier.Verify(key.Ed25519, digest, signature.EdDsaSignatureValue);

                case PublicKeyAlgorithm.Ed448:
                    return key.Ed448 is not null && signature.Ed448SignatureValue is not null
                           && Ed448Verifier.Verify(key.Ed448, digest, signature.Ed448SignatureValue);

                default:
                    return false;
            }
        }

        /// <summary>
        /// The signature's creation time. RFC 9580 §5.2.3.11 requires it in the hashed area; a
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
        /// How far into the future a document signature's creation time may lie and still count:
        /// tolerance for a signer's or verifier's clock being slightly off. Anything beyond it is
        /// rejected - a signature isn't valid before it was made, and accepting future times would
        /// let a signer push an expiration (counted from creation) arbitrarily far out.
        /// </summary>
        public static readonly TimeSpan MaxClockSkew = TimeSpan.FromMinutes(5);

        /// <summary>Whether <paramref name="createdAt"/> lies further in the future than <see cref="MaxClockSkew"/> allows.</summary>
        public static bool IsFromTheFuture(DateTimeOffset createdAt, DateTimeOffset now) => createdAt > now + MaxClockSkew;

        /// <summary>
        /// Whether the signature is within its own validity period at <paramref name="now"/>: not
        /// past its hashed signature-expiration time (RFC 9580 §5.2.3.18; zero means it never
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

        /// <summary>RFC 9580's minimum digest size for signatures by <paramref name="key"/>.</summary>
        private static int MinimumHashBits(PublicKeyPacket key)
        {
            switch (key.Algorithm)
            {
                case PublicKeyAlgorithm.EdDsaLegacy:
                case PublicKeyAlgorithm.Ed25519:
                    return 256;
                case PublicKeyAlgorithm.Ed448:
                    return 512;
                case PublicKeyAlgorithm.Ecdsa:
                    // The curve's "fsize", except NIST P-521, which needs at least a 512-bit hash.
                    return key.EcdsaCurve is null ? int.MaxValue : Math.Min(BigIntegerMath.BitLength(key.EcdsaCurve.P), 512);
                case PublicKeyAlgorithm.Dsa:
                    return key.Dsa?.QBitLength ?? int.MaxValue;
                default:
                    return 0;
            }
        }
    }
}
