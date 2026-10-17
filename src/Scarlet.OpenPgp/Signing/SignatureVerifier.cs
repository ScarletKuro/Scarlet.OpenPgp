using System;
using System.Collections.Generic;
using System.Linq;
using Scarlet.OpenPgp.Hashing;
using Scarlet.OpenPgp.Internal;
using Scarlet.OpenPgp.Packets;

namespace Scarlet.OpenPgp.Signing
{
    /// <summary>
    /// Checks one v4/v6 signature against one public key: whether the key may have made it, the
    /// asymmetric check over an already-computed digest, and the signature's own validity period.
    /// Shared by document verification and by the self-signature checks in <see cref="Certificate"/>.
    /// </summary>
    internal static class SignatureVerifier
    {
        /// <summary>
        /// How far into the future a document signature's creation time may lie and still count:
        /// tolerance for a signer's or verifier's clock being slightly off. Anything beyond it is
        /// rejected - a signature isn't valid before it was made, and accepting future times would
        /// let a signer push an expiration (counted from creation) arbitrarily far out.
        /// </summary>
        public static readonly TimeSpan MaxClockSkew = TimeSpan.FromMinutes(5);

        /// <summary>
        /// Whether the signature's issuer hints (fingerprints first, then key IDs) allow
        /// <paramref name="key"/> to be its issuer. A signature with no hints at all could be from
        /// any key. The hints may be unauthenticated; they only ever narrow the search.
        /// </summary>
        /// <param name="signature">The signature.</param>
        /// <param name="key">The candidate issuer.</param>
        /// <param name="hashedOnly">
        /// Consider only signed hints. Required wherever a mismatch makes a signature be *ignored*
        /// in a way that could help an attacker - a key's own revocations and restrictions: an
        /// unsigned hint is editable by anyone, so replacing it must not make a revocation
        /// "someone else's". Without a signed hint the signature is simply verified against the key.
        /// </param>
        public static bool IsIssuedBy(SignaturePacket signature, PublicKeyPacket key, bool hashedOnly = false)
        {
            List<byte[]> fingerprints = signature.GetIssuerFingerprints(hashedOnly).ToList();
            if (fingerprints.Count > 0)
            {
                return fingerprints.Any(key.Fingerprint.Matches);
            }

            List<byte[]> keyIds = signature.GetIssuerKeyIds(hashedOnly).ToList();
            if (keyIds.Count > 0)
            {
                return keyIds.Any(key.Fingerprint.MatchesKeyId);
            }

            return true;
        }

        /// <summary>
        /// Whether <paramref name="signature"/> cannot have been made by <paramref name="key"/> at all
        /// (its version or algorithm differs), as opposed to being from the key but uncheckable.
        /// </summary>
        public static bool IsForDifferentKey(PublicKeyPacket key, SignaturePacket signature) =>
            key.Version != signature.Version || key.Algorithm != signature.PublicKeyAlgorithm;

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

            // SHA-1 counts here too: it is accepted for some key self-signatures, and must still meet
            // each algorithm's minimum (e.g. never for EdDSA or ECDSA).
            int minimumHashBits = key.VerificationKey.MinimumHashBits;
            if ((HashContext.IsSupported(signature.HashAlgorithm) || signature.HashAlgorithm == HashAlgorithmId.Sha1)
                && HashContext.DigestBits(signature.HashAlgorithm) < minimumHashBits)
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

            return key.CanVerify && key.VerificationKey.Verify(signature.HashAlgorithm, digest, signature.Value);
        }

        /// <summary>
        /// Classifies <paramref name="signature"/> as a signature by <paramref name="issuer"/> over
        /// <paramref name="signedContent"/>: verified, not from this key (a third-party
        /// certification, a forgery, a malformed packet - all ignored), or claiming to be from this
        /// key but impossible to check (an unsupported or too-weak hash or algorithm). The last kind
        /// must not be treated as absent: an uncheckable revocation or expiration could be genuine.
        /// </summary>
        public static KeySignatureCheck CheckKeySignature(PublicKeyPacket issuer, SignaturePacket signature, byte[] signedContent)
        {
            try
            {
                if (!IsIssuedBy(signature, issuer, hashedOnly: true) || IsForDifferentKey(issuer, signature))
                {
                    return KeySignatureCheck.NotFromKey;
                }

                if (GetIncompatibility(issuer, signature) is not null)
                {
                    return KeySignatureCheck.Unverifiable; // e.g. a hash too weak for the algorithm
                }

                GetCreationTime(signature); // throws if missing or malformed
                byte[] digest = SignatureHashBuilder.ComputeDigest(signedContent, signature, isKeySignature: true);
                return VerifyDigest(issuer, signature, digest) ? KeySignatureCheck.Valid : KeySignatureCheck.NotFromKey;
            }
            catch (FailClosedException ex)
            {
                // An unsupported hash (MD5, RIPEMD-160) can't be checked; anything else is malformed.
                return ex.IsUnsupported ? KeySignatureCheck.Unverifiable : KeySignatureCheck.NotFromKey;
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

        /// <summary>Whether <paramref name="createdAt"/> lies further in the future than <see cref="MaxClockSkew"/> allows.</summary>
        public static bool IsFromTheFuture(DateTimeOffset createdAt, DateTimeOffset now) => createdAt > now + MaxClockSkew;

        /// <summary>
        /// Whether the signature, created at <paramref name="createdAt"/>, is within its own validity
        /// period at <paramref name="now"/>: not past its hashed signature-expiration time (RFC 9580
        /// §5.2.3.18; zero means it never expires).
        /// </summary>
        public static bool IsUnexpired(SignaturePacket signature, DateTimeOffset createdAt, DateTimeOffset now) =>
            !signature.TryGetHashedTime(SignatureSubpacketType.SignatureExpirationTime, out uint lifetimeSeconds)
            || lifetimeSeconds == 0
            || now < createdAt.AddSeconds(lifetimeSeconds);
    }

    /// <summary>The outcome of checking a key signature (see <see cref="SignatureVerifier.CheckKeySignature"/>).</summary>
    internal enum KeySignatureCheck
    {
        /// <summary>Verified: made by the key, over this content.</summary>
        Valid,

        /// <summary>Not a signature by this key: a third party's, a forgery, or malformed. Ignored.</summary>
        NotFromKey,

        /// <summary>Claims to be by this key, but its hash or algorithm can't be checked.</summary>
        Unverifiable,
    }
}
