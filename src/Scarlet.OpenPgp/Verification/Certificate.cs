using System;
using System.Collections.Generic;
using System.Linq;
using Scarlet.OpenPgp.Internal;
using Scarlet.OpenPgp.Packets;

namespace Scarlet.OpenPgp.Verification
{
    /// <summary>
    /// One of the caller's trusted certificates (a "transferable public key", RFC 9580 §10.1), as
    /// verified by <see cref="CertificateBuilder"/>: a primary key with the self-signatures and
    /// revocations that verified against it, and its subkeys with theirs. Nothing unverified is in
    /// here, so a stray or forged packet in the key data can never change what it says.
    /// </summary>
    /// <remarks>
    /// Immutable. What the certificate means at a given time - whether a key is expired, revoked as
    /// of a signature, allowed to sign - is <see cref="KeyValidity"/>'s job.
    /// </remarks>
    internal sealed class Certificate
    {
        public Certificate(
            PublicKeyPacket primary,
            SignatureSet directSignatures,
            IReadOnlyList<SignaturePacket> revocations,
            IReadOnlyList<CertifiedUserId> userIds,
            IReadOnlyList<CertifiedSubkey> subkeys,
            int unverifiableSignatures)
        {
            Primary = primary;
            DirectSignatures = directSignatures;
            Revocations = revocations;
            UserIdEntries = userIds;
            Subkeys = subkeys;
            UnverifiableSignatures = unverifiableSignatures;

            // Derived once: the certificate never changes, and these are read on every verification.
            var keys = new PublicKeyPacket[1 + subkeys.Count];
            keys[0] = primary;
            for (int i = 0; i < subkeys.Count; i++)
            {
                keys[i + 1] = subkeys[i].Key;
            }

            Keys = keys;
            SelfSignatures = [.. directSignatures.Effective, .. userIds.SelectMany(u => u.Signatures.Effective)];
            var userIdTexts = new List<string>();
            foreach (CertifiedUserId userId in userIds)
            {
                if (userId.Text is { } text && userId.Signatures.Effective.Count > 0)
                {
                    userIdTexts.Add(text);
                }
            }

            UserIds = userIdTexts;
            HasSelfSignatures = directSignatures.HasAny || userIds.Any(u => u.Signatures.HasAny);
        }

        public PublicKeyPacket Primary { get; }

        /// <summary>Direct Key signatures (0x1F) and the certification revocations (0x30) of them.</summary>
        public SignatureSet DirectSignatures { get; }

        /// <summary>Key revocations (0x20).</summary>
        public IReadOnlyList<SignaturePacket> Revocations { get; }

        /// <summary>User IDs and User Attributes with their self-certifications and revocations of them.</summary>
        public IReadOnlyList<CertifiedUserId> UserIdEntries { get; }

        public IReadOnlyList<CertifiedSubkey> Subkeys { get; }

        /// <summary>Self-signatures and revocations that claim to be from the primary key but can't be checked (see <see cref="SignatureVerifier.CheckKeySignature"/>).</summary>
        public int UnverifiableSignatures { get; }

        /// <summary>The primary key followed by every subkey, in order.</summary>
        public IReadOnlyList<PublicKeyPacket> Keys { get; }

        /// <summary>The User IDs carrying an unrevoked self-certification, in certificate order.</summary>
        public IReadOnlyList<string> UserIds { get; }

        /// <summary>
        /// The self-signatures that describe the primary key: Direct Key signatures and User ID
        /// self-certifications, minus those a later certification revocation (0x30) took back.
        /// </summary>
        public IReadOnlyList<SignaturePacket> SelfSignatures { get; }

        /// <summary>Whether the primary key has ever had a valid self-signature, revoked or not.</summary>
        public bool HasSelfSignatures { get; }

        /// <summary>Whether <paramref name="key"/> (the primary or a subkey) has a valid revocation, hard or soft.</summary>
        public bool IsRevoked(PublicKeyPacket key) =>
            ReferenceEquals(key, Primary) ? Revocations.Count > 0 : FindSubkey(key)?.Revocations.Count > 0;

        public CertifiedSubkey? FindSubkey(PublicKeyPacket key)
        {
            foreach (CertifiedSubkey subkey in Subkeys)
            {
                if (ReferenceEquals(subkey.Key, key))
                {
                    return subkey;
                }
            }

            return null;
        }
    }

    /// <summary>
    /// Verified self-certifications (or Direct Key signatures) and the verified certification
    /// revocations (0x30) over the same content. A revocation takes back every certification made
    /// no later than itself; a newer certification is valid again, as RFC 9580 §5.2.1.14 lets a key
    /// owner re-certify.
    /// </summary>
    internal sealed class SignatureSet(IReadOnlyList<SignaturePacket> signatures, IReadOnlyList<SignaturePacket> revocations)
    {
        public IReadOnlyList<SignaturePacket> Signatures { get; } = signatures;

        public IReadOnlyList<SignaturePacket> Revocations { get; } = revocations;

        public bool HasAny => Signatures.Count > 0;

        /// <summary>
        /// The signatures no revocation took back. Computed once; every signature here passed
        /// <see cref="SignatureVerifier.CheckKeySignature"/>, which requires a readable creation
        /// time, so this can't throw.
        /// </summary>
        public IReadOnlyList<SignaturePacket> Effective { get; } = Unrevoked(signatures, revocations);

        /// <summary>A revocation takes back every signature made no later than itself, so only the newest revocation matters - linear rather than comparing every pair.</summary>
        private static SignaturePacket[] Unrevoked(IReadOnlyList<SignaturePacket> signatures, IReadOnlyList<SignaturePacket> revocations)
        {
            if (revocations.Count == 0)
            {
                return [.. signatures];
            }

            DateTimeOffset newestRevocation = DateTimeOffset.MinValue;
            foreach (SignaturePacket revocation in revocations)
            {
                DateTimeOffset createdAt = SignatureVerifier.GetCreationTime(revocation);
                if (createdAt > newestRevocation)
                {
                    newestRevocation = createdAt;
                }
            }

            var unrevoked = new List<SignaturePacket>();
            foreach (SignaturePacket signature in signatures)
            {
                if (SignatureVerifier.GetCreationTime(signature) > newestRevocation)
                {
                    unrevoked.Add(signature);
                }
            }

            return [.. unrevoked];
        }
    }

    /// <summary>A User ID or User Attribute packet, identified by its hash prefix, with its verified self-certifications.</summary>
    internal sealed class CertifiedUserId(byte[] hashPrefix, string? text, SignatureSet signatures)
    {
        /// <summary>The framed packet as certifications hash it (RFC 9580 §5.2.4); also what identifies a repeated copy.</summary>
        public byte[] HashPrefix { get; } = hashPrefix;

        /// <summary>The User ID text; <c>null</c> for a User Attribute.</summary>
        public string? Text { get; } = text;

        public SignatureSet Signatures { get; } = signatures;
    }

    /// <summary>A subkey binding signature with the back-signatures embedded in it that verified against the subkey.</summary>
    internal sealed class SubkeyBinding(SignaturePacket signature, IReadOnlyList<SignaturePacket> backSignatures)
    {
        public SignaturePacket Signature { get; } = signature;

        public IReadOnlyList<SignaturePacket> BackSignatures { get; } = backSignatures;
    }

    /// <summary>A subkey with its verified binding signatures and revocations.</summary>
    internal sealed class CertifiedSubkey(PublicKeyPacket key, IReadOnlyList<SubkeyBinding> bindings, IReadOnlyList<SignaturePacket> revocations, int unverifiableSignatures)
    {
        public PublicKeyPacket Key { get; } = key;

        public IReadOnlyList<SubkeyBinding> Bindings { get; } = bindings;

        public IReadOnlyList<SignaturePacket> Revocations { get; } = revocations;

        /// <summary>Bindings or revocations that may concern this subkey but can't be checked or parsed.</summary>
        public int UnverifiableSignatures { get; } = unverifiableSignatures;
    }
}
