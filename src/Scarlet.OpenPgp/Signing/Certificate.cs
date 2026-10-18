using System;
using System.Collections.Generic;
using System.Linq;
using Scarlet.OpenPgp.Packets;

namespace Scarlet.OpenPgp.Signing
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
        public IEnumerable<PublicKeyPacket> Keys => new[] { Primary }.Concat(Subkeys.Select(s => s.Key));

        /// <summary>The User IDs carrying an unrevoked self-certification, in certificate order.</summary>
        public IReadOnlyList<string> UserIds =>
            UserIdEntries.Where(u => u.Text is not null && u.Signatures.Effective.Any()).Select(u => u.Text!).ToList();

        /// <summary>
        /// The self-signatures that describe the primary key: Direct Key signatures and User ID
        /// self-certifications, minus those a later certification revocation (0x30) took back.
        /// </summary>
        public IEnumerable<SignaturePacket> SelfSignatures =>
            DirectSignatures.Effective.Concat(UserIdEntries.SelectMany(u => u.Signatures.Effective));

        /// <summary>Whether the primary key has ever had a valid self-signature, revoked or not.</summary>
        public bool HasSelfSignatures => DirectSignatures.HasAny || UserIdEntries.Any(u => u.Signatures.HasAny);

        /// <summary>Whether <paramref name="key"/> (the primary or a subkey) has a valid revocation, hard or soft.</summary>
        public bool IsRevoked(PublicKeyPacket key) =>
            ReferenceEquals(key, Primary) ? Revocations.Count > 0 : FindSubkey(key)?.Revocations.Count > 0;

        public CertifiedSubkey? FindSubkey(PublicKeyPacket key) => Subkeys.FirstOrDefault(s => ReferenceEquals(s.Key, key));

        /// <summary>
        /// Combines two copies of the same certificate (same primary key fingerprint): e.g. an old
        /// export and a newer one concatenated into one key file. Everything either copy verifiably
        /// says is kept - in particular every revocation - so a stale copy can't mask a newer
        /// revocation by being a separate candidate. Which copy comes first makes no difference.
        /// </summary>
        public static Certificate Merge(Certificate first, Certificate second)
        {
            var userIds = first.UserIdEntries.ToList();
            foreach (CertifiedUserId userId in second.UserIdEntries)
            {
                int index = userIds.FindIndex(u => u.HashPrefix.AsSpan().SequenceEqual(userId.HashPrefix));
                if (index < 0)
                {
                    userIds.Add(userId);
                }
                else
                {
                    userIds[index] = new CertifiedUserId(userId.HashPrefix, userId.Text, SignatureSet.Merge(userIds[index].Signatures, userId.Signatures));
                }
            }

            var subkeys = first.Subkeys.ToList();
            foreach (CertifiedSubkey subkey in second.Subkeys)
            {
                int index = subkeys.FindIndex(s => s.Key.Fingerprint.Matches(subkey.Key.Fingerprint.Bytes));
                if (index < 0)
                {
                    subkeys.Add(subkey);
                }
                else
                {
                    subkeys[index] = CertifiedSubkey.Merge(subkeys[index], subkey);
                }
            }

            return new Certificate(
                first.Primary,
                SignatureSet.Merge(first.DirectSignatures, second.DirectSignatures),
                [.. first.Revocations, .. second.Revocations],
                userIds,
                subkeys,
                first.UnverifiableSignatures + second.UnverifiableSignatures);
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

        public IEnumerable<SignaturePacket> Effective =>
            Signatures.Where(s => !Revocations.Any(r => SignatureVerifier.GetCreationTime(r) >= SignatureVerifier.GetCreationTime(s)));

        public static SignatureSet Merge(SignatureSet first, SignatureSet second) =>
            new([.. first.Signatures, .. second.Signatures], [.. first.Revocations, .. second.Revocations]);
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

        public static CertifiedSubkey Merge(CertifiedSubkey first, CertifiedSubkey second) =>
            new(first.Key, [.. first.Bindings, .. second.Bindings], [.. first.Revocations, .. second.Revocations], first.UnverifiableSignatures + second.UnverifiableSignatures);
    }
}
