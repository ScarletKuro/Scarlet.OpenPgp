using System;
using System.Collections.Generic;
using System.Linq;
using Scarlet.OpenPgp.Internal;
using Scarlet.OpenPgp.Packets;

namespace Scarlet.OpenPgp.Verification
{
    /// <summary>
    /// Turns the packets of one certificate into a verified <see cref="Certificate"/>: works out what
    /// each signature covers, checks it cryptographically, and keeps only what verifies.
    /// </summary>
    /// <remarks>
    /// <para>
    /// A signature counts for whatever it verifiably covers, not for where it sits in the block. A
    /// key revocation moved after a User ID, or a subkey revocation moved under another subkey,
    /// still verifies over its own content, so it still applies - rearranging packets must not be a
    /// way to make a revocation disappear.
    /// </para>
    /// <para>
    /// Every signature check is paid for from a <see cref="CheckBudget"/> shared by all copies of the
    /// certificate, so key data downloaded from somewhere can't force unbounded work - a "flooded"
    /// certificate carrying tens of thousands of third-party signatures (CVE-2019-13050), or one
    /// repeated thousands of times, is rejected instead.
    /// </para>
    /// </remarks>
    internal sealed class CertificateBuilder
    {
        private readonly PublicKeyPacket _primary;
        private readonly byte[] _primaryHashPrefix;
        private readonly CheckBudget _budget;
        private readonly List<SignaturePacket> _directSignatures = [];
        private readonly List<SignaturePacket> _directRevocations = [];
        private readonly List<SignaturePacket> _revocations = [];
        private readonly List<UserIdDraft> _userIds = [];
        private readonly List<SubkeyDraft> _subkeys = [];
        private int _unverifiableSignatures;

        private CertificateBuilder(PublicKeyPacket primary, CheckBudget budget)
        {
            _primary = primary;
            _primaryHashPrefix = KeyHashPrefix.Build(primary.Version, primary.Body);
            _budget = budget;
        }

        /// <summary>Builds a certificate from <paramref name="packets"/>, whose first packet is its Public-Key packet.</summary>
        /// <param name="packets">The certificate's packets.</param>
        /// <param name="budgetFor">The check budget for a primary key - the same one for every copy of a certificate.</param>
        public static Certificate Build(IReadOnlyList<Packet> packets, Func<PublicKeyPacket, CheckBudget> budgetFor)
        {
            var primary = PublicKeyPacket.Parse(packets[0].Body);
            if (!primary.CanVerify)
            {
                // It can neither sign data nor certify its own subkeys and User IDs.
                throw FailClosedException.Unsupported("The primary key's algorithm (" + primary.AlgorithmDescription + ") can't make signatures this library verifies.");
            }

            var builder = new CertificateBuilder(primary, budgetFor(primary));
            builder.ReadPackets(packets);
            return builder.ToCertificate();
        }

        private void ReadPackets(IReadOnlyList<Packet> packets)
        {
            // What the signatures currently being read are attached to.
            UserIdDraft? currentUserId = null;
            SubkeyDraft? currentSubkey = null;
            bool inSubkeySection = false;

            // Signatures whose target may not have been read yet (a subkey further down), or that
            // aren't next to it: matched against every candidate once the whole block is read.
            var subkeySignatures = new List<(SignaturePacket Signature, SubkeyDraft? Preferred)>();
            var certificationRevocations = new List<(SignaturePacket Signature, UserIdDraft? Preferred)>();
            bool unparseableOutsideSubkeys = false;

            for (int i = 1; i < packets.Count; i++)
            {
                Packet packet = packets[i];
                switch (packet.Header.Tag)
                {
                    case PacketTag.UserId:
                    case PacketTag.UserAttribute:
                        if (inSubkeySection)
                        {
                            throw new FailClosedException("User ID packet after a subkey in a public key block.");
                        }

                        currentUserId = AddUserId(packet.Header.Tag, packet.Body);
                        break;

                    case PacketTag.PublicSubkey:
                        inSubkeySection = true;
                        currentUserId = null;
                        currentSubkey = AddSubkey(packet.Body);
                        break;

                    case PacketTag.Signature:
                        SignaturePacket? signature = TryParseSignature(packet.Body);
                        if (signature is null)
                        {
                            unparseableOutsideSubkeys |= RecordUnparseable(RawSignatureType(packet.Body), inSubkeySection, currentSubkey);
                            break;
                        }

                        switch ((SignatureType)signature.SignatureTypeRaw)
                        {
                            case SignatureType.DirectKey:
                                Record(Check(_primary, signature, _primaryHashPrefix), signature, _directSignatures);
                                break;

                            case SignatureType.KeyRevocation:
                                Record(Check(_primary, signature, _primaryHashPrefix), signature, _revocations);
                                break;

                            case SignatureType.CertificationRevocation:
                                certificationRevocations.Add((signature, currentUserId));
                                break;

                            case SignatureType.SubkeyBinding:
                            case SignatureType.SubkeyRevocation:
                                subkeySignatures.Add((signature, inSubkeySection ? currentSubkey : null));
                                break;

                            default:
                                // Self-certifications only mean something next to their User ID;
                                // elsewhere they are dropped, which can only take capabilities away.
                                if (currentUserId is not null)
                                {
                                    AddCertification(currentUserId, signature);
                                }

                                break;
                        }

                        break;

                    default:
                        throw new FailClosedException("Unexpected packet (tag " + packet.Header.RawTag + ") in a public key block.");
                }
            }

            foreach ((SignaturePacket signature, UserIdDraft? preferred) in certificationRevocations)
            {
                AddCertificationRevocation(signature, preferred);
            }

            foreach ((SignaturePacket signature, SubkeyDraft? preferred) in subkeySignatures)
            {
                AddSubkeySignature(signature, preferred);
            }

            if (unparseableOutsideSubkeys)
            {
                MarkAllSubkeysUnverifiable();
            }
        }

        private Certificate ToCertificate() => new(
            _primary,
            new SignatureSet(_directSignatures, _directRevocations),
            _revocations,
            _userIds.Select(u => new CertifiedUserId(u.HashPrefix, u.Text, new SignatureSet(u.Signatures, u.Revocations))).ToList(),
            _subkeys.Select(s => new CertifiedSubkey(s.Key, s.Bindings, s.Revocations, s.UnverifiableSignatures)).ToList(),
            _unverifiableSignatures);

        /// <summary>Every key-signature check goes through here, so the budget can't be bypassed.</summary>
        private KeySignatureCheck Check(PublicKeyPacket issuer, SignaturePacket signature, byte[] signedContent)
        {
            _budget.Spend();
            return SignatureVerifier.CheckKeySignature(issuer, signature, signedContent);
        }

        /// <summary>Keeps a verified signature in <paramref name="verified"/>, and counts one that claims to be the key's own but can't be checked.</summary>
        private void Record(KeySignatureCheck check, SignaturePacket signature, List<SignaturePacket> verified)
        {
            if (check == KeySignatureCheck.Valid)
            {
                verified.Add(signature);
            }
            else if (check == KeySignatureCheck.Unverifiable)
            {
                _unverifiableSignatures++;
            }
        }

        private UserIdDraft AddUserId(PacketTag tag, byte[] body)
        {
            byte[] hashPrefix = BuildUserIdHashPrefix(tag, body);
            UserIdDraft? existing = _userIds.FirstOrDefault(u => u.HashPrefix.AsSpan().SequenceEqual(hashPrefix));
            if (existing is not null)
            {
                return existing;
            }

            // User IDs are UTF-8 by convention (RFC 9580 §5.11); invalid bytes become U+FFFD, which
            // is fine for a display-only value. User Attributes (photos) have no text.
            var entry = new UserIdDraft(hashPrefix, tag == PacketTag.UserId ? System.Text.Encoding.UTF8.GetString(body) : null);
            _userIds.Add(entry);
            return entry;
        }

        /// <summary>
        /// The subkey to attach the following signatures to, or <c>null</c> if it can't be parsed or
        /// doesn't match its primary's version - it is then simply unusable, like any subkey of an
        /// unknown algorithm. A repeated subkey continues the existing entry, so its signatures -
        /// revocations included - all land in one place; as a separate entry, a copy without the
        /// revocation could be picked instead.
        /// </summary>
        private SubkeyDraft? AddSubkey(byte[] body)
        {
            PublicKeyPacket key;
            try
            {
                key = PublicKeyPacket.Parse(body);
            }
            catch (FailClosedException)
            {
                return null;
            }

            if (key.Version != _primary.Version)
            {
                return null; // RFC 9580 §10.1: every subkey has its primary key's version
            }

            SubkeyDraft? existing = _subkeys.FirstOrDefault(s => s.Key.Fingerprint.Matches(key.Fingerprint.Bytes));
            if (existing is not null)
            {
                return existing;
            }

            // Subkey binding and revocation signatures hash the primary key, then the subkey, each
            // with the same key framing (RFC 9580 §5.2.4).
            var subkey = new SubkeyDraft(key, Concat(_primaryHashPrefix, KeyHashPrefix.Build(key.Version, key.Body)));
            _subkeys.Add(subkey);
            return subkey;
        }

        private void AddCertification(UserIdDraft userId, SignaturePacket signature)
        {
            if (signature.SignatureTypeRaw < (byte)SignatureType.GenericCertification
                || signature.SignatureTypeRaw > (byte)SignatureType.PositiveCertification)
            {
                return;
            }

            Record(Check(_primary, signature, Concat(_primaryHashPrefix, userId.HashPrefix)), signature, userId.Signatures);
        }

        /// <summary>
        /// A certification revocation (0x30, RFC 9580 §5.2.1.14) revokes earlier certifications over
        /// the same content: a User ID's self-certifications, or - over the primary key alone - its
        /// Direct Key signatures. Matched against the User ID it follows first, then the primary key
        /// alone, then every other User ID. One by a third party matches nothing and is ignored.
        /// </summary>
        private void AddCertificationRevocation(SignaturePacket signature, UserIdDraft? preferred)
        {
            // The targets in order - the preferred User ID, the primary key alone (null), the other
            // User IDs - with each one's signed content built only when it is reached.
            var targets = new List<UserIdDraft?>(_userIds.Count + 1);
            if (preferred is not null)
            {
                targets.Add(preferred);
            }

            targets.Add(null);
            foreach (UserIdDraft userId in _userIds)
            {
                if (userId != preferred)
                {
                    targets.Add(userId);
                }
            }

            foreach (UserIdDraft? target in targets)
            {
                byte[] content = target is null ? _primaryHashPrefix : Concat(_primaryHashPrefix, target.HashPrefix);
                KeySignatureCheck check = Check(_primary, signature, content);
                if (check == KeySignatureCheck.NotFromKey)
                {
                    continue; // over other content, or not the primary key's at all
                }

                // Unverifiable doesn't depend on the content (an unsupported or too-weak hash), so it
                // is counted once: the revocation could be genuine, so the key isn't usable.
                Record(check, signature, target is null ? _directRevocations : target.Revocations);
                return;
            }
        }

        /// <summary>
        /// A subkey binding or revocation applies to the subkey it verifies for: the one it follows
        /// first, then every other. One that verifies for none is ignored; one by the primary key
        /// that can't be checked makes every subkey it could concern unusable.
        /// </summary>
        private void AddSubkeySignature(SignaturePacket signature, SubkeyDraft? preferred)
        {
            IEnumerable<SubkeyDraft> candidates = preferred is null ? _subkeys : new[] { preferred }.Concat(_subkeys.Where(s => s != preferred));
            foreach (SubkeyDraft subkey in candidates)
            {
                KeySignatureCheck check = Check(_primary, signature, subkey.BindingContent);
                if (check == KeySignatureCheck.Valid)
                {
                    AddVerifiedSubkeySignature(subkey, signature);
                    return;
                }

                if (check == KeySignatureCheck.Unverifiable)
                {
                    // Not content-dependent, so it is the same for every subkey: without knowing which
                    // one it concerns, none can be trusted.
                    MarkAllSubkeysUnverifiable();
                    return;
                }
            }
        }

        private void AddVerifiedSubkeySignature(SubkeyDraft subkey, SignaturePacket signature)
        {
            if (signature.SignatureTypeRaw == (byte)SignatureType.SubkeyRevocation)
            {
                subkey.Revocations.Add(signature);
                return;
            }

            // The back-signature is made by the subkey over the same content, proving the subkey's
            // owner agreed to be bound (RFC 9580 §5.2.1.6). A loop, not a LINQ filter: Check spends
            // the budget and can throw, which must not hide inside a lazily evaluated predicate.
            var backSignatures = new List<SignaturePacket>();
            foreach (SignaturePacket embedded in signature.EmbeddedSignatures)
            {
                if (embedded.SignatureTypeRaw == (byte)SignatureType.PrimaryKeyBinding
                    && Check(subkey.Key, embedded, subkey.BindingContent) == KeySignatureCheck.Valid)
                {
                    backSignatures.Add(embedded);
                }
            }

            subkey.Bindings.Add(new SubkeyBinding(signature, backSignatures));
        }

        /// <summary>
        /// A signature that can't even be parsed may still be the key's own statement - often a
        /// revocation - so it must not just vanish: it counts as uncheckable, which makes what it
        /// could concern unusable. User ID certifications and their revocations are skipped: third
        /// parties issue those too, and an unparseable one can't be told apart.
        /// </summary>
        /// <returns>
        /// Whether it is a subkey binding or revocation outside any subkey's section, which could
        /// concern any subkey - including ones not read yet, so the caller marks them all at the end.
        /// </returns>
        private bool RecordUnparseable(byte type, bool inSubkeySection, SubkeyDraft? currentSubkey)
        {
            switch ((SignatureType)type)
            {
                case SignatureType.DirectKey:
                case SignatureType.KeyRevocation:
                    _unverifiableSignatures++;
                    return false;

                case SignatureType.SubkeyBinding:
                case SignatureType.SubkeyRevocation:
                    if (currentSubkey is not null)
                    {
                        currentSubkey.UnverifiableSignatures++;
                    }

                    return !inSubkeySection;

                default:
                    return false;
            }
        }

        private void MarkAllSubkeysUnverifiable()
        {
            foreach (SubkeyDraft subkey in _subkeys)
            {
                subkey.UnverifiableSignatures++;
            }
        }

        /// <summary>The signature type octet of a signature body that may not parse: the third octet in v3, the second otherwise; 0 if too short.</summary>
        private static byte RawSignatureType(byte[] body)
        {
            int index = body.Length > 0 && body[0] == 3 ? 2 : 1;
            return body.Length > index ? body[index] : (byte)0;
        }

        private static SignaturePacket? TryParseSignature(byte[] body)
        {
            try
            {
                return SignaturePacket.Parse(body);
            }
            catch (FailClosedException)
            {
                return null;
            }
        }

        /// <summary>RFC 9580 §5.2.4: a v4/v6 certification hashes 0xB4 (User ID) or 0xD1 (User Attribute), a 4-octet length, then the packet body.</summary>
        private static byte[] BuildUserIdHashPrefix(PacketTag tag, byte[] body)
        {
            var prefix = new byte[5 + body.Length];
            prefix[0] = tag == PacketTag.UserId ? (byte)0xB4 : (byte)0xD1;
            prefix[1] = (byte)(body.Length >> 24);
            prefix[2] = (byte)(body.Length >> 16);
            prefix[3] = (byte)(body.Length >> 8);
            prefix[4] = (byte)body.Length;
            Array.Copy(body, 0, prefix, 5, body.Length);
            return prefix;
        }

        private static byte[] Concat(byte[] a, byte[] b)
        {
            var result = new byte[a.Length + b.Length];
            Array.Copy(a, 0, result, 0, a.Length);
            Array.Copy(b, 0, result, a.Length, b.Length);
            return result;
        }

        private sealed class UserIdDraft(byte[] hashPrefix, string? text)
        {
            public byte[] HashPrefix { get; } = hashPrefix;

            public string? Text { get; } = text;

            public List<SignaturePacket> Signatures { get; } = [];

            public List<SignaturePacket> Revocations { get; } = [];
        }

        private sealed class SubkeyDraft(PublicKeyPacket key, byte[] bindingContent)
        {
            public PublicKeyPacket Key { get; } = key;

            /// <summary>What a binding or revocation of this subkey hashes: the framed primary key, then the framed subkey.</summary>
            public byte[] BindingContent { get; } = bindingContent;

            public List<SubkeyBinding> Bindings { get; } = [];

            public List<SignaturePacket> Revocations { get; } = [];

            public int UnverifiableSignatures { get; set; }
        }
    }
}
