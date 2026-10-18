using System;
using System.Collections.Generic;
using System.Linq;
using Scarlet.OpenPgp.Internal;
using Scarlet.OpenPgp.Packets;

namespace Scarlet.OpenPgp.Verification
{
    /// <summary>
    /// Turns the packets of one certificate - every copy of it in a key input - into a verified
    /// <see cref="Certificate"/>: works out what each signature covers, checks it cryptographically,
    /// and keeps only what verifies.
    /// </summary>
    /// <remarks>
    /// <para>
    /// A signature counts for whatever it verifiably covers, not for where it sits in the block. A
    /// key revocation moved after a User ID, a subkey revocation moved under another subkey or into
    /// another copy of the certificate, or a self-certification moved under another User ID, still
    /// verifies over its own content, so it still applies - rearranging packets, or repeating the
    /// Public-Key packet to start a new copy, must not be a way to make a revocation or restriction
    /// disappear. So signatures are only collected while the copies are read (<see cref="AddCopy"/>),
    /// and matched against every User ID and subkey of every copy at the end (<see cref="Build"/>).
    /// </para>
    /// <para>
    /// Every signature check is paid for from one <see cref="CheckBudget"/> per certificate,
    /// weighted by what the check costs, so key data downloaded from somewhere can't force unbounded
    /// work - a "flooded" certificate carrying tens of thousands of third-party signatures
    /// (CVE-2019-13050), one repeated thousands of times, or one whose key makes every check
    /// expensive, is rejected instead.
    /// </para>
    /// </remarks>
    internal sealed class CertificateBuilder
    {
        private readonly PublicKeyPacket _primary;
        private readonly byte[] _primaryHashPrefix;
        private readonly CheckBudget _budget = new();
        private readonly List<SignaturePacket> _directSignatures = [];
        private readonly List<SignaturePacket> _directRevocations = [];
        private readonly List<SignaturePacket> _revocations = [];
        private readonly List<UserIdDraft> _userIds = [];
        private readonly Dictionary<byte[], UserIdDraft> _userIdsByPrefix = new(ByteArrayComparer.Instance);
        private readonly List<SubkeyDraft> _subkeys = [];
        private readonly Dictionary<byte[], SubkeyDraft> _subkeysByFingerprint = new(ByteArrayComparer.Instance);

        // Signatures whose target is only known once every copy has been read, each with the target
        // it was placed next to (tried first). Matched in Build.
        private readonly List<(SignaturePacket Signature, UserIdDraft? Preferred)> _certifications = [];
        private readonly List<(SignaturePacket Signature, UserIdDraft? Preferred)> _certificationRevocations = [];
        private readonly List<(SignaturePacket Signature, SubkeyDraft? Preferred)> _subkeySignatures = [];

        // Parsed signatures already taken in, by body: a copy repeating them adds nothing. Placement
        // doesn't matter, since every signature is matched against every target.
        private readonly HashSet<byte[]> _seenSignatures = new(ByteArrayComparer.Instance);
        private bool _unparseableOutsideSubkeys;
        private int _unverifiableSignatures;

        private CertificateBuilder(PublicKeyPacket primary)
        {
            _primary = primary;
            _primaryHashPrefix = KeyHashPrefix.Build(primary.Version, primary.Body);
        }

        public PublicKeyPacket Primary => _primary;

        /// <summary>Starts a certificate for <paramref name="primary"/>.</summary>
        /// <exception cref="FailClosedException">The primary key can't make signatures this library verifies (reported as unsupported).</exception>
        public static CertificateBuilder Create(PublicKeyPacket primary)
        {
            if (!primary.CanVerify)
            {
                // It can neither sign data nor certify its own subkeys and User IDs.
                throw FailClosedException.Unsupported("The primary key's algorithm (" + primary.AlgorithmDescription + ") can't make signatures this library verifies.");
            }

            return new CertificateBuilder(primary);
        }

        /// <summary>Reads one copy of the certificate: <paramref name="packets"/> starts with this certificate's Public-Key packet.</summary>
        public void AddCopy(IReadOnlyList<Packet> packets)
        {
            // What the signatures currently being read sit next to, in this copy.
            UserIdDraft? currentUserId = null;
            SubkeyDraft? currentSubkey = null;
            bool inSubkeySection = false;

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
                            // Not deduplicated: where an unparseable signature sits decides which
                            // subkey it could concern, so each placement counts.
                            _unparseableOutsideSubkeys |= RecordUnparseable(packet.Body, inSubkeySection, currentSubkey);
                            break;
                        }

                        // Every signature this builder uses is the primary key's (back-signatures are
                        // embedded in its bindings), so a third party's, which names its issuer, is
                        // dropped here rather than held until every copy has been read.
                        if (!CouldBeFromPrimary(signature) || !_seenSignatures.Add(signature.Body))
                        {
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
                                _certificationRevocations.Add((signature, currentUserId));
                                break;

                            case SignatureType.SubkeyBinding:
                            case SignatureType.SubkeyRevocation:
                                _subkeySignatures.Add((signature, inSubkeySection ? currentSubkey : null));
                                break;

                            default:
                                if (signature.SignatureTypeRaw >= (byte)SignatureType.GenericCertification
                                    && signature.SignatureTypeRaw <= (byte)SignatureType.PositiveCertification)
                                {
                                    _certifications.Add((signature, currentUserId));
                                }

                                break;
                        }

                        break;

                    default:
                        throw new FailClosedException("Unexpected packet (tag " + packet.Header.RawTag + ") in a public key block.");
                }
            }
        }

        /// <summary>Matches the collected signatures against every User ID and subkey of every copy, and returns the verified certificate.</summary>
        public Certificate Build()
        {
            foreach ((SignaturePacket signature, UserIdDraft? preferred) in _certifications)
            {
                AddCertification(signature, preferred);
            }

            foreach ((SignaturePacket signature, UserIdDraft? preferred) in _certificationRevocations)
            {
                AddCertificationRevocation(signature, preferred);
            }

            foreach ((SignaturePacket signature, SubkeyDraft? preferred) in _subkeySignatures)
            {
                AddSubkeySignature(signature, preferred);
            }

            if (_unparseableOutsideSubkeys)
            {
                MarkAllSubkeysUnverifiable();
            }

            SetAsideCollidableCertifications();

            return new Certificate(
                _primary,
                new SignatureSet(_directSignatures, _directRevocations),
                _revocations,
                _userIds.Select(u => new CertifiedUserId(u.HashPrefix, u.Text, new SignatureSet(u.Signatures, u.Revocations))).ToList(),
                _subkeys.Select(s => new CertifiedSubkey(s.Key, s.Bindings, s.Revocations, s.UnverifiableSignatures)).ToList(),
                _unverifiableSignatures);
        }

        /// <summary>
        /// Drops SHA-1 User ID self-certifications made after the collision cutoff (see
        /// <see cref="SignatureVerifier.Sha1CertificationCutoff"/>) when the key has any other
        /// self-signature: a forged one would be added to a key that has real ones, newer than them
        /// and without their restrictions. A key whose self-signatures are all like that keeps them -
        /// dropping them would drop the restrictions they carry, and a key with no self-signature at
        /// all is unrestricted.
        /// </summary>
        /// <remarks>
        /// Stricter than GnuPG 2.4, which still accepts these self-signatures; the User ID they
        /// certify then isn't listed. Real keys with one (e.g. a Node.js releaser's, from 2020) keep
        /// their other self-signatures, so verdicts don't change.
        /// </remarks>
        private void SetAsideCollidableCertifications()
        {
            bool hasOtherSelfSignature = _directSignatures.Count > 0
                || _userIds.Exists(u => u.Signatures.Exists(s => !IsCollidable(s)));
            if (!hasOtherSelfSignature)
            {
                return;
            }

            foreach (UserIdDraft userId in _userIds)
            {
                userId.Signatures.RemoveAll(IsCollidable);
            }

            // Every signature here verified, which requires a readable creation time.
            static bool IsCollidable(SignaturePacket signature) =>
                SignatureVerifier.IsCollidableCertification(signature, SignatureVerifier.GetCreationTime(signature));
        }

        /// <summary>
        /// Whether <paramref name="signature"/> could be the primary key's at all: its signed issuer
        /// hints, version and algorithm allow it. A free test, done as each signature is read: a third
        /// party's signature names its issuer, so it is dropped at once - never held in memory or
        /// tried against every User ID or subkey.
        /// </summary>
        private bool CouldBeFromPrimary(SignaturePacket signature) =>
            SignatureVerifier.IsIssuedBy(signature, _primary, hashedOnly: true) && !SignatureVerifier.IsForDifferentKey(_primary, signature);

        /// <summary>
        /// Every key-signature check goes through here, so the budget can't be bypassed. A check
        /// costs what its key's verification costs, plus the hashing of <paramref name="signedContent"/>
        /// and of the signature's own hashed area: a huge User ID is hashed again for every signature
        /// over it, and a signature with a huge hashed area again for every User ID or subkey it is
        /// tried against.
        /// </summary>
        private KeySignatureCheck Check(PublicKeyPacket issuer, SignaturePacket signature, byte[] signedContent)
        {
            if (!SignatureVerifier.IsIssuedBy(signature, issuer, hashedOnly: true) || SignatureVerifier.IsForDifferentKey(issuer, signature))
            {
                return KeySignatureCheck.NotFromKey;
            }

            _budget.Spend((issuer.CanVerify ? issuer.VerificationKey.CheckCost : 1) + ((signedContent.Length + signature.HashedPortionLength) / CheckBudget.HashedBytesPerUnit));
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
            if (_userIdsByPrefix.TryGetValue(hashPrefix, out UserIdDraft? existing))
            {
                return existing;
            }

            // User IDs are UTF-8 by convention (RFC 9580 §5.11); invalid bytes become U+FFFD, which
            // is fine for a display-only value. User Attributes (photos) have no text.
            var entry = new UserIdDraft(hashPrefix, Concat(_primaryHashPrefix, hashPrefix), tag == PacketTag.UserId ? System.Text.Encoding.UTF8.GetString(body) : null);
            _userIds.Add(entry);
            _userIdsByPrefix.Add(hashPrefix, entry);
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

            if (_subkeysByFingerprint.TryGetValue(key.Fingerprint.Bytes, out SubkeyDraft? existing))
            {
                return existing;
            }

            // Subkey binding and revocation signatures hash the primary key, then the subkey, each
            // with the same key framing (RFC 9580 §5.2.4).
            var subkey = new SubkeyDraft(key, Concat(_primaryHashPrefix, KeyHashPrefix.Build(key.Version, key.Body)));
            _subkeys.Add(subkey);
            _subkeysByFingerprint.Add(key.Fingerprint.Bytes, subkey);
            return subkey;
        }

        /// <summary>The User ID it was placed next to first, then every other.</summary>
        private IEnumerable<UserIdDraft> UserIdCandidates(UserIdDraft? preferred) =>
            preferred is null ? _userIds : new[] { preferred }.Concat(_userIds.Where(u => u != preferred));

        /// <summary>
        /// A self-certification (0x10-0x13) applies to the User ID it verifies over: the one it
        /// follows first, then every other. Dropping one because it was moved would drop whatever it
        /// restricts - a newer self-signature that makes the key expire, say - leaving an older one
        /// in charge. One by a third party matches nothing and is ignored.
        /// </summary>
        private void AddCertification(SignaturePacket signature, UserIdDraft? preferred)
        {
            foreach (UserIdDraft userId in UserIdCandidates(preferred))
            {
                KeySignatureCheck check = Check(_primary, signature, userId.CertificationContent);
                if (check == KeySignatureCheck.NotFromKey)
                {
                    continue;
                }

                // Unverifiable doesn't depend on the content (an unsupported or too-weak hash), so
                // it is counted once.
                Record(check, signature, userId.Signatures);
                return;
            }
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
            // User IDs.
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
                KeySignatureCheck check = Check(_primary, signature, target is null ? _primaryHashPrefix : target.CertificationContent);
                if (check == KeySignatureCheck.NotFromKey)
                {
                    continue; // over other content
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
        /// could concern unusable. Anyone can make a genuine signature unparseable (re-encode its
        /// signature value, change its version octet) without a private key, so skipping it would
        /// let anyone delete it.
        /// </summary>
        /// <remarks>
        /// User ID certifications and their revocations are issued by third parties too, and theirs
        /// are ignored. So one of those counts only if its signed issuer hint names the primary key:
        /// an unsigned hint can be changed, and one without any signed hint can't be told apart from
        /// a third party's (RFC 9580 has every v4/v6 signature carry a hashed Issuer Fingerprint).
        /// </remarks>
        /// <returns>
        /// Whether it is a subkey binding or revocation outside any subkey's section, which could
        /// concern any subkey - including ones not read yet, so they are all marked at the end.
        /// </returns>
        private bool RecordUnparseable(byte[] body, bool inSubkeySection, SubkeyDraft? currentSubkey)
        {
            // The type octet is the second in v4/v6 and the third in v3. The version octet isn't
            // signed either: a v4 revocation relabeled as v3 must still be seen as a revocation, so
            // both positions are considered.
            bool outsideSubkeys = body.Length > 1 && RecordUnparseable(body[1], body, inSubkeySection, currentSubkey);
            if (body.Length > 2 && body[0] == 3)
            {
                outsideSubkeys |= RecordUnparseable(body[2], body, inSubkeySection, currentSubkey);
            }

            return outsideSubkeys;
        }

        private bool RecordUnparseable(byte type, byte[] body, bool inSubkeySection, SubkeyDraft? currentSubkey)
        {
            if ((type >= (byte)SignatureType.GenericCertification && type <= (byte)SignatureType.PositiveCertification)
                || type == (byte)SignatureType.CertificationRevocation)
            {
                if (HasSignedHintFor(body, _primary))
                {
                    _unverifiableSignatures++;
                }

                return false;
            }

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

        /// <summary>
        /// Whether the hashed subpacket area of a signature body that doesn't parse as a whole names
        /// <paramref name="key"/> by Issuer Fingerprint or Issuer Key ID. The area is read on its
        /// own, so a broken signature value or unhashed area doesn't hide it. The version octet isn't
        /// trusted to say where the area is: it is read both as v4 (two-octet length) and as v6
        /// (four-octet length) lays it out (RFC 9580 §5.2.3).
        /// </summary>
        private static bool HasSignedHintFor(byte[] body, PublicKeyPacket key) =>
            HasSignedHintFor(body, 2, key) || HasSignedHintFor(body, 4, key);

        private static bool HasSignedHintFor(byte[] body, int lengthSize, PublicKeyPacket key)
        {
            // Version, type, public-key and hash algorithm octets, then the hashed area's length.
            int start = 4 + lengthSize;
            if (body.Length < start)
            {
                return false;
            }

            long length = 0;
            for (int i = 4; i < start; i++)
            {
                length = (length << 8) | body[i];
            }

            if (length > body.Length - start)
            {
                return false;
            }

            SubpacketArea hashed;
            try
            {
                hashed = SubpacketArea.Read(body, start, (int)length);
            }
            catch (FailClosedException)
            {
                return false;
            }

            foreach (SignatureSubpacket subpacket in hashed)
            {
                if ((subpacket.Is(SignatureSubpacketType.IssuerFingerprint) && subpacket.Data.Length > 1 && key.Fingerprint.Matches(subpacket.Data.Slice(1)))
                    || (subpacket.Is(SignatureSubpacketType.IssuerKeyId) && subpacket.Data.Length == 8 && key.Fingerprint.MatchesKeyId(subpacket.Data)))
                {
                    return true;
                }
            }

            return false;
        }

        private void MarkAllSubkeysUnverifiable()
        {
            foreach (SubkeyDraft subkey in _subkeys)
            {
                subkey.UnverifiableSignatures++;
            }
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

        private sealed class UserIdDraft(byte[] hashPrefix, byte[] certificationContent, string? text)
        {
            public byte[] HashPrefix { get; } = hashPrefix;

            /// <summary>What a certification of this User ID hashes: the framed primary key, then the framed User ID. Built once, not per signature.</summary>
            public byte[] CertificationContent { get; } = certificationContent;

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
