using System;
using System.Collections.Generic;
using System.Linq;
using Scarlet.OpenPgp.Internal;
using Scarlet.OpenPgp.Packets;

namespace Scarlet.OpenPgp.Signing
{
    /// <summary>
    /// One of the caller's trusted certificates (a "transferable public key", RFC 9580 §10.1): a
    /// primary key, its self-signatures and revocations, and its subkeys with their binding
    /// signatures and revocations. Only signatures that verify against the primary key (or, for a
    /// subkey's back-signature, against the subkey) are kept, so a stray or forged signature in the
    /// block can never change what the certificate says.
    /// </summary>
    /// <remarks>
    /// <para>
    /// A signature counts for whatever it verifiably covers, not for where it sits in the block. A
    /// key revocation moved after a User ID, or a subkey revocation moved under another subkey,
    /// still verifies over its own content, so it still applies - rearranging packets must not be a
    /// way to make a revocation disappear.
    /// </para>
    /// <para>
    /// The cryptographic checks happen once, here; whether a key is valid *at a given time* - not
    /// expired, not revoked, still bound - depends on the clock and on the document signature's
    /// creation time, so that part is <see cref="CheckSigningKey"/>.
    /// </para>
    /// </remarks>
    internal sealed class Certificate
    {
        private const byte SignDataFlag = 0x02;

        private readonly byte[] _primaryHashPrefix;

        /// <summary>Verified Direct Key signatures (0x1F), and the certification revocations (0x30) over the primary key alone that revoke them.</summary>
        private readonly SignatureSet _directSignatures = new();

        /// <summary>Verified key revocations (0x20).</summary>
        private readonly List<SignaturePacket> _revocations = [];

        private readonly List<UserIdEntry> _userIds = [];
        private readonly List<Subkey> _subkeys = [];

        /// <summary>Self-signatures and revocations that claim to be from the primary key but can't be checked (see <see cref="SignatureVerifier.CheckKeySignature"/>).</summary>
        private int _unverifiableSignatures;

        private Certificate(PublicKeyPacket primary)
        {
            Primary = primary;
            _primaryHashPrefix = KeyHashPrefix.Build(primary.Version, primary.Body);
        }

        public PublicKeyPacket Primary { get; }

        /// <summary>The primary key followed by every subkey, in order.</summary>
        public IEnumerable<PublicKeyPacket> Keys => new[] { Primary }.Concat(_subkeys.Select(s => s.Key));

        /// <summary>The User IDs carrying an unrevoked valid self-certification, in certificate order.</summary>
        public IReadOnlyList<string> UserIds =>
            _userIds.Where(u => u.Text is not null && u.Signatures.Effective.Any()).Select(u => u.Text!).ToList();

        /// <summary>
        /// The self-signatures that describe the primary key: Direct Key signatures and User ID
        /// self-certifications, minus those a later certification revocation (0x30) took back.
        /// </summary>
        private IEnumerable<SignaturePacket> SelfSignatures =>
            _directSignatures.Effective.Concat(_userIds.SelectMany(u => u.Signatures.Effective));

        /// <summary>Whether the primary key has ever had a valid self-signature, revoked or not.</summary>
        private bool HasSelfSignatures => _directSignatures.HasAny || _userIds.Any(u => u.Signatures.HasAny);

        /// <summary>
        /// Folds another copy of this same certificate (same primary key fingerprint) into this one:
        /// e.g. an old export and a newer one concatenated into one key file. Everything either copy
        /// verifiably says is kept - in particular every revocation - so a stale copy can't mask a
        /// newer revocation by being a separate candidate. The newest valid self-signature still
        /// wins, so the result is the same whichever copy came first.
        /// </summary>
        public void MergeFrom(Certificate other)
        {
            _directSignatures.MergeFrom(other._directSignatures);
            _revocations.AddRange(other._revocations);
            _unverifiableSignatures += other._unverifiableSignatures;
            foreach (UserIdEntry userId in other._userIds)
            {
                UserIdEntry? existing = FindUserId(userId.HashPrefix);
                if (existing is null)
                {
                    _userIds.Add(userId);
                }
                else
                {
                    existing.Signatures.MergeFrom(userId.Signatures);
                }
            }

            foreach (Subkey subkey in other._subkeys)
            {
                Subkey? existing = FindSubkey(subkey.Key.Fingerprint);
                if (existing is null)
                {
                    _subkeys.Add(subkey);
                }
                else
                {
                    existing.MergeFrom(subkey);
                }
            }
        }

        /// <summary>Whether <paramref name="key"/> (the primary or a subkey) has a valid revocation, hard or soft.</summary>
        public bool IsRevoked(PublicKeyPacket key)
        {
            if (ReferenceEquals(key, Primary))
            {
                return _revocations.Count > 0;
            }

            return _subkeys.Any(s => ReferenceEquals(s.Key, key) && s.IsRevoked);
        }

        /// <summary>
        /// When <paramref name="key"/> expires according to its newest valid self-signature (binding
        /// signature, for a subkey) as of <paramref name="now"/> - or, if none is valid any more, its
        /// newest self-signature at all; <c>null</c> if it never expires.
        /// </summary>
        public DateTimeOffset? GetExpiration(PublicKeyPacket key, DateTimeOffset now)
        {
            try
            {
                SignaturePacket? selfSignature = ReferenceEquals(key, Primary)
                    ? LatestPrimarySelfSignature(now) ?? Latest(SelfSignatures)
                    : _subkeys.FirstOrDefault(s => ReferenceEquals(s.Key, key))?.LatestBinding(now);
                return ExpirationOf(selfSignature, key.CreatedAt);
            }
            catch (FailClosedException)
            {
                return null;
            }
        }

        /// <summary>
        /// Builds a certificate from <paramref name="packets"/>[<paramref name="start"/>] (a Public-Key
        /// packet) up to, not including, <paramref name="end"/>.
        /// </summary>
        public static Certificate Build(List<Packet> packets, int start, int end)
        {
            var certificate = new Certificate(PublicKeyPacket.Parse(packets[start].Body));

            // What the signatures currently being read are attached to.
            UserIdEntry? currentUserId = null;
            Subkey? currentSubkey = null;
            bool inSubkeySection = false;

            // Signatures whose target may not have been read yet (a subkey further down), or that
            // aren't next to it: matched against every candidate once the whole block is read.
            var subkeySignatures = new List<(SignaturePacket Signature, Subkey? Preferred)>();
            var certificationRevocations = new List<(SignaturePacket Signature, UserIdEntry? Preferred)>();
            bool unparseableOutsideSubkeys = false;

            for (int i = start + 1; i < end; i++)
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

                        currentUserId = certificate.AddUserId(packet.Header.Tag, packet.Body);
                        break;

                    case PacketTag.PublicSubkey:
                        inSubkeySection = true;
                        currentUserId = null;
                        currentSubkey = Subkey.TryCreate(certificate.Primary, packet.Body);
                        if (currentSubkey is not null)
                        {
                            // A repeated subkey continues the existing entry, so its signatures -
                            // revocations included - all land in one place. As a separate entry, a
                            // copy without the revocation could be picked instead.
                            Subkey? existing = certificate.FindSubkey(currentSubkey.Key.Fingerprint);
                            if (existing is null)
                            {
                                certificate._subkeys.Add(currentSubkey);
                            }
                            else
                            {
                                currentSubkey = existing;
                            }
                        }

                        break;

                    case PacketTag.Signature:
                        SignaturePacket? signature = TryParseSignature(packet.Body);
                        if (signature is null)
                        {
                            unparseableOutsideSubkeys |= certificate.RecordUnparseable(RawSignatureType(packet.Body), inSubkeySection, currentSubkey);
                            break;
                        }

                        switch ((SignatureType)signature.SignatureTypeRaw)
                        {
                            case SignatureType.DirectKey:
                                Record(certificate.CheckOverPrimary(signature), signature, certificate._directSignatures.Signatures, ref certificate._unverifiableSignatures);
                                break;

                            case SignatureType.KeyRevocation:
                                Record(certificate.CheckOverPrimary(signature), signature, certificate._revocations, ref certificate._unverifiableSignatures);
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
                                    certificate.AddCertification(currentUserId, signature);
                                }

                                break;
                        }

                        break;

                    default:
                        throw new FailClosedException("Unexpected packet (tag " + packet.Header.RawTag + ") in a public key block.");
                }
            }

            foreach ((SignaturePacket signature, UserIdEntry? preferred) in certificationRevocations)
            {
                certificate.AddCertificationRevocation(signature, preferred);
            }

            foreach ((SignaturePacket signature, Subkey? preferred) in subkeySignatures)
            {
                certificate.AddSubkeySignature(signature, preferred);
            }

            if (unparseableOutsideSubkeys)
            {
                certificate.MarkAllSubkeysUnverifiable();
            }

            return certificate;
        }

        /// <summary>
        /// Whether <paramref name="signingKey"/> (this certificate's primary key or one of its
        /// subkeys) may have made a data signature created at <paramref name="signatureCreatedAt"/>,
        /// judged at <paramref name="now"/>. Returns <see cref="VerificationStatus.Valid"/> or the
        /// reason it may not, with an explanation.
        /// </summary>
        public (VerificationStatus Status, string Message) CheckSigningKey(PublicKeyPacket signingKey, DateTimeOffset signatureCreatedAt, DateTimeOffset now)
        {
            try
            {
                var primaryCheck = CheckPrimary(signatureCreatedAt, now, out SignaturePacket? primarySelfSignature);
                if (primaryCheck.Status != VerificationStatus.Valid)
                {
                    return primaryCheck;
                }

                if (ReferenceEquals(signingKey, Primary))
                {
                    byte[]? flags = primarySelfSignature?.KeyFlags;
                    if (flags is not null && !HasSignFlag(flags))
                    {
                        return (VerificationStatus.KeyNotValidForSigning, "The primary key's self-signature does not allow it to sign data.");
                    }

                    return (VerificationStatus.Valid, "Valid.");
                }

                Subkey? subkey = _subkeys.FirstOrDefault(s => ReferenceEquals(s.Key, signingKey));
                if (subkey is null)
                {
                    return (VerificationStatus.NoMatchingKey, "The signing key is not part of this certificate.");
                }

                return subkey.Check(signatureCreatedAt, now);
            }
            catch (FailClosedException ex)
            {
                return (VerificationStatus.KeyNotValidForSigning, "The certificate's self-signatures can't be used: " + ex.Message);
            }
        }

        private (VerificationStatus Status, string Message) CheckPrimary(DateTimeOffset signatureCreatedAt, DateTimeOffset now, out SignaturePacket? latestSelfSignature)
        {
            latestSelfSignature = null;
            // A self-signature or revocation the key appears to have made, but whose hash or
            // algorithm can't be checked, could be genuine - a revocation, an expiration, a
            // restriction. Ignoring it could widen what the key may do, so the key isn't usable.
            if (_unverifiableSignatures > 0)
            {
                return (VerificationStatus.KeyNotValidForSigning, "The certificate has self-signatures or revocations whose hash or algorithm can't be checked, so the primary key's validity can't be determined.");
            }

            var revocation = CheckRevocations(_revocations, signatureCreatedAt, "primary key");
            if (revocation.Status != VerificationStatus.Valid)
            {
                return revocation;
            }

            latestSelfSignature = LatestPrimarySelfSignature(now);
            if (Primary.Version == 6 && latestSelfSignature is null)
            {
                return (VerificationStatus.KeyNotValidForSigning, "The v6 primary key has no valid, unrevoked Direct Key self-signature.");
            }

            // Only a v4 key that never had a self-signature counts as a bare, unrestricted key. If it
            // has self-signatures but none is valid now (all expired or revoked, say), the
            // restrictions and the expiration they carried must not silently disappear - the key is
            // simply not usable.
            if (latestSelfSignature is null && HasSelfSignatures)
            {
                return (VerificationStatus.KeyNotValidForSigning, "None of the primary key's self-signatures is currently valid (they have expired or been revoked).");
            }

            if (signatureCreatedAt < Primary.CreatedAt)
            {
                return (VerificationStatus.InvalidSignatureTime, "The signature predates the primary key.");
            }

            return CheckExpiration(latestSelfSignature, Primary.CreatedAt, signatureCreatedAt, now, "primary key");
        }

        /// <summary>
        /// The self-signature that describes the primary key at <paramref name="now"/>. RFC 9580
        /// §5.2.3.10: the most recent valid self-signature wins. For a v6 key that must be a Direct Key
        /// signature, and one must exist (§5.2.3.10, §10.1.1) - otherwise an attacker could strip it to
        /// drop an expiration. A v4 key may carry its information on a User ID self-signature instead,
        /// and a bare v4 key with no self-signature at all has no flags and no expiration.
        /// </summary>
        private SignaturePacket? LatestPrimarySelfSignature(DateTimeOffset now)
        {
            IEnumerable<SignaturePacket> candidates = SelfSignatures.Where(s => IsCurrent(s, Primary, now));
            if (Primary.Version == 6)
            {
                candidates = candidates.Where(s => s.SignatureTypeRaw == (byte)SignatureType.DirectKey);
            }

            return Latest(candidates);
        }

        private UserIdEntry AddUserId(PacketTag tag, byte[] body)
        {
            byte[] hashPrefix = BuildUserIdHashPrefix(tag, body);
            UserIdEntry? existing = FindUserId(hashPrefix);
            if (existing is not null)
            {
                return existing;
            }

            // User IDs are UTF-8 by convention (RFC 9580 §5.11); invalid bytes become U+FFFD, which
            // is fine for a display-only value. User Attributes (photos) have no text.
            var entry = new UserIdEntry(hashPrefix, tag == PacketTag.UserId ? System.Text.Encoding.UTF8.GetString(body) : null);
            _userIds.Add(entry);
            return entry;
        }

        private void AddCertification(UserIdEntry userId, SignaturePacket signature)
        {
            if (signature.SignatureTypeRaw < (byte)SignatureType.GenericCertification
                || signature.SignatureTypeRaw > (byte)SignatureType.PositiveCertification)
            {
                return;
            }

            KeySignatureCheck check = SignatureVerifier.CheckKeySignature(Primary, signature, Concat(_primaryHashPrefix, userId.HashPrefix));
            Record(check, signature, userId.Signatures.Signatures, ref _unverifiableSignatures);
        }

        /// <summary>
        /// A certification revocation (0x30, RFC 9580 §5.2.1.14) revokes earlier certifications over
        /// the same content: a User ID's self-certifications, or - over the primary key alone - its
        /// Direct Key signatures. Matched against the User ID it follows first, then the primary key
        /// alone, then every other User ID. One by a third party matches nothing and is ignored.
        /// </summary>
        private void AddCertificationRevocation(SignaturePacket signature, UserIdEntry? preferred)
        {
            var candidates = new List<(byte[] Content, List<SignaturePacket> Revocations)>();
            if (preferred is not null)
            {
                candidates.Add((Concat(_primaryHashPrefix, preferred.HashPrefix), preferred.Signatures.Revocations));
            }

            candidates.Add((_primaryHashPrefix, _directSignatures.Revocations));
            candidates.AddRange(_userIds.Where(u => u != preferred).Select(u => (Concat(_primaryHashPrefix, u.HashPrefix), u.Signatures.Revocations)));

            foreach ((byte[] content, List<SignaturePacket> revocations) in candidates)
            {
                KeySignatureCheck check = SignatureVerifier.CheckKeySignature(Primary, signature, content);
                if (check == KeySignatureCheck.NotFromKey)
                {
                    continue; // over other content, or not the primary key's at all
                }

                // Unverifiable doesn't depend on the content (an unsupported or too-weak hash), so it
                // is counted once: the revocation could be genuine, so the key isn't usable.
                Record(check, signature, revocations, ref _unverifiableSignatures);
                return;
            }
        }

        /// <summary>
        /// A subkey binding or revocation applies to the subkey it verifies for: the one it follows
        /// first, then every other. One that verifies for none is ignored; one by the primary key
        /// that can't be checked makes every subkey it could concern unusable.
        /// </summary>
        private void AddSubkeySignature(SignaturePacket signature, Subkey? preferred)
        {
            IEnumerable<Subkey> candidates = preferred is null ? _subkeys : new[] { preferred }.Concat(_subkeys.Where(s => s != preferred));
            foreach (Subkey subkey in candidates)
            {
                KeySignatureCheck check = subkey.AddSignature(Primary, signature);
                if (check == KeySignatureCheck.Valid)
                {
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
        private bool RecordUnparseable(byte type, bool inSubkeySection, Subkey? currentSubkey)
        {
            switch ((SignatureType)type)
            {
                case SignatureType.DirectKey:
                case SignatureType.KeyRevocation:
                    _unverifiableSignatures++;
                    return false;

                case SignatureType.SubkeyBinding:
                case SignatureType.SubkeyRevocation:
                    currentSubkey?.MarkUnverifiable();
                    return !inSubkeySection;

                default:
                    return false;
            }
        }

        private void MarkAllSubkeysUnverifiable()
        {
            foreach (Subkey subkey in _subkeys)
            {
                subkey.MarkUnverifiable();
            }
        }

        private KeySignatureCheck CheckOverPrimary(SignaturePacket signature) => SignatureVerifier.CheckKeySignature(Primary, signature, _primaryHashPrefix);

        private Subkey? FindSubkey(KeyFingerprint fingerprint) => _subkeys.FirstOrDefault(s => s.Key.Fingerprint.Matches(fingerprint.Bytes));

        private UserIdEntry? FindUserId(byte[] hashPrefix) => _userIds.FirstOrDefault(u => u.HashPrefix.AsSpan().SequenceEqual(hashPrefix));

        /// <summary>Keeps a verified signature in <paramref name="verified"/>, and counts one that claims to be the key's own but can't be checked.</summary>
        private static void Record(KeySignatureCheck check, SignaturePacket signature, List<SignaturePacket> verified, ref int unverifiable)
        {
            if (check == KeySignatureCheck.Valid)
            {
                verified.Add(signature);
            }
            else if (check == KeySignatureCheck.Unverifiable)
            {
                unverifiable++;
            }
        }

        /// <summary>A self-signature counts at <paramref name="now"/> if it was made no earlier than its key and no later than now, and hasn't expired.</summary>
        private static bool IsCurrent(SignaturePacket signature, PublicKeyPacket key, DateTimeOffset now)
        {
            DateTimeOffset createdAt = SignatureVerifier.GetCreationTime(signature);
            return createdAt >= key.CreatedAt && createdAt <= now && SignatureVerifier.IsUnexpired(signature, createdAt, now);
        }

        /// <summary>The newest of <paramref name="signatures"/> (see <see cref="NewestTied"/>), or <c>null</c> if there are none.</summary>
        private static SignaturePacket? Latest(IEnumerable<SignaturePacket> signatures) => NewestTied(signatures).FirstOrDefault();

        /// <summary>
        /// Every signature sharing the newest creation time. Packet order can't pick between them -
        /// it is unsigned - so when there are several they must agree on everything read from them
        /// (key flags and key expiration); if they don't, which one "wins" is ambiguous and the
        /// certificate fails closed.
        /// </summary>
        private static List<SignaturePacket> NewestTied(IEnumerable<SignaturePacket> signatures)
        {
            var newest = new List<SignaturePacket>();
            DateTimeOffset newestCreatedAt = DateTimeOffset.MinValue;
            foreach (SignaturePacket signature in signatures)
            {
                DateTimeOffset createdAt = SignatureVerifier.GetCreationTime(signature);
                if (newest.Count == 0 || createdAt > newestCreatedAt)
                {
                    newest.Clear();
                    newestCreatedAt = createdAt;
                }

                if (createdAt == newestCreatedAt)
                {
                    newest.Add(signature);
                }
            }

            if (newest.Skip(1).Any(s => !AgreeOnKeyProperties(s, newest[0])))
            {
                throw new FailClosedException("Self-signatures made at the same time disagree about the key's flags or expiration.");
            }

            return newest;
        }

        private static bool AgreeOnKeyProperties(SignaturePacket a, SignaturePacket b)
        {
            byte[]? aFlags = a.KeyFlags;
            byte[]? bFlags = b.KeyFlags;
            bool sameFlags = aFlags is null ? bFlags is null : bFlags is not null && aFlags.AsSpan().SequenceEqual(bFlags);
            bool aExpires = a.TryGetHashedTime(SignatureSubpacketType.KeyExpirationTime, out uint aLifetime);
            bool bExpires = b.TryGetHashedTime(SignatureSubpacketType.KeyExpirationTime, out uint bLifetime);
            return sameFlags && aExpires == bExpires && aLifetime == bLifetime;
        }

        /// <summary>
        /// Applies revocations (RFC 9580 §5.2.3.31). "Superseded" and "retired" are soft: signatures
        /// made before the revocation stay valid. Anything else - compromise, no reason, or an
        /// unknown reason - means every signature by the key is suspect.
        /// </summary>
        private static (VerificationStatus Status, string Message) CheckRevocations(List<SignaturePacket> revocations, DateTimeOffset signatureCreatedAt, string what)
        {
            foreach (SignaturePacket revocation in revocations)
            {
                byte? reason = revocation.RevocationReason;
                bool soft = reason == 1 || reason == 3;
                if (!soft)
                {
                    return (VerificationStatus.KeyRevoked, "The " + what + " has been revoked" + (reason == 2 ? " (key material compromised)." : "."));
                }

                if (signatureCreatedAt >= SignatureVerifier.GetCreationTime(revocation))
                {
                    return (VerificationStatus.KeyRevoked, "The " + what + " was retired or superseded before the signature was made.");
                }
            }

            return (VerificationStatus.Valid, "Valid.");
        }

        /// <summary>The key must be unexpired both now and when it made the signature (RFC 9580 §5.2.3.13).</summary>
        private static (VerificationStatus Status, string Message) CheckExpiration(SignaturePacket? selfSignature, DateTimeOffset keyCreatedAt, DateTimeOffset signatureCreatedAt, DateTimeOffset now, string what)
        {
            if (ExpirationOf(selfSignature, keyCreatedAt) is DateTimeOffset expiresAt)
            {
                if (now >= expiresAt)
                {
                    return (VerificationStatus.KeyExpired, "The " + what + " expired at " + expiresAt.ToString("u", System.Globalization.CultureInfo.InvariantCulture) + ".");
                }

                if (signatureCreatedAt >= expiresAt)
                {
                    return (VerificationStatus.KeyExpired, "The signature was made after the " + what + " expired.");
                }
            }

            return (VerificationStatus.Valid, "Valid.");
        }

        /// <summary>The key's expiration according to <paramref name="selfSignature"/>'s key-expiration subpacket (a lifetime from <paramref name="keyCreatedAt"/>; absent or zero means never).</summary>
        private static DateTimeOffset? ExpirationOf(SignaturePacket? selfSignature, DateTimeOffset keyCreatedAt)
        {
            if (selfSignature is not null
                && selfSignature.TryGetHashedTime(SignatureSubpacketType.KeyExpirationTime, out uint lifetimeSeconds)
                && lifetimeSeconds != 0)
            {
                return keyCreatedAt.AddSeconds(lifetimeSeconds);
            }

            return null;
        }

        private static bool HasSignFlag(byte[] flags) => flags.Length > 0 && (flags[0] & SignDataFlag) != 0;

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

        /// <summary>
        /// Verified self-certifications (or Direct Key signatures) and the verified certification
        /// revocations (0x30) over the same content. A revocation takes back every certification
        /// made no later than itself; a newer certification is valid again, as RFC 9580 §5.2.1.14
        /// lets a key owner re-certify.
        /// </summary>
        private sealed class SignatureSet
        {
            public List<SignaturePacket> Signatures { get; } = [];

            public List<SignaturePacket> Revocations { get; } = [];

            public bool HasAny => Signatures.Count > 0;

            public IEnumerable<SignaturePacket> Effective =>
                Signatures.Where(s => !Revocations.Any(r => SignatureVerifier.GetCreationTime(r) >= SignatureVerifier.GetCreationTime(s)));

            public void MergeFrom(SignatureSet other)
            {
                Signatures.AddRange(other.Signatures);
                Revocations.AddRange(other.Revocations);
            }
        }

        /// <summary>A User ID or User Attribute packet, identified by its hash prefix, with its self-certifications.</summary>
        private sealed class UserIdEntry(byte[] hashPrefix, string? text)
        {
            /// <summary>The framed packet as certifications hash it (see <see cref="BuildUserIdHashPrefix"/>); also what identifies a repeated copy.</summary>
            public byte[] HashPrefix { get; } = hashPrefix;

            /// <summary>The User ID text; <c>null</c> for a User Attribute.</summary>
            public string? Text { get; } = text;

            public SignatureSet Signatures { get; } = new();
        }

        /// <summary>A subkey with its verified binding signatures (each with its verified back-signatures) and revocations.</summary>
        private sealed class Subkey
        {
            private readonly byte[] _bindingContent;
            private readonly List<(SignaturePacket Binding, List<SignaturePacket> BackSignatures)> _bindings = [];
            private readonly List<SignaturePacket> _revocations = [];
            private int _unverifiableSignatures;

            private Subkey(PublicKeyPacket key, byte[] bindingContent)
            {
                Key = key;
                _bindingContent = bindingContent;
            }

            public PublicKeyPacket Key { get; }

            /// <summary>The subkey, or <c>null</c> if it can't be parsed or doesn't match its primary's version - it is then simply unusable, like any subkey of an unknown algorithm.</summary>
            public static Subkey? TryCreate(PublicKeyPacket primary, byte[] body)
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

                if (key.Version != primary.Version)
                {
                    return null; // RFC 9580 §10.1: every subkey has its primary key's version
                }

                // Subkey binding and revocation signatures hash the primary key, then the subkey,
                // each with the same key framing (RFC 9580 §5.2.4).
                byte[] content = Concat(KeyHashPrefix.Build(primary.Version, primary.Body), KeyHashPrefix.Build(key.Version, key.Body));
                return new Subkey(key, content);
            }

            /// <summary>Checks a subkey binding or revocation signature against this subkey, keeping it if it verifies. The caller deals with an uncheckable one.</summary>
            public KeySignatureCheck AddSignature(PublicKeyPacket primary, SignaturePacket signature)
            {
                KeySignatureCheck check = SignatureVerifier.CheckKeySignature(primary, signature, _bindingContent);
                if (check != KeySignatureCheck.Valid)
                {
                    return check;
                }

                if (signature.SignatureTypeRaw == (byte)SignatureType.SubkeyRevocation)
                {
                    _revocations.Add(signature);
                }
                else
                {
                    // The back-signature is made by the subkey over the same content, proving the
                    // subkey's owner agreed to be bound (RFC 9580 §5.2.1.6).
                    List<SignaturePacket> backSignatures = signature.EmbeddedSignatures
                        .Where(s => s.SignatureTypeRaw == (byte)SignatureType.PrimaryKeyBinding)
                        .Where(s => SignatureVerifier.CheckKeySignature(Key, s, _bindingContent) == KeySignatureCheck.Valid)
                        .ToList();
                    _bindings.Add((signature, backSignatures));
                }

                return check;
            }

            public bool IsRevoked => _revocations.Count > 0;

            /// <summary>Records a binding or revocation that may concern this subkey but can't be checked or parsed (see <see cref="Certificate.Build"/>).</summary>
            public void MarkUnverifiable() => _unverifiableSignatures++;

            /// <summary>Takes another copy of this subkey's verified bindings and revocations (see <see cref="Certificate.MergeFrom"/>).</summary>
            public void MergeFrom(Subkey other)
            {
                _bindings.AddRange(other._bindings);
                _revocations.AddRange(other._revocations);
                _unverifiableSignatures += other._unverifiableSignatures;
            }

            /// <summary>The newest binding signature that is valid at <paramref name="now"/> - the one that describes the subkey.</summary>
            public SignaturePacket? LatestBinding(DateTimeOffset now) => Latest(CurrentBindings(now));

            private IEnumerable<SignaturePacket> CurrentBindings(DateTimeOffset now) => _bindings.Select(b => b.Binding).Where(b => IsCurrent(b, Key, now));

            public (VerificationStatus Status, string Message) Check(DateTimeOffset signatureCreatedAt, DateTimeOffset now)
            {
                if (_unverifiableSignatures > 0)
                {
                    return (VerificationStatus.KeyNotValidForSigning, "The subkey has binding or revocation signatures whose hash or algorithm can't be checked, so its validity can't be determined.");
                }

                var revocation = CheckRevocations(_revocations, signatureCreatedAt, "signing subkey");
                if (revocation.Status != VerificationStatus.Valid)
                {
                    return revocation;
                }

                List<SignaturePacket> newest = NewestTied(CurrentBindings(now));
                SignaturePacket? latest = newest.FirstOrDefault();
                if (latest is null)
                {
                    return (VerificationStatus.KeyNotValidForSigning, "The subkey has no valid binding signature from its primary key.");
                }

                // A subkey may only sign data if its binding says so and carries a valid
                // back-signature (RFC 9580 §5.2.1.6, §10.1.3). Without the back-signature anyone
                // could "bind" someone else's signing key to their own certificate.
                byte[]? flags = latest.KeyFlags;
                if (flags is null || !HasSignFlag(flags))
                {
                    return (VerificationStatus.KeyNotValidForSigning, "The subkey's binding signature does not allow it to sign data.");
                }

                // Every binding tied for newest needs one, so packet order can't choose the one that has it.
                bool allBacked = newest.All(binding => _bindings
                    .Where(b => ReferenceEquals(b.Binding, binding))
                    .Any(b => b.BackSignatures.Any(s => IsCurrent(s, Key, now))));
                if (!allBacked)
                {
                    return (VerificationStatus.KeyNotValidForSigning, "The signing subkey has no valid primary-key binding (back-)signature.");
                }

                if (signatureCreatedAt < Key.CreatedAt)
                {
                    return (VerificationStatus.InvalidSignatureTime, "The signature predates the signing subkey.");
                }

                return CheckExpiration(latest, Key.CreatedAt, signatureCreatedAt, now, "signing subkey");
            }
        }
    }
}
