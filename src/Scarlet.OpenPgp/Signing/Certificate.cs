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
    /// The cryptographic checks happen once, here; whether a key is valid *at a given time* - not
    /// expired, not revoked, still bound - depends on the clock and on the document signature's
    /// creation time, so that part is <see cref="CheckSigningKey"/>.
    /// </remarks>
    internal sealed class Certificate
    {
        private const byte SignDataFlag = 0x02;

        private readonly byte[] _primaryHashPrefix;
        private readonly List<SignaturePacket> _selfSignatures = [];
        private readonly List<SignaturePacket> _revocations = [];
        private readonly List<Subkey> _subkeys = [];
        private readonly List<string> _userIds = [];

        private Certificate(PublicKeyPacket primary)
        {
            Primary = primary;
            _primaryHashPrefix = KeyHashPrefix.Build(primary.Version, primary.Body);
        }

        public PublicKeyPacket Primary { get; }

        /// <summary>The primary key followed by every subkey, in order.</summary>
        public IEnumerable<PublicKeyPacket> Keys => new[] { Primary }.Concat(_subkeys.Select(s => s.Key));

        /// <summary>The User IDs carrying a valid self-certification, in certificate order.</summary>
        public IReadOnlyList<string> UserIds => _userIds;

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
        /// signature, for a subkey) as of <paramref name="now"/>; <c>null</c> if it never does or no
        /// valid self-signature says so.
        /// </summary>
        public DateTimeOffset? GetExpiration(PublicKeyPacket key, DateTimeOffset now)
        {
            try
            {
                SignaturePacket? selfSignature = ReferenceEquals(key, Primary)
                    ? LatestPrimarySelfSignature(now)
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
            byte[]? userIdPrefix = null;
            string? userId = null;
            Subkey? currentSubkey = null;
            bool inSubkeySection = false;

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

                        userIdPrefix = BuildUserIdHashPrefix(packet.Header.Tag, packet.Body);

                        // User IDs are UTF-8 by convention (RFC 9580 §5.11); invalid bytes become U+FFFD,
                        // which is fine for a display-only value. User Attributes (photos) have no text.
                        userId = packet.Header.Tag == PacketTag.UserId ? System.Text.Encoding.UTF8.GetString(packet.Body) : null;
                        break;

                    case PacketTag.PublicSubkey:
                        inSubkeySection = true;
                        currentSubkey = Subkey.TryCreate(certificate.Primary, packet.Body);
                        if (currentSubkey is not null)
                        {
                            certificate._subkeys.Add(currentSubkey);
                        }

                        break;

                    case PacketTag.Signature:
                        SignaturePacket? signature = TryParseSignature(packet.Body);
                        if (signature is null)
                        {
                            break; // an unparseable signature can't say anything about the key
                        }

                        if (inSubkeySection)
                        {
                            currentSubkey?.AddSignature(certificate, signature);
                        }
                        else if (userIdPrefix is not null) // in the User ID section
                        {
                            certificate.AddUserIdSignature(signature, userIdPrefix, userId);
                        }
                        else
                        {
                            certificate.AddDirectSignature(signature);
                        }

                        break;

                    case PacketTag.Trust:
                    case PacketTag.Marker:
                    case PacketTag.Padding:
                        break;

                    default:
                        throw new FailClosedException("Unexpected packet (tag " + packet.Header.RawTag + ") in a public key block.");
                }
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
                return (VerificationStatus.KeyNotValidForSigning, "The certificate's self-signatures are malformed: " + ex.Message);
            }
        }

        private (VerificationStatus Status, string Message) CheckPrimary(DateTimeOffset signatureCreatedAt, DateTimeOffset now, out SignaturePacket? latestSelfSignature)
        {
            latestSelfSignature = null;
            var revocation = CheckRevocations(_revocations, signatureCreatedAt, "primary key");
            if (revocation.Status != VerificationStatus.Valid)
            {
                return revocation;
            }

            latestSelfSignature = LatestPrimarySelfSignature(now);
            if (Primary.Version == 6 && latestSelfSignature is null)
            {
                return (VerificationStatus.KeyNotValidForSigning, "The v6 primary key has no valid Direct Key self-signature.");
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
            IEnumerable<SignaturePacket> candidates = _selfSignatures.Where(s => IsCurrent(s, Primary, now));
            if (Primary.Version == 6)
            {
                candidates = candidates.Where(s => s.SignatureTypeRaw == (byte)SignatureType.DirectKey);
            }

            return Latest(candidates);
        }

        private void AddDirectSignature(SignaturePacket signature)
        {
            switch ((SignatureType)signature.SignatureTypeRaw)
            {
                case SignatureType.DirectKey:
                    if (IsValidKeySignature(Primary, signature, _primaryHashPrefix))
                    {
                        _selfSignatures.Add(signature);
                    }

                    break;

                case SignatureType.KeyRevocation:
                    if (IsValidKeySignature(Primary, signature, _primaryHashPrefix))
                    {
                        _revocations.Add(signature);
                    }

                    break;
            }
        }

        private void AddUserIdSignature(SignaturePacket signature, byte[] userIdPrefix, string? userId)
        {
            if (signature.SignatureTypeRaw < (byte)SignatureType.GenericCertification
                || signature.SignatureTypeRaw > (byte)SignatureType.PositiveCertification)
            {
                return; // certification revocations etc. don't affect whether the key can sign
            }

            if (IsValidKeySignature(Primary, signature, Concat(_primaryHashPrefix, userIdPrefix)))
            {
                _selfSignatures.Add(signature);
                if (userId is not null && !_userIds.Contains(userId))
                {
                    _userIds.Add(userId);
                }
            }
        }

        /// <summary>
        /// Whether <paramref name="signature"/> is a well-formed signature by <paramref name="issuer"/>
        /// over <paramref name="signedContent"/>. Signatures naming a different issuer (third-party
        /// certifications) are skipped without the cost of a verification.
        /// </summary>
        internal static bool IsValidKeySignature(PublicKeyPacket issuer, SignaturePacket signature, byte[] signedContent)
        {
            try
            {
                if (!IsIssuedBy(signature, issuer) || SignatureVerifier.GetIncompatibility(issuer, signature) is not null)
                {
                    return false;
                }

                SignatureVerifier.GetCreationTime(signature); // throws if missing or malformed
                byte[] digest = SignatureHashBuilder.ComputeDigest(signedContent, signature, isKeySignature: true);
                return SignatureVerifier.VerifyDigest(issuer, signature, digest);
            }
            catch (FailClosedException)
            {
                return false;
            }
        }

        /// <summary>
        /// Whether the signature's issuer hints (fingerprints first, then key IDs) allow
        /// <paramref name="key"/> to be its issuer. A signature with no hints at all could be from
        /// any key. The hints may be unauthenticated; they only ever narrow the search.
        /// </summary>
        internal static bool IsIssuedBy(SignaturePacket signature, PublicKeyPacket key)
        {
            List<byte[]> fingerprints = signature.IssuerFingerprints.ToList();
            if (fingerprints.Count > 0)
            {
                return fingerprints.Any(key.Fingerprint.Matches);
            }

            List<byte[]> keyIds = signature.IssuerKeyIds.ToList();
            if (keyIds.Count > 0)
            {
                return keyIds.Any(key.Fingerprint.MatchesKeyId);
            }

            return true;
        }

        /// <summary>A self-signature counts at <paramref name="now"/> if it was made no earlier than its key and no later than now, and hasn't expired.</summary>
        private static bool IsCurrent(SignaturePacket signature, PublicKeyPacket key, DateTimeOffset now)
        {
            DateTimeOffset createdAt = SignatureVerifier.GetCreationTime(signature);
            return createdAt >= key.CreatedAt && createdAt <= now && SignatureVerifier.IsUnexpired(signature, now);
        }

        private static SignaturePacket? Latest(IEnumerable<SignaturePacket> signatures)
        {
            SignaturePacket? latest = null;
            DateTimeOffset latestCreatedAt = DateTimeOffset.MinValue;
            foreach (SignaturePacket signature in signatures)
            {
                DateTimeOffset createdAt = SignatureVerifier.GetCreationTime(signature);
                if (latest is null || createdAt >= latestCreatedAt)
                {
                    latest = signature;
                    latestCreatedAt = createdAt;
                }
            }

            return latest;
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

        /// <summary>A subkey with its verified binding signatures (each with its verified back-signatures) and revocations.</summary>
        private sealed class Subkey
        {
            private readonly byte[] _bindingContent;
            private readonly List<(SignaturePacket Binding, List<SignaturePacket> BackSignatures)> _bindings = [];
            private readonly List<SignaturePacket> _revocations = [];

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

            public void AddSignature(Certificate certificate, SignaturePacket signature)
            {
                switch ((SignatureType)signature.SignatureTypeRaw)
                {
                    case SignatureType.SubkeyBinding:
                        if (IsValidKeySignature(certificate.Primary, signature, _bindingContent))
                        {
                            // The back-signature is made by the subkey over the same content, proving
                            // the subkey's owner agreed to be bound (RFC 9580 §5.2.1.6).
                            List<SignaturePacket> backSignatures = signature.EmbeddedSignatures
                                .Where(s => s.SignatureTypeRaw == (byte)SignatureType.PrimaryKeyBinding)
                                .Where(s => IsValidKeySignature(Key, s, _bindingContent))
                                .ToList();
                            _bindings.Add((signature, backSignatures));
                        }

                        break;

                    case SignatureType.SubkeyRevocation:
                        if (IsValidKeySignature(certificate.Primary, signature, _bindingContent))
                        {
                            _revocations.Add(signature);
                        }

                        break;
                }
            }

            public bool IsRevoked => _revocations.Count > 0;

            /// <summary>The newest binding signature that is valid at <paramref name="now"/> - the one that describes the subkey.</summary>
            public SignaturePacket? LatestBinding(DateTimeOffset now) => Latest(_bindings.Select(b => b.Binding).Where(b => IsCurrent(b, Key, now)));

            public (VerificationStatus Status, string Message) Check(DateTimeOffset signatureCreatedAt, DateTimeOffset now)
            {
                var revocation = CheckRevocations(_revocations, signatureCreatedAt, "signing subkey");
                if (revocation.Status != VerificationStatus.Valid)
                {
                    return revocation;
                }

                SignaturePacket? latest = LatestBinding(now);
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

                List<SignaturePacket> backSignatures = _bindings.First(b => ReferenceEquals(b.Binding, latest)).BackSignatures;
                if (!backSignatures.Any(s => IsCurrent(s, Key, now)))
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
