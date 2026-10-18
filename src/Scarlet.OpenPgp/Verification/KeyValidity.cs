using System;
using System.Collections.Generic;
using System.Linq;
using Scarlet.OpenPgp.Internal;
using Scarlet.OpenPgp.Packets;

namespace Scarlet.OpenPgp.Verification
{
    /// <summary>
    /// What a verified <see cref="Certificate"/> means at a given time: whether one of its keys may
    /// have made a signature (not revoked, not expired, bound, allowed to sign), and when it expires.
    /// Every rule that depends on the clock or on a signature's creation time lives here.
    /// </summary>
    internal static class KeyValidity
    {
        private const byte SignDataFlag = 0x02;

        /// <summary>
        /// Whether <paramref name="signingKey"/> (the certificate's primary key or one of its
        /// subkeys) may have made a data signature created at <paramref name="signatureCreatedAt"/>,
        /// judged at <paramref name="now"/>. Returns <see cref="VerificationStatus.Valid"/> or the
        /// reason it may not, with an explanation.
        /// </summary>
        public static (VerificationStatus Status, string Message) CheckSigningKey(Certificate certificate, PublicKeyPacket signingKey, DateTimeOffset signatureCreatedAt, DateTimeOffset now)
        {
            try
            {
                var primaryCheck = CheckPrimary(certificate, signatureCreatedAt, now, out SignaturePacket? primarySelfSignature);
                if (primaryCheck.Status != VerificationStatus.Valid)
                {
                    return primaryCheck;
                }

                if (ReferenceEquals(signingKey, certificate.Primary))
                {
                    byte[]? flags = primarySelfSignature?.KeyFlags;
                    if (flags is not null && !HasSignFlag(flags))
                    {
                        return (VerificationStatus.KeyNotValidForSigning, "The primary key's self-signature does not allow it to sign data.");
                    }

                    return (VerificationStatus.Valid, "Valid.");
                }

                CertifiedSubkey? subkey = certificate.FindSubkey(signingKey);
                if (subkey is null)
                {
                    return (VerificationStatus.NoMatchingKey, "The signing key is not part of this certificate.");
                }

                return CheckSubkey(subkey, signatureCreatedAt, now);
            }
            catch (FailClosedException ex)
            {
                return (VerificationStatus.KeyNotValidForSigning, "The certificate's self-signatures can't be used: " + ex.Message);
            }
        }

        /// <summary>
        /// When <paramref name="key"/> expires according to its self-signature (binding signature,
        /// for a subkey) in effect at <paramref name="now"/> - or, if none is, its newest one at all.
        /// <c>null</c> when that sets no expiration, or when it can't be determined (ambiguous or
        /// malformed self-signatures; <see cref="CheckSigningKey"/> reports why).
        /// </summary>
        public static DateTimeOffset? GetExpiration(Certificate certificate, PublicKeyPacket key, DateTimeOffset now)
        {
            try
            {
                SignaturePacket? selfSignature;
                if (ReferenceEquals(key, certificate.Primary))
                {
                    selfSignature = LatestPrimarySelfSignature(certificate, now) ?? Latest(certificate.SelfSignatures);
                }
                else
                {
                    CertifiedSubkey? subkey = certificate.FindSubkey(key);
                    selfSignature = subkey is null ? null : Latest(CurrentBindings(subkey, now)) ?? Latest(subkey.Bindings.Select(b => b.Signature));
                }

                return ExpirationOf(selfSignature, key.CreatedAt);
            }
            catch (FailClosedException)
            {
                return null;
            }
        }

        private static (VerificationStatus Status, string Message) CheckPrimary(Certificate certificate, DateTimeOffset signatureCreatedAt, DateTimeOffset now, out SignaturePacket? latestSelfSignature)
        {
            latestSelfSignature = null;
            PublicKeyPacket primary = certificate.Primary;

            // A self-signature or revocation the key appears to have made, but whose hash or
            // algorithm can't be checked, could be genuine - a revocation, an expiration, a
            // restriction. Ignoring it could widen what the key may do, so the key isn't usable.
            if (certificate.UnverifiableSignatures > 0)
            {
                return (VerificationStatus.KeyNotValidForSigning, "The certificate has self-signatures or revocations whose hash or algorithm can't be checked, so the primary key's validity can't be determined.");
            }

            var revocation = CheckRevocations(certificate.Revocations, signatureCreatedAt, "primary key");
            if (revocation.Status != VerificationStatus.Valid)
            {
                return revocation;
            }

            latestSelfSignature = LatestPrimarySelfSignature(certificate, now);
            if (primary.Version == 6 && latestSelfSignature is null)
            {
                return (VerificationStatus.KeyNotValidForSigning, "The v6 primary key has no valid, unrevoked Direct Key self-signature.");
            }

            // Only a v4 key that never had a self-signature counts as a bare, unrestricted key. If it
            // has self-signatures but none is valid now (all expired or revoked, say), the
            // restrictions and the expiration they carried must not silently disappear - the key is
            // simply not usable.
            if (latestSelfSignature is null && certificate.HasSelfSignatures)
            {
                return (VerificationStatus.KeyNotValidForSigning, "None of the primary key's self-signatures is currently valid (they have expired or been revoked).");
            }

            if (signatureCreatedAt < primary.CreatedAt)
            {
                return (VerificationStatus.InvalidSignatureTime, "The signature predates the primary key.");
            }

            return CheckExpiration(latestSelfSignature, primary.CreatedAt, signatureCreatedAt, now, "primary key");
        }

        /// <summary>
        /// The self-signature that describes the primary key at <paramref name="now"/>. RFC 9580
        /// §5.2.3.10: the most recent valid self-signature wins. For a v6 key that must be a Direct Key
        /// signature, and one must exist (§5.2.3.10, §10.1.1) - otherwise an attacker could strip it to
        /// drop an expiration. A v4 key may carry its information on a User ID self-signature instead,
        /// and a bare v4 key with no self-signature at all has no flags and no expiration.
        /// </summary>
        private static SignaturePacket? LatestPrimarySelfSignature(Certificate certificate, DateTimeOffset now)
        {
            var candidates = new List<SignaturePacket>();
            foreach (SignaturePacket selfSignature in certificate.SelfSignatures)
            {
                bool rightType = certificate.Primary.Version != 6 || selfSignature.SignatureTypeRaw == (byte)SignatureType.DirectKey;
                if (rightType && IsCurrent(selfSignature, certificate.Primary, now))
                {
                    candidates.Add(selfSignature);
                }
            }

            return Latest(candidates);
        }

        private static (VerificationStatus Status, string Message) CheckSubkey(CertifiedSubkey subkey, DateTimeOffset signatureCreatedAt, DateTimeOffset now)
        {
            if (subkey.UnverifiableSignatures > 0)
            {
                return (VerificationStatus.KeyNotValidForSigning, "The subkey has binding or revocation signatures whose hash or algorithm can't be checked, so its validity can't be determined.");
            }

            var revocation = CheckRevocations(subkey.Revocations, signatureCreatedAt, "signing subkey");
            if (revocation.Status != VerificationStatus.Valid)
            {
                return revocation;
            }

            List<SignaturePacket> newest = NewestTied(CurrentBindings(subkey, now));
            SignaturePacket? latest = newest.FirstOrDefault();
            if (latest is null)
            {
                return (VerificationStatus.KeyNotValidForSigning, "The subkey has no valid binding signature from its primary key.");
            }

            // A subkey may only sign data if its binding says so and carries a valid back-signature
            // (RFC 9580 §5.2.1.6, §10.1.3). Without the back-signature anyone could "bind" someone
            // else's signing key to their own certificate.
            byte[]? flags = latest.KeyFlags;
            if (flags is null || !HasSignFlag(flags))
            {
                return (VerificationStatus.KeyNotValidForSigning, "The subkey's binding signature does not allow it to sign data.");
            }

            // Every binding tied for newest needs one, so packet order can't choose the one that has it.
            bool allBacked = newest.All(binding => subkey.Bindings
                .Where(b => ReferenceEquals(b.Signature, binding))
                .Any(b => b.BackSignatures.Any(s => IsCurrent(s, subkey.Key, now))));
            if (!allBacked)
            {
                return (VerificationStatus.KeyNotValidForSigning, "The signing subkey has no valid primary-key binding (back-)signature.");
            }

            if (signatureCreatedAt < subkey.Key.CreatedAt)
            {
                return (VerificationStatus.InvalidSignatureTime, "The signature predates the signing subkey.");
            }

            return CheckExpiration(latest, subkey.Key.CreatedAt, signatureCreatedAt, now, "signing subkey");
        }

        /// <summary>The bindings in effect at <paramref name="now"/>. Materialized here, so the parsing <see cref="IsCurrent"/> does (and may fail closed on) happens in this call, not wherever the result is first enumerated.</summary>
        private static List<SignaturePacket> CurrentBindings(CertifiedSubkey subkey, DateTimeOffset now)
        {
            var current = new List<SignaturePacket>();
            foreach (SubkeyBinding binding in subkey.Bindings)
            {
                if (IsCurrent(binding.Signature, subkey.Key, now))
                {
                    current.Add(binding.Signature);
                }
            }

            return current;
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
        private static (VerificationStatus Status, string Message) CheckRevocations(IReadOnlyList<SignaturePacket> revocations, DateTimeOffset signatureCreatedAt, string what)
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
            if (ExpirationOf(selfSignature, keyCreatedAt) is { } expiresAt)
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
    }
}
