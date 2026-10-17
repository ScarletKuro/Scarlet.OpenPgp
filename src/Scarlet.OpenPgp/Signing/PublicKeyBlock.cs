using System;
using System.Collections.Generic;
using Scarlet.OpenPgp.Armor;
using Scarlet.OpenPgp.Internal;
using Scarlet.OpenPgp.Packets;

namespace Scarlet.OpenPgp.Signing
{
    /// <summary>
    /// The caller's trusted public key block, reduced to what verification needs: the primary key
    /// and, when its self-signatures declare one, the time the key expires.
    /// </summary>
    /// <remarks>
    /// A real key block is a "bag of packets": the primary Public-Key packet, then User ID packets
    /// each followed by certifications, then subkeys with their binding signatures. The key's
    /// expiration time lives in a self-signature (RFC 4880 §5.2.3.6), so it is only taken from
    /// signatures that actually verify against the primary key - a stray or forged signature in the
    /// block can't set or clear it. Signatures that don't parse, use an unsupported algorithm, or
    /// don't verify are simply not self-signatures as far as this reader is concerned, matching how
    /// RFC 4880 says an implementation should treat a signature it can't validate.
    /// </remarks>
    internal sealed class PublicKeyBlock
    {
        private PublicKeyBlock(PublicKeyPacket primaryKey, DateTimeOffset? expiresAt)
        {
            PrimaryKey = primaryKey;
            ExpiresAt = expiresAt;
        }

        public PublicKeyPacket PrimaryKey { get; }

        /// <summary>When the primary key expires, per its most recent valid self-signature; <c>null</c> if it never does.</summary>
        public DateTimeOffset? ExpiresAt { get; }

        public static PublicKeyBlock Parse(string publicKeyArmor, DateTimeOffset now)
        {
            AsciiArmorBlock block = AsciiArmorReader.Read(publicKeyArmor);
            if (!string.Equals(block.Label, "PUBLIC KEY BLOCK", StringComparison.Ordinal))
            {
                throw new FailClosedException("Expected a PUBLIC KEY BLOCK armor block, found \"" + block.Label + "\".");
            }

            List<Packet> packets = PacketReader.ReadAll(block.Body);
            int primaryIndex = packets.FindIndex(p => p.Header.Tag == PacketTag.PublicKey);
            if (primaryIndex < 0)
            {
                throw new FailClosedException("No Public-Key packet found in the public key armor block.");
            }

            byte[] primaryBody = packets[primaryIndex].Body;
            PublicKeyPacket primaryKey = PublicKeyPacket.Parse(primaryBody);
            byte[] keyPrefix = BuildKeyHashPrefix(primaryBody);

            SignaturePacket? latestSelfSignature = null;
            DateTimeOffset latestCreatedAt = DateTimeOffset.MinValue;
            byte[]? currentUserId = null;
            bool seenUserIdOrAttribute = false;

            // Stop at the next primary key: a concatenated second certificate is a different key.
            for (int i = primaryIndex + 1; i < packets.Count && packets[i].Header.Tag != PacketTag.PublicKey; i++)
            {
                Packet packet = packets[i];
                if (packet.Header.Tag == PacketTag.PublicSubkey)
                {
                    break; // subkey binding signatures don't describe the primary key's lifetime
                }

                if (packet.Header.Tag == PacketTag.UserId)
                {
                    currentUserId = packet.Body;
                    seenUserIdOrAttribute = true;
                    continue;
                }

                if (packet.Header.Tag == PacketTag.UserAttribute)
                {
                    currentUserId = null;
                    seenUserIdOrAttribute = true;
                    continue;
                }

                if (packet.Header.Tag != PacketTag.Signature)
                {
                    continue;
                }

                if (!TryVerifySelfSignature(primaryKey, keyPrefix, currentUserId, seenUserIdOrAttribute, packet.Body, now, out SignaturePacket? selfSignature, out DateTimeOffset createdAt))
                {
                    continue;
                }

                if (latestSelfSignature is null || createdAt >= latestCreatedAt)
                {
                    latestSelfSignature = selfSignature;
                    latestCreatedAt = createdAt;
                }
            }

            DateTimeOffset? expiresAt = null;
            if (latestSelfSignature is not null
                && latestSelfSignature.TryGetHashedTime(SignatureSubpacketType.KeyExpirationTime, out uint keyLifetimeSeconds)
                && keyLifetimeSeconds != 0)
            {
                expiresAt = primaryKey.CreatedAt.AddSeconds(keyLifetimeSeconds);
            }

            return new PublicKeyBlock(primaryKey, expiresAt);
        }

        private static bool TryVerifySelfSignature(
            PublicKeyPacket primaryKey,
            byte[] keyPrefix,
            byte[]? currentUserId,
            bool seenUserIdOrAttribute,
            byte[] signatureBody,
            DateTimeOffset now,
            out SignaturePacket? selfSignature,
            out DateTimeOffset createdAt)
        {
            selfSignature = null;
            createdAt = default;
            try
            {
                SignaturePacket signature = SignaturePacket.Parse(signatureBody);
                byte[] signedContent;
                if (signature.SignatureTypeRaw == (byte)SignatureType.DirectKey && !seenUserIdOrAttribute)
                {
                    signedContent = keyPrefix;
                }
                else if (signature.SignatureTypeRaw >= (byte)SignatureType.GenericCertification
                         && signature.SignatureTypeRaw <= (byte)SignatureType.PositiveCertification
                         && currentUserId is not null)
                {
                    signedContent = Concat(keyPrefix, BuildUserIdHashPrefix(currentUserId));
                }
                else
                {
                    return false;
                }

                createdAt = SignatureVerifier.GetCreationTime(signature);
                if (createdAt < primaryKey.CreatedAt || !SignatureVerifier.IsUnexpired(signature, now))
                {
                    return false;
                }

                if (!SignatureVerifier.VerifyCryptographic(primaryKey, signature, signedContent))
                {
                    return false;
                }

                selfSignature = signature;
                return true;
            }
            catch (FailClosedException)
            {
                return false;
            }
        }

        /// <summary>RFC 4880 §5.2.4: a key is hashed as 0x99, a 2-octet length, then the Public-Key packet body.</summary>
        private static byte[] BuildKeyHashPrefix(byte[] publicKeyPacketBody)
        {
            var prefix = new byte[3 + publicKeyPacketBody.Length];
            prefix[0] = 0x99;
            prefix[1] = (byte)(publicKeyPacketBody.Length >> 8);
            prefix[2] = (byte)publicKeyPacketBody.Length;
            Array.Copy(publicKeyPacketBody, 0, prefix, 3, publicKeyPacketBody.Length);
            return prefix;
        }

        /// <summary>RFC 4880 §5.2.4: a v4 certification hashes the User ID as 0xB4, a 4-octet length, then the User ID bytes.</summary>
        private static byte[] BuildUserIdHashPrefix(byte[] userId)
        {
            var prefix = new byte[5 + userId.Length];
            prefix[0] = 0xB4;
            prefix[1] = (byte)(userId.Length >> 24);
            prefix[2] = (byte)(userId.Length >> 16);
            prefix[3] = (byte)(userId.Length >> 8);
            prefix[4] = (byte)userId.Length;
            Array.Copy(userId, 0, prefix, 5, userId.Length);
            return prefix;
        }

        private static byte[] Concat(byte[] a, byte[] b)
        {
            var result = new byte[a.Length + b.Length];
            Array.Copy(a, 0, result, 0, a.Length);
            Array.Copy(b, 0, result, a.Length, b.Length);
            return result;
        }
    }
}
