using System.Collections.Generic;
using Scarlet.OpenPgp.Internal;
using Scarlet.OpenPgp.Packets;

namespace Scarlet.OpenPgp.Signing
{
    /// <summary>
    /// The caller's trusted keys: one or more certificates, as found in a key file or keyring
    /// export (several certificates simply follow one another, RFC 9580 §10.1).
    /// </summary>
    internal sealed class KeyRing
    {
        private KeyRing(List<Certificate> certificates)
        {
            Certificates = certificates;
        }

        public IReadOnlyList<Certificate> Certificates { get; }

        /// <summary>
        /// Splits <paramref name="packetBytes"/> into certificates, merging copies of the same
        /// certificate. A well-formed certificate this library doesn't support (a LibrePGP v5 key, a
        /// 1024-bit RSA key) is skipped, since it can't make a verifiable signature. Anything
        /// malformed - including packets that don't belong in a public key block, such as secret
        /// keys or messages - fails the whole input: silently dropping one certificate could drop
        /// the copy that carries a revocation and leave a stale copy in charge. Input with no usable
        /// certificate fails too.
        /// </summary>
        public static KeyRing Parse(byte[] packetBytes)
        {
            List<Packet> packets = PacketReader.ReadAll(packetBytes);
            var certificates = new List<Certificate>();
            string? lastError = null;

            int i = 0;
            while (i < packets.Count && packets[i].Header.Tag != PacketTag.PublicKey)
            {
                if (!IsIgnorable(packets[i].Header.Tag))
                {
                    throw new FailClosedException("Public key input does not start with a Public-Key packet (found tag " + packets[i].Header.RawTag + ").");
                }

                i++;
            }

            while (i < packets.Count)
            {
                int end = i + 1;
                while (end < packets.Count && packets[end].Header.Tag != PacketTag.PublicKey)
                {
                    end++;
                }

                try
                {
                    Certificate certificate = Certificate.Build(packets, i, end);

                    // Several copies of one certificate (an old and a new export, say) become one, so
                    // a stale copy without a revocation can't be picked instead of the revoked one.
                    Certificate? existing = certificates.Find(c => c.Primary.Fingerprint.Matches(certificate.Primary.Fingerprint.Bytes));
                    if (existing is null)
                    {
                        certificates.Add(certificate);
                    }
                    else
                    {
                        existing.MergeFrom(certificate);
                    }
                }
                catch (FailClosedException ex) when (ex.IsUnsupported)
                {
                    lastError = ex.Message;
                }

                i = end;
            }

            if (certificates.Count == 0)
            {
                throw new FailClosedException(lastError ?? "No Public-Key packet found in the public key input.");
            }

            return new KeyRing(certificates);
        }

        private static bool IsIgnorable(PacketTag tag) => tag == PacketTag.Marker || tag == PacketTag.Trust || tag == PacketTag.Padding;
    }
}
