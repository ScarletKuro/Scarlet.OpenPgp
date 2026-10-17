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
        /// Splits <paramref name="packetBytes"/> into certificates. A certificate whose primary key
        /// is malformed or of an unknown version is skipped (the others stay usable); input with no
        /// usable certificate, or with packets that don't belong in a public key block (such as
        /// secret keys or messages), fails closed.
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
                catch (FailClosedException ex)
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
