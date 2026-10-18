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
        /// <summary>The most packets one certificate may have. Real ones have tens; a key flooded with signatures (CVE-2019-13050) has hundreds of thousands.</summary>
        public const int MaxCertificatePackets = 16384;

        /// <summary>The most certificates (Public-Key packets) one key input may hold - far more than any set of keys one trusts.</summary>
        public const int MaxCertificates = 16384;

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
        /// keys or messages, and a certificate over the size limits - fails the whole input: silently
        /// dropping one certificate could drop the copy that carries a revocation and leave a stale
        /// copy in charge. Input with no usable certificate fails too.
        /// </summary>
        /// <remarks>Packets are read and certificates built one at a time, so only one certificate's packets are ever held at once.</remarks>
        public static KeyRing Parse(byte[] packetBytes)
        {
            var certificates = new List<Certificate>();
            string? lastError = null;
            int certificateCount = 0;
            List<Packet>? current = null;

            foreach (Packet packet in PacketReader.Enumerate(packetBytes))
            {
                if (packet.Header.Tag == PacketTag.PublicKey)
                {
                    if (current is not null)
                    {
                        Add(current);
                    }

                    if (++certificateCount > MaxCertificates)
                    {
                        throw new FailClosedException("The public key input holds more than " + MaxCertificates + " certificates.");
                    }

                    current = [packet];
                    continue;
                }

                if (current is null)
                {
                    throw new FailClosedException("Public key input does not start with a Public-Key packet (found tag " + packet.Header.RawTag + ").");
                }

                if (current.Count == MaxCertificatePackets)
                {
                    throw new FailClosedException("A certificate has more than " + MaxCertificatePackets + " packets; it is too large or flooded with signatures.");
                }

                current.Add(packet);
            }

            if (current is not null)
            {
                Add(current);
            }

            if (certificates.Count == 0)
            {
                throw new FailClosedException(lastError ?? "No Public-Key packet found in the public key input.");
            }

            return new KeyRing(certificates);

            void Add(List<Packet> packets)
            {
                Certificate certificate;
                try
                {
                    certificate = CertificateBuilder.Build(packets);
                }
                catch (FailClosedException ex) when (ex.IsUnsupported)
                {
                    lastError = ex.Message;
                    return;
                }

                // Several copies of one certificate (an old and a new export, say) become one, so a
                // stale copy without a revocation can't be picked instead of the revoked one.
                int existing = certificates.FindIndex(c => c.Primary.Fingerprint.Matches(certificate.Primary.Fingerprint.Bytes));
                if (existing < 0)
                {
                    certificates.Add(certificate);
                }
                else
                {
                    certificates[existing] = Certificate.Merge(certificates[existing], certificate);
                }
            }
        }
    }
}
