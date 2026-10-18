using System.Collections.Generic;
using System.Security.Cryptography;
using Scarlet.OpenPgp.Internal;
using Scarlet.OpenPgp.Packets;

namespace Scarlet.OpenPgp.Verification
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
        /// <remarks>
        /// Packets are read one certificate copy at a time, so only one copy's packets are held at
        /// once. All copies of a certificate feed one <see cref="CertificateBuilder"/>, which matches
        /// their signatures against every copy's User IDs and subkeys: a revocation in one copy
        /// applies to the subkey from another. Building each copy on its own and merging afterwards
        /// let a repeated Public-Key packet cut a revocation off from its subkey.
        /// </remarks>
        public static KeyRing Parse(byte[] packetBytes)
        {
            // One builder per certificate, by primary fingerprint in first-seen order, and the
            // digests of copies already read, so an exact repeat costs a hash rather than a pass.
            var builders = new Dictionary<byte[], CertificateBuilder>(ByteArrayComparer.Instance);
            var order = new List<CertificateBuilder>();
            var seenCopies = new HashSet<byte[]>(ByteArrayComparer.Instance);
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

            if (order.Count == 0)
            {
                throw new FailClosedException(lastError ?? "No Public-Key packet found in the public key input.");
            }

            // Several copies of one certificate (an old and a new export, say) become one, so a stale
            // copy without a revocation can't be picked instead of the revoked one.
            var certificates = new List<Certificate>(order.Count);
            foreach (CertificateBuilder builder in order)
            {
                certificates.Add(builder.Build());
            }

            return new KeyRing(certificates);

            void Add(List<Packet> packets)
            {
                if (!seenCopies.Add(Digest(packets)))
                {
                    return; // an exact repeat of a copy already read says nothing new
                }

                try
                {
                    var primary = PublicKeyPacket.Parse(packets[0].Body);
                    if (!builders.TryGetValue(primary.Fingerprint.Bytes, out CertificateBuilder? builder))
                    {
                        builder = CertificateBuilder.Create(primary);
                        builders.Add(primary.Fingerprint.Bytes, builder);
                        order.Add(builder);
                    }

                    builder.AddCopy(packets);
                }
                catch (FailClosedException ex) when (ex.IsUnsupported)
                {
                    lastError = ex.Message;
                }
            }
        }

        /// <summary>A digest identifying a certificate copy by its exact packets (tag, length and body of each).</summary>
        private static byte[] Digest(List<Packet> packets)
        {
            using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
            var header = new byte[5];
            foreach (Packet packet in packets)
            {
                header[0] = packet.Header.RawTag;
                header[1] = (byte)(packet.Body.Length >> 24);
                header[2] = (byte)(packet.Body.Length >> 16);
                header[3] = (byte)(packet.Body.Length >> 8);
                header[4] = (byte)packet.Body.Length;
                hash.AppendData(header);
                hash.AppendData(packet.Body);
            }

            return hash.GetHashAndReset();
        }
    }
}
