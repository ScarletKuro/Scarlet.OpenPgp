using System;
using System.Collections.Generic;
using Scarlet.OpenPgp.Internal;
using Scarlet.OpenPgp.Packets;

namespace Scarlet.OpenPgp.Verification
{
    /// <summary>
    /// Verifies one or more document signatures over content that is streamed in once. Phases:
    /// <see cref="Start"/> parses the signatures and keys and opens one digest per signature;
    /// <see cref="Update"/> feeds content to every digest; <see cref="Complete"/> checks each
    /// signature against each key that may have made it and reports the first valid one.
    /// </summary>
    /// <remarks>
    /// The verdict is "valid" if any signature is valid by any supplied key - the same question
    /// "did someone I trust sign this?" that a single signature answers. Signatures by keys the
    /// caller didn't supply are ignored. When nothing verifies, the most informative failure is
    /// reported (e.g. "key expired" beats "no matching key" from another signature).
    /// </remarks>
    internal sealed class DocumentVerification : IDisposable
    {
        /// <summary>The most distinct signatures one input may carry. Real files have one to a handful (Debian's Release has three); the limit only exists to bound the hashing work.</summary>
        public const int MaxSignatures = 32;

        /// <summary>The most signature packets one input may carry, counting identical copies of the same signature.</summary>
        public const int MaxSignaturePackets = 8 * MaxSignatures;

        /// <summary>
        /// The most checking work (in <see cref="Crypto.VerificationKey.CheckCost"/> units, about 0.3 ms
        /// each) the signatures of one input may call for, summed over every key each could be from.
        /// A signature that names its issuer has one or two candidate keys; one that names none could
        /// be from any key in the ring, and 32 of them against a large keyring meant tens of thousands
        /// of checks. Room for <see cref="MaxSignatures"/> signatures by one key of the costliest kind
        /// (brainpoolP512r1, 48 units), so only signatures naming no issuer can reach it.
        /// </summary>
        public const int MaxCheckCost = 2048;

        private readonly List<Entry> _entries;
        private readonly VerificationResult? _earlyResult;

        private DocumentVerification(List<Entry> entries, VerificationResult? earlyResult)
        {
            _entries = entries;
            _earlyResult = earlyResult;
        }

        /// <param name="signaturePackets">The raw signature packets (already de-armored).</param>
        /// <param name="keyRing">The caller's trusted keys.</param>
        /// <param name="isClearsign">
        /// The content is a clearsigned message's canonical text: signatures must be text signatures
        /// (type 0x01), and the content is already canonical so it's hashed as-is. Otherwise both
        /// binary and text signatures are accepted, and text signatures get their line endings
        /// canonicalized while hashing.
        /// </param>
        public static DocumentVerification Start(byte[] signaturePackets, KeyRing keyRing, bool isClearsign)
        {
            var bodies = new List<byte[]>();
            int packetCount = 0;
            try
            {
                // Read lazily and stop at the first reason to reject: reading every packet before
                // looking let a 1 MiB input of tiny packets allocate 69 MiB of packet objects.
                foreach (Packet packet in PacketReader.Enumerate(signaturePackets))
                {
                    if (packet.Header.Tag != PacketTag.Signature)
                    {
                        // A detached signature or clearsign signature block holds signatures only;
                        // anything else means this isn't what the caller thinks it is.
                        return Failed(VerificationStatus.MalformedInput, "The signature input contains a non-signature packet (tag " + packet.Header.RawTag + ").");
                    }

                    // Each signature costs a full pass over the data, so the count bounds the work a
                    // hostile signature file can cause (256 copies made an 8 MiB file cost 2 GiB of
                    // hashing). Checked as each one arrives, so no packet is ever compared against more
                    // than MaxSignatures others - checking afterwards made 64,000 distinct packets
                    // quadratic (8 s just to reject). Identical copies count too: they cost no
                    // hashing, but each is still a packet to read and compare.
                    if (++packetCount > MaxSignaturePackets)
                    {
                        return Failed(VerificationStatus.MalformedInput, "The signature input contains more than " + MaxSignaturePackets + " signature packets.");
                    }

                    // An identical copy adds nothing but another pass over the data.
                    if (bodies.Exists(b => b.AsSpan().SequenceEqual(packet.Body)))
                    {
                        continue;
                    }

                    if (bodies.Count == MaxSignatures)
                    {
                        return Failed(VerificationStatus.MalformedInput, "The signature input contains more than " + MaxSignatures + " signatures.");
                    }

                    bodies.Add(packet.Body);
                }
            }
            catch (FailClosedException ex)
            {
                return Failed(VerificationStatus.MalformedInput, "The signature is malformed: " + ex.Message);
            }

            if (bodies.Count == 0)
            {
                return Failed(VerificationStatus.MalformedInput, "The signature input contains no signature.");
            }

            var entries = new List<Entry>(bodies.Count);
            foreach (byte[] body in bodies)
            {
                entries.Add(Entry.Create(body, keyRing, isClearsign));
            }

            long checkCost = 0;
            foreach (Entry entry in entries)
            {
                checkCost += entry.CandidateCost;
            }

            if (checkCost > MaxCheckCost)
            {
                foreach (Entry entry in entries)
                {
                    entry.Dispose();
                }

                return Failed(VerificationStatus.MalformedInput, "The signatures don't name their issuer, and too many of the supplied keys could have made them to check them all.");
            }

            return new DocumentVerification(entries, null);
        }

        public static DocumentVerification Failed(VerificationStatus status, string message)
        {
            return new DocumentVerification([], new VerificationResult(status, message));
        }

        /// <summary>Whether the outcome is already known without reading any content (every signature failed before hashing, or the input was unusable).</summary>
        public bool NeedsContent => _earlyResult is null && _entries.Exists(e => e.Digest is not null);

        public void Update(byte[] buffer, int offset, int count)
        {
            foreach (Entry entry in _entries)
            {
                entry.Digest?.Update(buffer, offset, count);
            }
        }

        public VerificationResult Complete(DateTimeOffset now, string? signedText)
        {
            if (_earlyResult is not null)
            {
                return _earlyResult;
            }

            VerificationResult? best = null;
            foreach (Entry entry in _entries)
            {
                VerificationResult result = entry.Evaluate(now, signedText);
                if (result.IsValid)
                {
                    return result;
                }

                if (best is null || Rank(result.Status) > Rank(best.Status))
                {
                    best = result;
                }
            }

            // Start rejects input without a signature, so there is always one; if that ever changed,
            // the answer must still be a failure, never null.
            return best ?? Failure(VerificationStatus.MalformedInput, "The signature input contains no signature.");
        }

        public void Dispose()
        {
            foreach (Entry entry in _entries)
            {
                entry.Dispose();
            }
        }

        /// <summary>How much a failure tells the caller: one that got as far as a matching key and a good signature beats one that didn't.</summary>
        private static int Rank(VerificationStatus status)
        {
            switch (status)
            {
                case VerificationStatus.MalformedInput:
                    return 1;
                case VerificationStatus.NoMatchingKey:
                    return 2;
                case VerificationStatus.WrongSignatureType:
                    return 3;
                case VerificationStatus.UnsupportedAlgorithm:
                    return 4;
                case VerificationStatus.BadSignature:
                    return 5;
                default:
                    return 6; // a cryptographically valid signature rejected on key/time grounds
            }
        }

        private static VerificationResult Failure(VerificationStatus status, string message, Certificate? certificate = null, PublicKeyPacket? key = null, DateTimeOffset? createdAt = null)
        {
            return new VerificationResult(status, message, key?.Fingerprint.ToString(), certificate?.Primary.Fingerprint.ToString(), createdAt);
        }

        /// <summary>One signature: either an early failure, or its digest-in-progress and the keys that may have made it.</summary>
        private sealed class Entry : IDisposable
        {
            private VerificationResult? _failure;
            private SignaturePacket? _signature;
            private readonly List<(Certificate Certificate, PublicKeyPacket Key)> _candidates = [];

            public SignatureDigest? Digest { get; private set; }

            /// <summary>What checking this signature against every candidate key would cost (see <see cref="MaxCheckCost"/>).</summary>
            public int CandidateCost
            {
                get
                {
                    if (Digest is null || _signature is not { } signature)
                    {
                        return 0; // failed early; nothing will be checked
                    }

                    int cost = 0;
                    foreach ((Certificate _, PublicKeyPacket key) in _candidates)
                    {
                        // Only keys of the signature's version and algorithm get a cryptographic check.
                        cost += key.CanVerify && !SignatureVerifier.IsForDifferentKey(key, signature) ? key.VerificationKey.CheckCost : 0;
                    }

                    return cost;
                }
            }

            public void Dispose() => Digest?.Dispose();

            public static Entry Create(byte[] body, KeyRing keyRing, bool isClearsign)
            {
                var entry = new Entry();
                SignaturePacket signature;
                try
                {
                    signature = SignaturePacket.Parse(body);
                }
                catch (FailClosedException ex)
                {
                    entry._failure = Failure(ex.IsUnsupported ? VerificationStatus.UnsupportedAlgorithm : VerificationStatus.MalformedInput, "Signature cannot be used: " + ex.Message);
                    return entry;
                }

                entry._signature = signature;
                bool typeAllowed = isClearsign ? signature.IsCanonicalTextDocument : signature.IsBinaryDocument || signature.IsCanonicalTextDocument;
                if (!typeAllowed)
                {
                    entry._failure = Failure(
                        VerificationStatus.WrongSignatureType,
                        "Signature type 0x" + signature.SignatureTypeRaw.ToString("X2", System.Globalization.CultureInfo.InvariantCulture)
                        + (isClearsign ? " is not a text signature, as a clearsigned message requires." : " is not a document signature."));
                    return entry;
                }

                // Every key of every certificate: indexed rather than foreach'd, since enumerating
                // through IReadOnlyList<T> would allocate an enumerator per certificate.
                for (int c = 0; c < keyRing.Certificates.Count; c++)
                {
                    Certificate certificate = keyRing.Certificates[c];
                    for (int k = 0; k < certificate.Keys.Count; k++)
                    {
                        PublicKeyPacket key = certificate.Keys[k];
                        if (SignatureVerifier.IsIssuedBy(signature, key))
                        {
                            entry._candidates.Add((certificate, key));
                        }
                    }
                }

                if (entry._candidates.Count == 0)
                {
                    entry._failure = Failure(VerificationStatus.NoMatchingKey, "None of the supplied keys made this signature.");
                    return entry;
                }

                try
                {
                    entry.Digest = SignatureDigest.Begin(signature, canonicalizeText: !isClearsign && signature.IsCanonicalTextDocument);
                }
                catch (FailClosedException ex)
                {
                    entry._failure = Failure(VerificationStatus.UnsupportedAlgorithm, "Signature cannot be used: " + ex.Message);
                }

                return entry;
            }

            public VerificationResult Evaluate(DateTimeOffset now, string? signedText)
            {
                if (_failure is not null)
                {
                    return _failure;
                }

                SignaturePacket signature = _signature!;
                byte[] digest = Digest!.Finish();

                DateTimeOffset createdAt;
                try
                {
                    createdAt = SignatureVerifier.GetCreationTime(signature);
                }
                catch (FailClosedException ex)
                {
                    return Failure(VerificationStatus.MalformedInput, "Signature cannot be used: " + ex.Message);
                }

                VerificationResult? best = null;
                foreach ((Certificate certificate, PublicKeyPacket key) in _candidates)
                {
                    VerificationResult result = EvaluateCandidate(signature, digest, createdAt, certificate, key, now, signedText);
                    if (result.IsValid)
                    {
                        return result;
                    }

                    if (best is null || Rank(result.Status) > Rank(best.Status))
                    {
                        best = result;
                    }
                }

                // Every entry that reaches here has at least one candidate key (Create checks), so this
                // is unreachable - but if it ever were, the answer must still be a failure, never null.
                return best ?? Failure(VerificationStatus.NoMatchingKey, "None of the supplied keys made this signature.");
            }

            private static VerificationResult EvaluateCandidate(
                SignaturePacket signature,
                byte[] digest,
                DateTimeOffset createdAt,
                Certificate certificate,
                PublicKeyPacket key,
                DateTimeOffset now,
                string? signedText)
            {
                string? incompatibility = SignatureVerifier.GetIncompatibility(key, signature);
                if (incompatibility is not null)
                {
                    // A key we can't use, or a hash too weak for it, is "unsupported"; a key whose
                    // version or algorithm simply doesn't match the signature didn't make it.
                    VerificationStatus status = !key.CanVerify || !SignatureVerifier.IsForDifferentKey(key, signature)
                        ? VerificationStatus.UnsupportedAlgorithm
                        : VerificationStatus.BadSignature;
                    return Failure(status, "Signature cannot be checked with this key: " + incompatibility + ".", certificate, key, createdAt);
                }

                // Cryptography first: a forged signature must read as "bad", never as e.g. "expired".
                if (!SignatureVerifier.VerifyDocumentDigest(key, signature, digest))
                {
                    return Failure(VerificationStatus.BadSignature, "The signature does not match the data and key.", certificate, key, createdAt);
                }

                if (SignatureVerifier.IsFromTheFuture(createdAt, now))
                {
                    return Failure(VerificationStatus.InvalidSignatureTime, "The signature is dated in the future.", certificate, key, createdAt);
                }

                try
                {
                    if (!SignatureVerifier.IsUnexpired(signature, createdAt, now))
                    {
                        return Failure(VerificationStatus.SignatureExpired, "The signature has expired.", certificate, key, createdAt);
                    }
                }
                catch (FailClosedException ex)
                {
                    return Failure(VerificationStatus.MalformedInput, "Signature cannot be used: " + ex.Message, certificate, key, createdAt);
                }

                (VerificationStatus keyStatus, string keyMessage) = KeyValidity.CheckSigningKey(certificate, key, createdAt, now);
                if (keyStatus != VerificationStatus.Valid)
                {
                    return Failure(keyStatus, keyMessage, certificate, key, createdAt);
                }

                return new VerificationResult(
                    VerificationStatus.Valid,
                    "Good signature.",
                    key.Fingerprint.ToString(),
                    certificate.Primary.Fingerprint.ToString(),
                    createdAt,
                    signedText);
            }
        }
    }
}
