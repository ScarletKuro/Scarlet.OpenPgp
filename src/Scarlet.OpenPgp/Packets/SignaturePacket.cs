using System;
using System.Collections.Generic;
using System.Numerics;
using Scarlet.OpenPgp.Crypto;
using Scarlet.OpenPgp.Hashing;
using Scarlet.OpenPgp.Internal;

namespace Scarlet.OpenPgp.Packets
{
    /// <summary>A parsed v4 or v6 Signature packet (tag 2, RFC 9580 §5.2.3).</summary>
    internal sealed class SignaturePacket
    {
        /// <summary>
        /// How deep signatures may be embedded in each other. A primary-key binding (back-)signature
        /// embedded in a subkey binding signature is the only legitimate use (RFC 9580 §5.2.3.34),
        /// so one level suffices. Without a limit, a hostile signature nesting thousands of levels
        /// overflows the stack - which kills the process rather than failing closed.
        /// </summary>
        private const int MaxEmbeddingDepth = 1;

        private readonly int _depth;

        private SignaturePacket(
            byte[] body,
            int depth,
            int hashedPortionLength,
            SubpacketArea hashedSubpackets,
            SubpacketArea unhashedSubpackets,
            byte[] leftHashBytes16,
            byte[] salt,
            SignatureValue value)
        {
            Body = body;
            _depth = depth;
            Version = body[0];
            SignatureTypeRaw = body[1];
            PublicKeyAlgorithm = (PublicKeyAlgorithm)body[2];
            HashAlgorithm = (HashAlgorithmId)body[3];
            HashedPortionLength = hashedPortionLength;
            HashedSubpackets = hashedSubpackets;
            UnhashedSubpackets = unhashedSubpackets;
            LeftHashBytes16 = leftHashBytes16;
            Salt = salt;
            Value = value;
        }

        /// <summary>The packet body exactly as received.</summary>
        public byte[] Body { get; }

        public byte Version { get; }

        public byte SignatureTypeRaw { get; }

        public bool IsBinaryDocument => SignatureTypeRaw == (byte)SignatureType.BinaryDocument;

        public bool IsCanonicalTextDocument => SignatureTypeRaw == (byte)SignatureType.CanonicalTextDocument;

        public PublicKeyAlgorithm PublicKeyAlgorithm { get; }

        public HashAlgorithmId HashAlgorithm { get; }

        /// <summary>
        /// The packet body from the version octet through the end of the hashed subpackets - the part
        /// of the signature that is itself hashed, before the trailer (RFC 9580 §5.2.4).
        /// </summary>
        public ReadOnlySpan<byte> HashedPortion => Body.AsSpan(0, HashedPortionLength);

        /// <summary>The length of <see cref="HashedPortion"/>, which starts at the beginning of <see cref="Body"/>.</summary>
        public int HashedPortionLength { get; }

        public SubpacketArea HashedSubpackets { get; }

        public SubpacketArea UnhashedSubpackets { get; }

        /// <summary>The 2-byte quick-check prefix of the expected hash (RFC 9580 §5.2.3), immediately preceding the salt/signature values.</summary>
        public byte[] LeftHashBytes16 { get; }

        /// <summary>The v6 signature salt, hashed before any other data (RFC 9580 §5.2.4). Empty for v4.</summary>
        public byte[] Salt { get; }

        /// <summary>The algorithm-specific signature value.</summary>
        public SignatureValue Value { get; }

        /// <summary>The key flags (RFC 9580 §5.2.3.29) from the hashed area, or <c>null</c> when absent.</summary>
        public byte[]? KeyFlags => FindUniqueHashed(SignatureSubpacketType.KeyFlags) is { } flags ? flags.Data.ToArray() : null;

        /// <summary>The machine-readable reason for revocation code (RFC 9580 §5.2.3.31) from the hashed area, or <c>null</c> when absent.</summary>
        public byte? RevocationReason
        {
            get
            {
                SignatureSubpacket? subpacket = FindUniqueHashed(SignatureSubpacketType.ReasonForRevocation);
                if (subpacket is null)
                {
                    return null;
                }

                if (subpacket.Value.Data.Length < 1)
                {
                    throw new FailClosedException("Reason for Revocation subpacket is empty.");
                }

                return subpacket.Value.Data[0];
            }
        }

        /// <summary>
        /// The embedded signatures (RFC 9580 §5.2.3.34) from either area - a signing subkey's
        /// primary-key binding "back-signature" lives here. Location doesn't matter for security: an
        /// embedded signature is only ever trusted after it verifies cryptographically on its own.
        /// Malformed ones are skipped.
        /// </summary>
        public IEnumerable<SignaturePacket> EmbeddedSignatures
        {
            get
            {
                foreach (SignatureSubpacket subpacket in AllSubpackets())
                {
                    if (!subpacket.Is(SignatureSubpacketType.EmbeddedSignature))
                    {
                        continue;
                    }

                    SignaturePacket? embedded = null;
                    try
                    {
                        embedded = Parse(subpacket.Data.ToArray(), _depth + 1);
                    }
                    catch (FailClosedException)
                    {
                        // A malformed embedded signature can't be a valid back-signature.
                    }

                    if (embedded is not null)
                    {
                        yield return embedded;
                    }
                }
            }
        }

        /// <summary>
        /// Reads a 4-byte big-endian time value (a timestamp or a duration in seconds) from the
        /// *hashed* subpacket area only - the unhashed area isn't covered by the signature, so
        /// anyone could add or change a value there. Returns <c>false</c> when absent. Fails closed
        /// when present more than once (which value would win is ambiguous) or not exactly 4 bytes.
        /// </summary>
        public bool TryGetHashedTime(SignatureSubpacketType type, out uint value)
        {
            value = 0;
            SignatureSubpacket? subpacket = FindUniqueHashed(type);
            if (subpacket is null)
            {
                return false;
            }

            ReadOnlySpan<byte> data = subpacket.Value.Data;
            if (data.Length != 4)
            {
                throw new FailClosedException("Hashed time subpacket (type " + (byte)type + ") must be exactly 4 bytes.");
            }

            value = ((uint)data[0] << 24) | ((uint)data[1] << 16) | ((uint)data[2] << 8) | data[3];
            return true;
        }

        public static SignaturePacket Parse(byte[] body) => Parse(body, 0);

        private static SignaturePacket Parse(byte[] body, int depth)
        {
            if (depth > MaxEmbeddingDepth)
            {
                throw new FailClosedException("Signature is embedded more than " + MaxEmbeddingDepth + " level deep.");
            }

            if (body.Length < 4)
            {
                throw new FailClosedException("Signature packet body is too short to contain a signature header.");
            }

            byte version = body[0];
            if (version != 4 && version != 6)
            {
                throw FailClosedException.Unsupported("Only v4 and v6 signature packets are supported (got version " + version + ").");
            }

            var algorithm = (PublicKeyAlgorithm)body[2];
            var hashAlgorithm = (HashAlgorithmId)body[3];
            var reader = new PacketBodyReader(body);
            reader.ReadBytes(4, "signature header");

            // v4 subpacket areas have 2-octet lengths, v6 4-octet ones (RFC 9580 §5.2.3).
            int lengthFieldSize = version == 6 ? 4 : 2;
            (int hashedStart, int hashedLength) = reader.SkipLengthPrefixed(lengthFieldSize, "hashed subpacket data");
            SubpacketArea hashedSubpackets = SubpacketArea.Read(body, hashedStart, hashedLength);
            int hashedPortionLength = reader.Offset;

            // The unhashed area isn't covered by the signature, so anyone can add to or change it
            // (RFC 9580 §13.13). Nothing in it may decide whether the signature is valid: if a
            // malformed or "critical" unhashed subpacket could make the signature fail to parse, then
            // two unsigned bytes added to a certificate's revocation would make the revocation
            // vanish. It is read leniently (unreadable = empty) and never validated.
            (int unhashedStart, int unhashedLength) = reader.SkipLengthPrefixed(lengthFieldSize, "unhashed subpacket data");
            SubpacketArea unhashedSubpackets = TryReadSubpackets(body, unhashedStart, unhashedLength);

            ValidateSubpackets(hashedSubpackets, version, depth);

            byte[] leftHashBytes16 = reader.ReadBytes(2, "left-hash-bits field");

            byte[] salt = [];
            if (version == 6)
            {
                int saltSize = reader.ReadByte("salt size");
                if (saltSize != HashContext.V6SaltSize(hashAlgorithm))
                {
                    throw new FailClosedException("v6 signature salt size does not match its hash algorithm (RFC 9580 Table 23).");
                }

                salt = reader.ReadBytes(saltSize, "salt");
            }

            SignatureValue value = ParseValue(algorithm, version, ref reader);
            reader.ExpectEnd("Signature packet body");

            return new SignaturePacket(body, depth, hashedPortionLength, hashedSubpackets, unhashedSubpackets, leftHashBytes16, salt, value);
        }

        private static SignatureValue ParseValue(PublicKeyAlgorithm algorithm, byte version, ref PacketBodyReader reader)
        {
            switch (algorithm)
            {
                case PublicKeyAlgorithm.RsaEncryptOrSign:
                case PublicKeyAlgorithm.RsaSignOnly:
                    return new RsaSignatureValue(reader.ReadMpi(requireCanonical: true));

                case PublicKeyAlgorithm.Dsa:
                case PublicKeyAlgorithm.Ecdsa:
                    // Canonical, like RSA's: these are true integers, so a second encoding of the
                    // same value would only be a way to make a different-looking copy of a signature.
                    return new RsSignatureValue(reader.ReadMpi(requireCanonical: true), reader.ReadMpi(requireCanonical: true));

                case PublicKeyAlgorithm.EdDsaLegacy:
                    if (version == 6)
                    {
                        throw new FailClosedException("EdDSALegacy must not be used in v6 signatures (RFC 9580 §5.2.3.3).");
                    }

                    return ParseEdDsaLegacyValue(ref reader);

                case PublicKeyAlgorithm.Ed25519:
                    return new EdDsaSignatureValue(reader.ReadBytes(64, "Ed25519 signature"));

                case PublicKeyAlgorithm.Ed448:
                    return new EdDsaSignatureValue(reader.ReadBytes(114, "Ed448 signature"));

                default:
                    throw FailClosedException.Unsupported("Unsupported signature public-key algorithm: " + (byte)algorithm + ".");
            }
        }

        /// <summary>The 64-byte native Ed25519 signature (R || S), reconstructed from EdDSALegacy's two MPI-wrapped halves.</summary>
        private static EdDsaSignatureValue ParseEdDsaLegacyValue(ref PacketBodyReader reader)
        {
            BigInteger r = reader.ReadMpi(requireCanonical: false);
            BigInteger s = reader.ReadMpi(requireCanonical: false);

            // Reconstruct each value as a fixed 32 bytes rather than trusting the wire's own MPI
            // byte count: a compliant encoder is free to write a non-canonical *or* a fully minimal
            // MPI for these opaque-bytestring fields (see Mpi.ReadFrom's requireCanonical doc
            // comment), so whenever the true R or S value has a leading 0x00 byte, a minimal
            // encoding is only 31 bytes on the wire. Using that wire length here would spuriously
            // reject an otherwise valid signature roughly 1 time in 128 (confirmed by an intermittent
            // BouncyCastle-cross-validation test failure - random keys occasionally produce exactly
            // this case). Mpi.ToFixedLengthUnsignedBytes(value, 32) always yields exactly 32 bytes
            // for any value that actually fits in 256 bits, and throws FailClosedException for one
            // that doesn't - which is the correct check here.
            var signature = new byte[64];
            Mpi.ToFixedLengthUnsignedBytes(r, 32).CopyTo(signature, 0);
            Mpi.ToFixedLengthUnsignedBytes(s, 32).CopyTo(signature, 32);
            return new EdDsaSignatureValue(signature);
        }

        /// <summary>The unhashed area's subpackets, or none if its framing is broken - it is advisory, so an unreadable one is simply absent.</summary>
        private static SubpacketArea TryReadSubpackets(byte[] body, int start, int length)
        {
            try
            {
                return SubpacketArea.Read(body, start, length);
            }
            catch (FailClosedException)
            {
                return SubpacketArea.Empty;
            }
        }

        /// <summary>
        /// Rejects malformed subpackets that affect verification, and any critical subpacket whose
        /// meaning this library doesn't implement (RFC 9580 §5.2.3.7: "critical" means the verifier
        /// must understand it). The informational types (preferences, policy URI, features, ...) count
        /// as understood: they carry no meaning for whether a signature is valid. Malformed
        /// *non-critical* instances of the time/issuer types are left for the code that reads them,
        /// which fails closed if it ever needs one.
        /// </summary>
        private static void ValidateSubpackets(SubpacketArea subpackets, byte version, int depth)
        {
            foreach (SignatureSubpacket subpacket in subpackets)
            {
                // RFC 9580 §5.2.3.35: an Issuer Fingerprint whose version doesn't match the
                // signature's makes the whole signature malformed, critical or not.
                if (subpacket.Is(SignatureSubpacketType.IssuerFingerprint) && subpacket.Data.Length > 0 && subpacket.Data[0] != version)
                {
                    throw new FailClosedException("Issuer Fingerprint version does not match the signature version.");
                }

                if (!subpacket.Critical)
                {
                    continue;
                }

                switch ((SignatureSubpacketType)subpacket.RawType)
                {
                    case SignatureSubpacketType.SignatureCreationTime:
                    case SignatureSubpacketType.SignatureExpirationTime:
                    case SignatureSubpacketType.KeyExpirationTime:
                        RequireLength(subpacket, 4);
                        break;

                    case SignatureSubpacketType.IssuerKeyId:
                        RequireLength(subpacket, 8);
                        break;

                    case SignatureSubpacketType.IssuerFingerprint:
                        RequireLength(subpacket, version == 6 ? 33 : 21);
                        break;

                    case SignatureSubpacketType.ReasonForRevocation:
                        if (subpacket.Data.Length < 1)
                        {
                            throw new FailClosedException("Critical Reason for Revocation subpacket is empty.");
                        }

                        break;

                    case SignatureSubpacketType.EmbeddedSignature:
                        Parse(subpacket.Data.ToArray(), depth + 1); // throws if malformed or nested too deep
                        break;

                    case SignatureSubpacketType.ExportableCertification:
                    case SignatureSubpacketType.TrustSignature:
                    case SignatureSubpacketType.Revocable:
                    case SignatureSubpacketType.PreferredSymmetricCiphers:
                    case SignatureSubpacketType.RevocationKey:
                    case SignatureSubpacketType.PreferredHashAlgorithms:
                    case SignatureSubpacketType.PreferredCompressionAlgorithms:
                    case SignatureSubpacketType.KeyServerPreferences:
                    case SignatureSubpacketType.PreferredKeyServer:
                    case SignatureSubpacketType.PrimaryUserId:
                    case SignatureSubpacketType.PolicyUri:
                    case SignatureSubpacketType.KeyFlags:
                    case SignatureSubpacketType.SignersUserId:
                    case SignatureSubpacketType.Features:
                    case SignatureSubpacketType.PreferredAeadAlgorithms:
                    case SignatureSubpacketType.PreferredAeadCiphersuites:
                        break;

                    default:
                        // Includes Regular Expression (6), Notation Data (20), Signature Target (31) and Intended
                        // Recipient Fingerprint (35): each changes what the signature means in ways this
                        // verifier doesn't evaluate.
                        throw new FailClosedException(
                            "Signature contains an unrecognized critical subpacket (type " + subpacket.RawType + "); failing closed per RFC 9580.");
                }
            }
        }

        private static void RequireLength(SignatureSubpacket subpacket, int length)
        {
            if (subpacket.Data.Length != length)
            {
                throw new FailClosedException("Critical subpacket (type " + subpacket.RawType + ") must be exactly " + length + " bytes.");
            }
        }

        /// <summary>A hashed subpacket of <paramref name="type"/>, or <c>null</c>; fails closed if there is more than one.</summary>
        private SignatureSubpacket? FindUniqueHashed(SignatureSubpacketType type)
        {
            SignatureSubpacket? found = null;
            foreach (SignatureSubpacket subpacket in HashedSubpackets)
            {
                if (!subpacket.Is(type))
                {
                    continue;
                }

                if (found is not null)
                {
                    throw new FailClosedException("Signature has more than one hashed subpacket of type " + (byte)type + ".");
                }

                found = subpacket;
            }

            return found;
        }

        private IEnumerable<SignatureSubpacket> AllSubpackets()
        {
            foreach (SignatureSubpacket subpacket in HashedSubpackets)
            {
                yield return subpacket;
            }

            foreach (SignatureSubpacket subpacket in UnhashedSubpackets)
            {
                yield return subpacket;
            }
        }
    }
}
