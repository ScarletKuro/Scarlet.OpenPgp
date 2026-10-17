using System;
using System.Collections.Generic;
using System.Numerics;
using Scarlet.OpenPgp.Hashing;
using Scarlet.OpenPgp.Internal;

namespace Scarlet.OpenPgp.Packets
{
    /// <summary>A parsed v4 or v6 Signature packet (tag 2, RFC 9580 §5.2.3).</summary>
    internal sealed class SignaturePacket
    {
        private SignaturePacket(byte[] body)
        {
            Body = body;
        }

        /// <summary>The packet body exactly as received.</summary>
        public byte[] Body { get; }

        public byte Version { get; private set; }

        public byte SignatureTypeRaw { get; private set; }

        public bool IsBinaryDocument => SignatureTypeRaw == (byte)SignatureType.BinaryDocument;

        public bool IsCanonicalTextDocument => SignatureTypeRaw == (byte)SignatureType.CanonicalTextDocument;

        public PublicKeyAlgorithm PublicKeyAlgorithm { get; private set; }

        public HashAlgorithmId HashAlgorithm { get; private set; }

        /// <summary>
        /// The packet body from the version octet through the end of the hashed subpackets - the part
        /// of the signature that is itself hashed, before the trailer (RFC 9580 §5.2.4).
        /// </summary>
        public byte[] HashedPortion { get; private set; } = [];

        /// <summary>The raw hashed-subpacket area bytes.</summary>
        public byte[] HashedSubpacketData { get; private set; } = [];

        public IReadOnlyList<SignatureSubpacket> HashedSubpackets { get; private set; } = Array.Empty<SignatureSubpacket>();

        public IReadOnlyList<SignatureSubpacket> UnhashedSubpackets { get; private set; } = Array.Empty<SignatureSubpacket>();

        /// <summary>The 2-byte quick-check prefix of the expected hash (RFC 9580 §5.2.3), immediately preceding the salt/signature values.</summary>
        public byte[] LeftHashBytes16 { get; private set; } = [];

        /// <summary>The v6 signature salt, hashed before any other data (RFC 9580 §5.2.4). Empty for v4.</summary>
        public byte[] Salt { get; private set; } = [];

        public BigInteger? RsaSignatureValue { get; private set; }

        /// <summary>The DSA or ECDSA signature value r.</summary>
        public BigInteger? R { get; private set; }

        /// <summary>The DSA or ECDSA signature value s.</summary>
        public BigInteger? S { get; private set; }

        /// <summary>The 64-byte native Ed25519 signature (R || S), for both EdDSALegacy (reconstructed from its two MPI-wrapped halves) and native Ed25519.</summary>
        public byte[]? EdDsaSignatureValue { get; private set; }

        /// <summary>The 114-byte native Ed448 signature.</summary>
        public byte[]? Ed448SignatureValue { get; private set; }

        /// <summary>The first issuer key ID (8 bytes) from a type-16 subpacket in either area (searched hashed-first, matching how GnuPG places it in the unhashed area for legacy v4 signatures).</summary>
        public byte[]? IssuerKeyId
        {
            get
            {
                foreach (SignatureSubpacket subpacket in AllSubpackets())
                {
                    if (subpacket.Is(SignatureSubpacketType.IssuerKeyId) && subpacket.Data.Length == 8)
                    {
                        return subpacket.Data;
                    }
                }

                return null;
            }
        }

        /// <summary>
        /// Every issuer key ID and fingerprint the signature names, from either area. They are only
        /// hints for finding the right key - the unhashed area is unauthenticated - so a wrong hint
        /// can make verification fail, never succeed.
        /// </summary>
        public IEnumerable<byte[]> IssuerFingerprints
        {
            get
            {
                foreach (SignatureSubpacket subpacket in AllSubpackets())
                {
                    if (subpacket.Is(SignatureSubpacketType.IssuerFingerprint) && subpacket.Data.Length > 1)
                    {
                        yield return subpacket.Data.AsSpan(1).ToArray();
                    }
                }
            }
        }

        public IEnumerable<byte[]> IssuerKeyIds
        {
            get
            {
                foreach (SignatureSubpacket subpacket in AllSubpackets())
                {
                    if (subpacket.Is(SignatureSubpacketType.IssuerKeyId) && subpacket.Data.Length == 8)
                    {
                        yield return subpacket.Data;
                    }
                }
            }
        }

        /// <summary>The key flags (RFC 9580 §5.2.3.29) from the hashed area, or <c>null</c> when absent.</summary>
        public byte[]? KeyFlags => FindUniqueHashed(SignatureSubpacketType.KeyFlags)?.Data;

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

                if (subpacket.Data.Length < 1)
                {
                    throw new FailClosedException("Reason for Revocation subpacket is empty.");
                }

                return subpacket.Data[0];
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
                        embedded = Parse(subpacket.Data);
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

            if (subpacket.Data.Length != 4)
            {
                throw new FailClosedException("Hashed time subpacket (type " + (byte)type + ") must be exactly 4 bytes.");
            }

            value = ((uint)subpacket.Data[0] << 24) | ((uint)subpacket.Data[1] << 16) | ((uint)subpacket.Data[2] << 8) | subpacket.Data[3];
            return true;
        }

        public static SignaturePacket Parse(byte[] body)
        {
            if (body.Length < 4)
            {
                throw new FailClosedException("Signature packet body is too short to contain a signature header.");
            }

            var signature = new SignaturePacket(body);
            byte version = body[0];
            if (version != 4 && version != 6)
            {
                throw FailClosedException.Unsupported("Only v4 and v6 signature packets are supported (got version " + version + ").");
            }

            signature.Version = version;
            signature.SignatureTypeRaw = body[1];
            signature.PublicKeyAlgorithm = (PublicKeyAlgorithm)body[2];
            signature.HashAlgorithm = (HashAlgorithmId)body[3];

            // v4 subpacket areas have 2-octet lengths, v6 4-octet ones (RFC 9580 §5.2.3).
            int lengthFieldSize = version == 6 ? 4 : 2;
            int offset = 4;
            signature.HashedSubpacketData = ReadSubpacketRegion(body, ref offset, lengthFieldSize, "hashed");
            signature.HashedPortion = body.AsSpan(0, offset).ToArray();
            List<SignatureSubpacket> hashedSubpackets = SubpacketReader.ReadAll(signature.HashedSubpacketData);
            signature.HashedSubpackets = hashedSubpackets;

            byte[] unhashedSubpacketData = ReadSubpacketRegion(body, ref offset, lengthFieldSize, "unhashed");
            List<SignatureSubpacket> unhashedSubpackets = SubpacketReader.ReadAll(unhashedSubpacketData);
            signature.UnhashedSubpackets = unhashedSubpackets;

            signature.ValidateSubpackets(hashedSubpackets);
            signature.ValidateSubpackets(unhashedSubpackets);

            signature.LeftHashBytes16 = ReadFixed(body, ref offset, 2, "left-hash-bits field");

            if (version == 6)
            {
                int saltSize = ReadFixed(body, ref offset, 1, "salt size")[0];
                if (saltSize != HashContext.V6SaltSize(signature.HashAlgorithm))
                {
                    throw new FailClosedException("v6 signature salt size does not match its hash algorithm (RFC 9580 Table 23).");
                }

                signature.Salt = ReadFixed(body, ref offset, saltSize, "salt");
            }

            signature.ParseSignatureValues(body, ref offset);

            if (offset != body.Length)
            {
                throw new FailClosedException("Signature packet body has unexpected trailing data after its signature value.");
            }

            return signature;
        }

        private void ParseSignatureValues(byte[] body, ref int offset)
        {
            switch (PublicKeyAlgorithm)
            {
                case PublicKeyAlgorithm.RsaEncryptOrSign:
                case PublicKeyAlgorithm.RsaSignOnly:
                    RsaSignatureValue = ReadCanonicalMpi(body, ref offset);
                    break;

                case PublicKeyAlgorithm.Dsa:
                case PublicKeyAlgorithm.Ecdsa:
                    // Canonical, like RSA's: these are true integers, so a second encoding of the
                    // same value would only be a way to make a different-looking copy of a signature.
                    R = ReadCanonicalMpi(body, ref offset);
                    S = ReadCanonicalMpi(body, ref offset);
                    break;

                case PublicKeyAlgorithm.EdDsaLegacy:
                    if (Version == 6)
                    {
                        throw new FailClosedException("EdDSALegacy must not be used in v6 signatures (RFC 9580 §5.2.3.3).");
                    }

                    EdDsaSignatureValue = ParseEdDsaLegacySignature(body, ref offset);
                    break;

                case PublicKeyAlgorithm.Ed25519:
                    EdDsaSignatureValue = ReadFixed(body, ref offset, 64, "Ed25519 signature");
                    break;

                case PublicKeyAlgorithm.Ed448:
                    Ed448SignatureValue = ReadFixed(body, ref offset, 114, "Ed448 signature");
                    break;

                default:
                    throw FailClosedException.Unsupported("Unsupported signature public-key algorithm: " + (byte)PublicKeyAlgorithm + ".");
            }
        }

        private static byte[] ReadSubpacketRegion(byte[] body, ref int offset, int lengthFieldSize, string which)
        {
            byte[] lengthField = ReadFixed(body, ref offset, lengthFieldSize, which + " subpacket count");
            long length = 0;
            foreach (byte b in lengthField)
            {
                length = (length << 8) | b;
            }

            // Widened to long: a v6 4-octet count can be up to 2^32 - 1.
            if (offset + length > body.Length)
            {
                throw new FailClosedException("Unexpected end of input while reading the " + which + " subpacket data (truncated).");
            }

            return ReadFixed(body, ref offset, (int)length, which + " subpacket data");
        }

        private static byte[] ReadFixed(byte[] body, ref int offset, int length, string what)
        {
            if ((long)offset + length > body.Length)
            {
                throw new FailClosedException("Unexpected end of input while reading the " + what + ".");
            }

            var result = new byte[length];
            Array.Copy(body, offset, result, 0, length);
            offset += length;
            return result;
        }

        private static BigInteger ReadCanonicalMpi(byte[] body, ref int offset)
        {
            (BigInteger value, int consumed) = Mpi.ReadFrom(body, offset, requireCanonical: true);
            offset += consumed;
            return value;
        }

        /// <summary>
        /// Rejects malformed subpackets that affect verification, and any critical subpacket whose
        /// meaning this library doesn't implement (RFC 9580 §5.2.3.7: "critical" means the verifier
        /// must understand it). The informational types (preferences, policy URI, features, ...) count
        /// as understood: they carry no meaning for whether a signature is valid. Malformed
        /// *non-critical* instances of the time/issuer types are left for the code that reads them,
        /// which fails closed if it ever needs one.
        /// </summary>
        private void ValidateSubpackets(List<SignatureSubpacket> subpackets)
        {
            foreach (SignatureSubpacket subpacket in subpackets)
            {
                // RFC 9580 §5.2.3.35: an Issuer Fingerprint whose version doesn't match the
                // signature's makes the whole signature malformed, critical or not.
                if (subpacket.Is(SignatureSubpacketType.IssuerFingerprint) && subpacket.Data.Length > 0 && subpacket.Data[0] != Version)
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
                        RequireLength(subpacket, Version == 6 ? 33 : 21);
                        break;

                    case SignatureSubpacketType.ReasonForRevocation:
                        if (subpacket.Data.Length < 1)
                        {
                            throw new FailClosedException("Critical Reason for Revocation subpacket is empty.");
                        }

                        break;

                    case SignatureSubpacketType.EmbeddedSignature:
                        Parse(subpacket.Data); // throws if malformed
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
                        // Includes Regular Expression, Notation Data, Signature Target and Intended
                        // Recipient Fingerprint: each changes what the signature means in ways this
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

        private static byte[] ParseEdDsaLegacySignature(byte[] body, ref int offset)
        {
            (BigInteger r, int rConsumed) = Mpi.ReadFrom(body, offset);
            offset += rConsumed;
            (BigInteger s, int sConsumed) = Mpi.ReadFrom(body, offset);
            offset += sConsumed;

            // Reconstruct each value as a fixed 32 bytes rather than trusting the wire's own MPI
            // byte count (rConsumed/sConsumed - 2): a compliant encoder is free to write a
            // non-canonical *or* a fully minimal MPI for these opaque-bytestring fields (see
            // Mpi.ReadFrom's requireCanonical doc comment), so whenever the true R or S value has a
            // leading 0x00 byte, a minimal encoding is only 31 bytes on the wire. Using that wire
            // length here would spuriously reject an otherwise valid signature roughly 1 time in
            // 128 (confirmed by an intermittent BouncyCastle-cross-validation test failure - random
            // keys occasionally produce exactly this case). Mpi.ToFixedLengthUnsignedBytes(value, 32)
            // always yields exactly 32 bytes for any value that actually fits in 256 bits, and
            // throws FailClosedException for one that doesn't - which is the correct check here.
            byte[] r32 = Mpi.ToFixedLengthUnsignedBytes(r, 32);
            byte[] s32 = Mpi.ToFixedLengthUnsignedBytes(s, 32);

            var signature = new byte[64];
            Array.Copy(r32, 0, signature, 0, 32);
            Array.Copy(s32, 0, signature, 32, 32);
            return signature;
        }
    }
}
