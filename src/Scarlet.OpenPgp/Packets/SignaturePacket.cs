using System.Collections.Generic;
using System.Linq;
using System.Numerics;
using Scarlet.OpenPgp.Hashing;
using Scarlet.OpenPgp.Internal;

namespace Scarlet.OpenPgp.Packets
{
    /// <summary>A parsed v4 Signature packet (tag 2, RFC 4880 §5.2).</summary>
    internal sealed class SignaturePacket
    {
        private SignaturePacket(
            byte version,
            byte signatureTypeRaw,
            PublicKeyAlgorithm publicKeyAlgorithm,
            HashAlgorithmId hashAlgorithm,
            byte[] hashedSubpacketData,
            IReadOnlyList<SignatureSubpacket> hashedSubpackets,
            IReadOnlyList<SignatureSubpacket> unhashedSubpackets,
            byte[] leftHashBytes16,
            BigInteger? rsaSignatureValue,
            byte[]? edDsaSignatureValue)
        {
            Version = version;
            SignatureTypeRaw = signatureTypeRaw;
            PublicKeyAlgorithm = publicKeyAlgorithm;
            HashAlgorithm = hashAlgorithm;
            HashedSubpacketData = hashedSubpacketData;
            HashedSubpackets = hashedSubpackets;
            UnhashedSubpackets = unhashedSubpackets;
            LeftHashBytes16 = leftHashBytes16;
            RsaSignatureValue = rsaSignatureValue;
            EdDsaSignatureValue = edDsaSignatureValue;
        }

        public byte Version { get; }

        public byte SignatureTypeRaw { get; }

        public bool IsBinaryDocument => SignatureTypeRaw == (byte)SignatureType.BinaryDocument;

        public bool IsCanonicalTextDocument => SignatureTypeRaw == (byte)SignatureType.CanonicalTextDocument;

        public PublicKeyAlgorithm PublicKeyAlgorithm { get; }

        public HashAlgorithmId HashAlgorithm { get; }

        /// <summary>The raw hashed-subpacket region bytes, needed verbatim by <see cref="Signing.SignatureHashBuilder"/>.</summary>
        public byte[] HashedSubpacketData { get; }

        public IReadOnlyList<SignatureSubpacket> HashedSubpackets { get; }

        public IReadOnlyList<SignatureSubpacket> UnhashedSubpackets { get; }

        /// <summary>The 2-byte quick-check prefix of the expected hash (RFC 4880 §5.2.3), immediately preceding the signature MPIs.</summary>
        public byte[] LeftHashBytes16 { get; }

        public BigInteger? RsaSignatureValue { get; }

        /// <summary>The 64-byte native Ed25519 signature (R || S), reconstructed verbatim from its two MPI-wrapped halves.</summary>
        public byte[]? EdDsaSignatureValue { get; }

        /// <summary>The issuer key ID (8 bytes), from a type-16 subpacket in either area (searched hashed-first, matching how GnuPG places it in the unhashed area for legacy v4 signatures).</summary>
        public byte[]? IssuerKeyId
        {
            get
            {
                SignatureSubpacket? subpacket = HashedSubpackets.Concat(UnhashedSubpackets)
                    .FirstOrDefault(s => s.Is(SignatureSubpacketType.IssuerKeyId));
                return subpacket?.Data;
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
            bool found = false;
            foreach (SignatureSubpacket subpacket in HashedSubpackets)
            {
                if (!subpacket.Is(type))
                {
                    continue;
                }

                if (found)
                {
                    throw new FailClosedException("Signature has more than one hashed subpacket of type " + (byte)type + ".");
                }

                if (subpacket.Data.Length != 4)
                {
                    throw new FailClosedException("Hashed time subpacket (type " + (byte)type + ") must be exactly 4 bytes.");
                }

                value = ((uint)subpacket.Data[0] << 24) | ((uint)subpacket.Data[1] << 16) | ((uint)subpacket.Data[2] << 8) | subpacket.Data[3];
                found = true;
            }

            return found;
        }

        public static SignaturePacket Parse(byte[] body)
        {
            if (body.Length < 6)
            {
                throw new FailClosedException("Signature packet body is too short to contain a v4 header.");
            }

            byte version = body[0];
            if (version != 4)
            {
                throw new FailClosedException("Only v4 signature packets are supported (got version " + version + ").");
            }

            byte signatureTypeRaw = body[1];
            var publicKeyAlgorithm = (PublicKeyAlgorithm)body[2];
            byte hashAlgorithmByte = body[3];
            var hashAlgorithm = (HashAlgorithmId)hashAlgorithmByte;

            int offset = 4;
            byte[] hashedSubpacketData = ReadSubpacketRegion(body, ref offset, "hashed");
            List<SignatureSubpacket> hashedSubpackets = SubpacketReader.ReadAll(hashedSubpacketData);
            RejectUnknownCritical(hashedSubpackets);

            byte[] unhashedSubpacketData = ReadSubpacketRegion(body, ref offset, "unhashed");
            List<SignatureSubpacket> unhashedSubpackets = SubpacketReader.ReadAll(unhashedSubpacketData);
            RejectUnknownCritical(unhashedSubpackets);

            if (offset + 2 > body.Length)
            {
                throw new FailClosedException("Unexpected end of input while reading the left-hash-bits field.");
            }

            var leftHashBytes16 = new byte[2];
            System.Array.Copy(body, offset, leftHashBytes16, 0, 2);
            offset += 2;

            BigInteger? rsaSignatureValue = null;
            byte[]? edDsaSignatureValue = null;

            switch (publicKeyAlgorithm)
            {
                case PublicKeyAlgorithm.RsaEncryptOrSign:
                case PublicKeyAlgorithm.RsaSignOnly:
                    (BigInteger s, int consumed) = Mpi.ReadFrom(body, offset, requireCanonical: true);
                    offset += consumed;
                    rsaSignatureValue = s;
                    break;

                case PublicKeyAlgorithm.EdDsaLegacy:
                    edDsaSignatureValue = ParseEdDsaSignature(body, ref offset);
                    break;

                default:
                    throw new FailClosedException("Unsupported signature public-key algorithm: " + (byte)publicKeyAlgorithm + ".");
            }

            if (offset != body.Length)
            {
                throw new FailClosedException("Signature packet body has unexpected trailing data after its signature value.");
            }

            return new SignaturePacket(
                version,
                signatureTypeRaw,
                publicKeyAlgorithm,
                hashAlgorithm,
                hashedSubpacketData,
                hashedSubpackets,
                unhashedSubpackets,
                leftHashBytes16,
                rsaSignatureValue,
                edDsaSignatureValue);
        }

        private static byte[] ReadSubpacketRegion(byte[] body, ref int offset, string which)
        {
            if (offset + 2 > body.Length)
            {
                throw new FailClosedException("Unexpected end of input while reading the " + which + " subpacket count.");
            }

            int length = (body[offset] << 8) | body[offset + 1];
            offset += 2;

            // length is at most 0xFFFF here (a 2-byte field), so this can only overflow int if
            // offset is already within 64K of int.MaxValue - i.e. body is itself close to 2GB.
            // Widened to long anyway for the same reason as the other length checks in this
            // codebase: the overflow-safety pattern should not depend on how wide the length field
            // happens to be.
            if ((long)offset + length > body.Length)
            {
                throw new FailClosedException("Unexpected end of input while reading the " + which + " subpacket data (truncated).");
            }

            var region = new byte[length];
            System.Array.Copy(body, offset, region, 0, length);
            offset += length;
            return region;
        }

        /// <summary>
        /// Fails closed on a critical subpacket of a type we don't recognize (per RFC 4880), and
        /// also on a critical subpacket of a type we *do* recognize but whose payload doesn't match
        /// that type's fixed structure - "critical" means the verifier must understand the
        /// subpacket, and a malformed payload for a known type is exactly as unusable as an
        /// unknown type would be. Malformed *non-critical* instances of these same types are left
        /// alone: RFC 4880 makes them safe to ignore regardless of validity.
        /// </summary>
        private static void RejectUnknownCritical(List<SignatureSubpacket> subpackets)
        {
            foreach (SignatureSubpacket subpacket in subpackets)
            {
                if (!subpacket.Critical)
                {
                    continue;
                }

                switch (subpacket.RawType)
                {
                    case (byte)SignatureSubpacketType.SignatureCreationTime:
                    case (byte)SignatureSubpacketType.SignatureExpirationTime:
                    case (byte)SignatureSubpacketType.KeyExpirationTime:
                        if (subpacket.Data.Length != 4)
                        {
                            throw new FailClosedException("Critical time subpacket (type " + subpacket.RawType + ") must be exactly 4 bytes.");
                        }

                        break;

                    case (byte)SignatureSubpacketType.IssuerKeyId:
                        if (subpacket.Data.Length != 8)
                        {
                            throw new FailClosedException("Critical IssuerKeyId subpacket must be exactly 8 bytes.");
                        }

                        break;

                    case (byte)SignatureSubpacketType.IssuerFingerprint:
                        // version(1) + a v4 SHA-1 fingerprint (20 bytes) = 21 bytes. This library
                        // only supports v4 signatures/keys (SignaturePacket.Parse/PublicKeyPacket.Parse
                        // both reject any other version), so the fingerprint version must be 4 too.
                        if (subpacket.Data.Length != 21 || subpacket.Data[0] != 4)
                        {
                            throw new FailClosedException("Critical IssuerFingerprint subpacket must be a 21-byte v4 fingerprint.");
                        }

                        break;

                    default:
                        throw new FailClosedException(
                            "Signature contains an unrecognized critical subpacket (type " + subpacket.RawType + "); failing closed per RFC 4880.");
                }
            }
        }

        private static byte[] ParseEdDsaSignature(byte[] body, ref int offset)
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
            System.Array.Copy(r32, 0, signature, 0, 32);
            System.Array.Copy(s32, 0, signature, 32, 32);
            return signature;
        }
    }
}
