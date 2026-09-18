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
                    (BigInteger s, int consumed) = Mpi.ReadFrom(body, offset);
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

            if (offset + length > body.Length)
            {
                throw new FailClosedException("Unexpected end of input while reading the " + which + " subpacket data (truncated).");
            }

            var region = new byte[length];
            System.Array.Copy(body, offset, region, 0, length);
            offset += length;
            return region;
        }

        private static void RejectUnknownCritical(List<SignatureSubpacket> subpackets)
        {
            foreach (SignatureSubpacket subpacket in subpackets)
            {
                if (!subpacket.Critical)
                {
                    continue;
                }

                bool known = subpacket.RawType == (byte)SignatureSubpacketType.SignatureCreationTime
                             || subpacket.RawType == (byte)SignatureSubpacketType.IssuerKeyId
                             || subpacket.RawType == (byte)SignatureSubpacketType.IssuerFingerprint;

                if (!known)
                {
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

            // Each MPI wraps its raw 32-byte native EdDSA value verbatim (draft-koch-eddsa-for-openpgp
            // §3) - the same round-trip-preserves-original-bytes property used for the public key
            // point in PublicKeyPacket applies here, so no separate endianness handling is needed.
            byte[] r32 = Mpi.ToFixedLengthUnsignedBytes(r, rConsumed - 2);
            byte[] s32 = Mpi.ToFixedLengthUnsignedBytes(s, sConsumed - 2);

            if (r32.Length != 32 || s32.Length != 32)
            {
                throw new FailClosedException("Malformed EdDSA signature (expected two 32-byte native values).");
            }

            var signature = new byte[64];
            System.Array.Copy(r32, 0, signature, 0, 32);
            System.Array.Copy(s32, 0, signature, 32, 32);
            return signature;
        }
    }
}
