using System;
using Scarlet.OpenPgp.Crypto.Ed25519;
using Scarlet.OpenPgp.Crypto.Rsa;
using Scarlet.OpenPgp.Internal;

namespace Scarlet.OpenPgp.Packets
{
    /// <summary>A parsed v4 Public-Key packet (tag 6): version, creation time, algorithm, and algorithm-specific key material.</summary>
    internal sealed class PublicKeyPacket
    {
        /// <summary>
        /// The Ed25519 curve OID content octets used by the "EdDSALegacy" v4 convention
        /// (draft-koch-eddsa-for-openpgp), i.e. the DER content encoding of 1.3.6.1.4.1.11591.15.1.
        /// </summary>
        private static readonly byte[] Ed25519CurveOid = { 0x2B, 0x06, 0x01, 0x04, 0x01, 0xDA, 0x47, 0x0F, 0x01 };

        private PublicKeyPacket(
            DateTimeOffset createdAt,
            PublicKeyAlgorithm algorithm,
            RsaPublicKey? rsa,
            Ed25519PublicKey? edDsa,
            KeyFingerprint fingerprint)
        {
            CreatedAt = createdAt;
            Algorithm = algorithm;
            Rsa = rsa;
            EdDsa = edDsa;
            Fingerprint = fingerprint;
        }

        public DateTimeOffset CreatedAt { get; }

        public PublicKeyAlgorithm Algorithm { get; }

        public RsaPublicKey? Rsa { get; }

        public Ed25519PublicKey? EdDsa { get; }

        public KeyFingerprint Fingerprint { get; }

        public static PublicKeyPacket Parse(byte[] body)
        {
            if (body.Length < 6)
            {
                throw new FailClosedException("Public-key packet body is too short to contain a v4 header.");
            }

            byte version = body[0];
            if (version != 4)
            {
                throw new FailClosedException("Only v4 public-key packets are supported (got version " + version + ").");
            }

            long createdAtSeconds = ((long)body[1] << 24) | ((long)body[2] << 16) | ((long)body[3] << 8) | body[4];
            var createdAt = DateTimeOffset.FromUnixTimeSeconds(createdAtSeconds);

            byte algorithmByte = body[5];
            var algorithm = (PublicKeyAlgorithm)algorithmByte;

            RsaPublicKey? rsa = null;
            Ed25519PublicKey? edDsa = null;
            int offset = 6;

            switch (algorithm)
            {
                case PublicKeyAlgorithm.RsaEncryptOrSign:
                case PublicKeyAlgorithm.RsaSignOnly:
                    (System.Numerics.BigInteger n, int nConsumed) = Mpi.ReadFrom(body, offset, requireCanonical: true);
                    offset += nConsumed;
                    (System.Numerics.BigInteger e, int eConsumed) = Mpi.ReadFrom(body, offset, requireCanonical: true);
                    offset += eConsumed;
                    rsa = new RsaPublicKey(n, e);
                    break;

                case PublicKeyAlgorithm.EdDsaLegacy:
                    edDsa = ParseEdDsaMaterial(body, ref offset);
                    break;

                default:
                    throw new FailClosedException("Unsupported public-key algorithm: " + algorithmByte + ".");
            }

            if (offset != body.Length)
            {
                throw new FailClosedException("Public-key packet body has unexpected trailing data after its key material.");
            }

            var fingerprint = KeyFingerprint.ComputeV4(body);
            return new PublicKeyPacket(createdAt, algorithm, rsa, edDsa, fingerprint);
        }

        private static Ed25519PublicKey ParseEdDsaMaterial(byte[] body, ref int offset)
        {
            if (offset >= body.Length)
            {
                throw new FailClosedException("Unexpected end of input while reading the EdDSA curve OID length.");
            }

            int oidLength = body[offset];
            offset += 1;

            // oidLength is a single byte (at most 255), so overflow here is even less practical
            // than elsewhere - widened to long anyway for the same reason as the other checks.
            if ((long)offset + oidLength > body.Length)
            {
                throw new FailClosedException("Unexpected end of input while reading the EdDSA curve OID.");
            }

            for (int i = 0; i < oidLength; i++)
            {
                if (i >= Ed25519CurveOid.Length || body[offset + i] != Ed25519CurveOid[i])
                {
                    throw new FailClosedException("Unsupported EdDSA curve (only Ed25519 is supported).");
                }
            }

            if (oidLength != Ed25519CurveOid.Length)
            {
                throw new FailClosedException("Unsupported EdDSA curve (only Ed25519 is supported).");
            }

            offset += oidLength;

            (System.Numerics.BigInteger pointValue, int consumed) = Mpi.ReadFrom(body, offset);
            offset += consumed;

            // The MPI wraps the raw "native prefixed" point encoding verbatim (0x40 || 32-byte
            // point), per draft-koch-eddsa-for-openpgp §3. Round-tripping the MPI's BigInteger back
            // to a fixed-length big-endian byte array reconstructs those exact original bytes -
            // there is no separate byte-order conversion to do here.
            int pointFieldLength = consumed - 2; // total MPI bytes consumed minus its 2-byte bit-length prefix
            byte[] pointField = Mpi.ToFixedLengthUnsignedBytes(pointValue, pointFieldLength);

            if (pointField.Length != 33 || pointField[0] != 0x40)
            {
                throw new FailClosedException("Malformed Ed25519 public key point (expected a 0x40-prefixed 33-byte native encoding).");
            }

            var point = new byte[32];
            Array.Copy(pointField, 1, point, 0, 32);
            return new Ed25519PublicKey(point);
        }
    }
}
