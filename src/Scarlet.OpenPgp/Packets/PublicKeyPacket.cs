using System;
using System.Numerics;
using Scarlet.OpenPgp.Crypto.Dsa;
using Scarlet.OpenPgp.Crypto.Ecdsa;
using Scarlet.OpenPgp.Crypto.Ed25519;
using Scarlet.OpenPgp.Crypto.Rsa;
using Scarlet.OpenPgp.Internal;

namespace Scarlet.OpenPgp.Packets
{
    /// <summary>
    /// A parsed v4 or v6 Public-Key or Public-Subkey packet (RFC 9580 §5.5.2): version, creation
    /// time, algorithm, and - for the signing algorithms this library verifies - the key material.
    /// </summary>
    /// <remarks>
    /// Keys of algorithms that can't make signatures (ECDH, X25519, Elgamal, ...) or that this
    /// library doesn't implement still parse: they appear in real certificates as encryption
    /// subkeys, and their fingerprints are needed to check the binding signatures around them. Such
    /// a key simply has no verification material (<see cref="CanVerify"/> is <c>false</c>).
    /// Malformed material for an algorithm that *is* supported fails closed.
    /// </remarks>
    internal sealed class PublicKeyPacket
    {
        /// <summary>The Ed25519 curve OID content octets used by the EdDSALegacy convention: 1.3.6.1.4.1.11591.15.1.</summary>
        private static readonly byte[] Ed25519LegacyCurveOid = { 0x2B, 0x06, 0x01, 0x04, 0x01, 0xDA, 0x47, 0x0F, 0x01 };

        private PublicKeyPacket(byte version, DateTimeOffset createdAt, PublicKeyAlgorithm algorithm, byte[] body)
        {
            Version = version;
            CreatedAt = createdAt;
            Algorithm = algorithm;
            Body = body;
            Fingerprint = KeyFingerprint.Compute(version, body);
        }

        public byte Version { get; }

        public DateTimeOffset CreatedAt { get; }

        public PublicKeyAlgorithm Algorithm { get; }

        /// <summary>The packet body exactly as received, needed verbatim for fingerprints and key signatures.</summary>
        public byte[] Body { get; }

        public KeyFingerprint Fingerprint { get; }

        public RsaPublicKey? Rsa { get; private set; }

        public DsaPublicKey? Dsa { get; private set; }

        public EcCurve? EcdsaCurve { get; private set; }

        /// <summary>The SEC1 uncompressed point (0x04 || X || Y) of an ECDSA key.</summary>
        public byte[]? EcdsaPoint { get; private set; }

        /// <summary>The Ed25519 public key, for both EdDSALegacy (22) and native Ed25519 (27) keys.</summary>
        public Ed25519PublicKey? Ed25519 { get; private set; }

        /// <summary>The raw 57-octet Ed448 public key.</summary>
        public byte[]? Ed448 { get; private set; }

        /// <summary>A human-readable algorithm description, e.g. "RSA 4096", "ECDSA NIST P-256", "Ed25519".</summary>
        public string AlgorithmDescription
        {
            get
            {
                switch (Algorithm)
                {
                    case PublicKeyAlgorithm.RsaEncryptOrSign:
                    case PublicKeyAlgorithm.RsaSignOnly:
                        return Rsa is null ? "RSA" : "RSA " + Crypto.BigIntegerMath.BitLength(Rsa.Modulus).ToString(System.Globalization.CultureInfo.InvariantCulture);
                    case PublicKeyAlgorithm.Dsa:
                        return Dsa is null ? "DSA" : "DSA " + Crypto.BigIntegerMath.BitLength(Dsa.P).ToString(System.Globalization.CultureInfo.InvariantCulture);
                    case PublicKeyAlgorithm.Ecdsa:
                        return EcdsaCurve is null ? "ECDSA (unsupported curve)" : "ECDSA " + EcdsaCurve.Name;
                    case PublicKeyAlgorithm.EdDsaLegacy:
                        return "EdDSA Ed25519 (legacy)";
                    case PublicKeyAlgorithm.Ed25519:
                        return "Ed25519";
                    case PublicKeyAlgorithm.Ed448:
                        return "Ed448";
                    case PublicKeyAlgorithm.RsaEncryptOnly:
                        return "RSA (encrypt only)";
                    case PublicKeyAlgorithm.ElGamalEncryptOnly:
                        return "Elgamal";
                    case PublicKeyAlgorithm.Ecdh:
                        return "ECDH";
                    case PublicKeyAlgorithm.X25519:
                        return "X25519";
                    case PublicKeyAlgorithm.X448:
                        return "X448";
                    default:
                        return "Unknown (" + ((byte)Algorithm).ToString(System.Globalization.CultureInfo.InvariantCulture) + ")";
                }
            }
        }

        /// <summary>Whether this key has material this library can verify signatures with.</summary>
        public bool CanVerify => Rsa is not null || Dsa is not null || EcdsaPoint is not null || Ed25519 is not null || Ed448 is not null;

        public static PublicKeyPacket Parse(byte[] body)
        {
            if (body.Length < 6)
            {
                throw new FailClosedException("Public-key packet body is too short to contain a key header.");
            }

            byte version = body[0];
            if (version != 4 && version != 6)
            {
                throw FailClosedException.Unsupported("Only v4 and v6 public-key packets are supported (got version " + version + ").");
            }

            long createdAtSeconds = ((long)body[1] << 24) | ((long)body[2] << 16) | ((long)body[3] << 8) | body[4];
            var algorithm = (PublicKeyAlgorithm)body[5];
            var packet = new PublicKeyPacket(version, DateTimeOffset.FromUnixTimeSeconds(createdAtSeconds), algorithm, body);

            int offset = 6;
            if (version == 6)
            {
                // RFC 9580 §5.5.2.3: a 4-octet count of the key material, which must cover exactly
                // the rest of the packet.
                if (body.Length < 10)
                {
                    throw new FailClosedException("v6 public-key packet is too short to contain its key material length.");
                }

                long materialLength = ((long)body[6] << 24) | ((long)body[7] << 16) | ((long)body[8] << 8) | body[9];
                offset = 10;
                if (materialLength != body.Length - offset)
                {
                    throw new FailClosedException("v6 public-key packet's key material length does not match the packet.");
                }
            }

            if (!packet.ParseMaterial(body, ref offset))
            {
                return packet; // not a signing algorithm this library implements
            }

            if (offset != body.Length)
            {
                throw new FailClosedException("Public-key packet body has unexpected trailing data after its key material.");
            }

            return packet;
        }

        /// <summary>Parses the algorithm-specific key material. Returns <c>false</c> for algorithms without verification support.</summary>
        private bool ParseMaterial(byte[] body, ref int offset)
        {
            switch (Algorithm)
            {
                case PublicKeyAlgorithm.RsaEncryptOrSign:
                case PublicKeyAlgorithm.RsaSignOnly:
                    BigInteger n = ReadCanonicalMpi(body, ref offset);
                    BigInteger e = ReadCanonicalMpi(body, ref offset);
                    Rsa = new RsaPublicKey(n, e);
                    return true;

                case PublicKeyAlgorithm.Dsa:
                    BigInteger p = ReadCanonicalMpi(body, ref offset);
                    BigInteger q = ReadCanonicalMpi(body, ref offset);
                    BigInteger g = ReadCanonicalMpi(body, ref offset);
                    BigInteger y = ReadCanonicalMpi(body, ref offset);
                    Dsa = new DsaPublicKey(p, q, g, y);
                    return true;

                case PublicKeyAlgorithm.Ecdsa:
                    return ParseEcdsaMaterial(body, ref offset);

                case PublicKeyAlgorithm.EdDsaLegacy:
                    if (Version == 6)
                    {
                        throw new FailClosedException("EdDSALegacy keys are not allowed in v6 public-key packets (RFC 9580 §5.5.5.5).");
                    }

                    Ed25519 = ParseEdDsaLegacyMaterial(body, ref offset);
                    return true;

                case PublicKeyAlgorithm.Ed25519:
                    Ed25519 = new Ed25519PublicKey(ReadFixed(body, ref offset, Ed25519PublicKey.EncodedLength, "Ed25519 public key"));
                    return true;

                case PublicKeyAlgorithm.Ed448:
                    Ed448 = ReadFixed(body, ref offset, 57, "Ed448 public key");
                    return true;

                default:
                    return false;
            }
        }

        private bool ParseEcdsaMaterial(byte[] body, ref int offset)
        {
            byte[] oid = ReadCurveOid(body, ref offset);
            EcCurve? curve = EcCurve.FindByOid(oid);
            if (curve is null)
            {
                return false; // a curve this library doesn't implement (e.g. secp256k1)
            }

            (BigInteger pointValue, int consumed) = Mpi.ReadFrom(body, offset);
            offset += consumed;

            int coordinateLength = curve.FieldByteLength;
            EcdsaCurve = curve;
            EcdsaPoint = Mpi.ToFixedLengthUnsignedBytes(pointValue, 1 + (2 * coordinateLength));
            return true;
        }

        private static Ed25519PublicKey ParseEdDsaLegacyMaterial(byte[] body, ref int offset)
        {
            byte[] oid = ReadCurveOid(body, ref offset);
            if (!oid.AsSpan().SequenceEqual(Ed25519LegacyCurveOid))
            {
                throw FailClosedException.Unsupported("Unsupported EdDSALegacy curve (only Ed25519 is supported).");
            }

            (BigInteger pointValue, int consumed) = Mpi.ReadFrom(body, offset);
            offset += consumed;

            // The MPI wraps the "native prefixed" point encoding verbatim (0x40 || 32-byte point),
            // per draft-koch-eddsa-for-openpgp §3. Round-tripping the MPI's value to its own wire
            // length reconstructs exactly those bytes.
            byte[] pointField = Mpi.ToFixedLengthUnsignedBytes(pointValue, consumed - 2);
            if (pointField.Length != 33 || pointField[0] != 0x40)
            {
                throw new FailClosedException("Malformed Ed25519 public key point (expected a 0x40-prefixed 33-byte native encoding).");
            }

            var point = new byte[32];
            Array.Copy(pointField, 1, point, 0, 32);
            return new Ed25519PublicKey(point);
        }

        /// <summary>Reads a curve OID: a length octet (0 and 0xFF are reserved) and that many OID content octets (RFC 9580 §5.5.5.4).</summary>
        private static byte[] ReadCurveOid(byte[] body, ref int offset)
        {
            if (offset >= body.Length)
            {
                throw new FailClosedException("Unexpected end of input while reading a curve OID length.");
            }

            int oidLength = body[offset];
            offset += 1;
            if (oidLength == 0 || oidLength == 0xFF)
            {
                throw new FailClosedException("Curve OID length " + oidLength + " is reserved.");
            }

            return ReadFixed(body, ref offset, oidLength, "curve OID");
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
    }
}
