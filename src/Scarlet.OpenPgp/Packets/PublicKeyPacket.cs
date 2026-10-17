using System;
using System.Diagnostics.CodeAnalysis;
using System.Numerics;
using Scarlet.OpenPgp.Crypto;
using Scarlet.OpenPgp.Crypto.Dsa;
using Scarlet.OpenPgp.Crypto.Ecdsa;
using Scarlet.OpenPgp.Crypto.Ed25519;
using Scarlet.OpenPgp.Crypto.Ed448;
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
    /// a key simply has no <see cref="VerificationKey"/>. Malformed material for an algorithm that
    /// *is* supported fails closed.
    /// </remarks>
    internal sealed class PublicKeyPacket
    {
        /// <summary>The Ed25519 curve OID content octets used by the EdDSALegacy convention: 1.3.6.1.4.1.11591.15.1.</summary>
        private static readonly byte[] Ed25519LegacyCurveOid = [0x2B, 0x06, 0x01, 0x04, 0x01, 0xDA, 0x47, 0x0F, 0x01];

        private PublicKeyPacket(byte version, DateTimeOffset createdAt, PublicKeyAlgorithm algorithm, byte[] body, VerificationKey? verificationKey)
        {
            Version = version;
            CreatedAt = createdAt;
            Algorithm = algorithm;
            Body = body;
            VerificationKey = verificationKey;
            Fingerprint = KeyFingerprint.Compute(version, body);
        }

        public byte Version { get; }

        public DateTimeOffset CreatedAt { get; }

        public PublicKeyAlgorithm Algorithm { get; }

        /// <summary>The packet body exactly as received, needed verbatim for fingerprints and key signatures.</summary>
        public byte[] Body { get; }

        public KeyFingerprint Fingerprint { get; }

        /// <summary>The key material, when the algorithm is one this library verifies signatures with.</summary>
        public VerificationKey? VerificationKey { get; }

        /// <summary>Whether this key has material this library can verify signatures with.</summary>
        [MemberNotNullWhen(true, nameof(VerificationKey))]
        public bool CanVerify => VerificationKey is not null;

        /// <summary>A human-readable algorithm description, e.g. "RSA 4096", "ECDSA NIST P-256", "Ed25519".</summary>
        public string AlgorithmDescription => VerificationKey?.Description ?? DescribeUnverifiable(Algorithm);

        public static PublicKeyPacket Parse(byte[] body)
        {
            var reader = new PacketBodyReader(body);
            byte version = reader.ReadByte("public-key version");
            if (version != 4 && version != 6)
            {
                throw FailClosedException.Unsupported("Only v4 and v6 public-key packets are supported (got version " + version + ").");
            }

            var createdAt = DateTimeOffset.FromUnixTimeSeconds(reader.ReadBigEndian(4, "key creation time"));
            var algorithm = (PublicKeyAlgorithm)reader.ReadByte("public-key algorithm");

            if (version == 6)
            {
                // RFC 9580 §5.5.2.3: a 4-octet count of the key material, which must cover exactly
                // the rest of the packet.
                long materialLength = reader.ReadBigEndian(4, "v6 key material length");
                if (materialLength != body.Length - reader.Offset)
                {
                    throw new FailClosedException("v6 public-key packet's key material length does not match the packet.");
                }
            }

            VerificationKey? verificationKey = ParseMaterial(algorithm, version, ref reader);
            if (verificationKey is not null)
            {
                // Only for algorithms read to the end: an unknown algorithm's material is opaque.
                reader.ExpectEnd("Public-key packet body");
            }

            return new PublicKeyPacket(version, createdAt, algorithm, body, verificationKey);
        }

        /// <summary>The algorithm-specific key material, or <c>null</c> for algorithms this library can't verify with.</summary>
        private static VerificationKey? ParseMaterial(PublicKeyAlgorithm algorithm, byte version, ref PacketBodyReader reader)
        {
            switch (algorithm)
            {
                case PublicKeyAlgorithm.RsaEncryptOrSign:
                case PublicKeyAlgorithm.RsaSignOnly:
                    return new RsaPublicKey(reader.ReadMpi(requireCanonical: true), reader.ReadMpi(requireCanonical: true));

                case PublicKeyAlgorithm.Dsa:
                    return new DsaPublicKey(
                        reader.ReadMpi(requireCanonical: true),
                        reader.ReadMpi(requireCanonical: true),
                        reader.ReadMpi(requireCanonical: true),
                        reader.ReadMpi(requireCanonical: true));

                case PublicKeyAlgorithm.Ecdsa:
                    EcCurve? curve = EcCurve.FindByOid(reader.ReadCurveOid());
                    if (curve is null)
                    {
                        return null; // a curve this library doesn't implement (e.g. secp256k1)
                    }

                    byte[] point = Mpi.ToFixedLengthUnsignedBytes(reader.ReadMpi(requireCanonical: false), 1 + (2 * curve.FieldByteLength));
                    return new EcdsaPublicKey(curve, point);

                case PublicKeyAlgorithm.EdDsaLegacy:
                    if (version == 6)
                    {
                        throw new FailClosedException("EdDSALegacy keys are not allowed in v6 public-key packets (RFC 9580 §5.5.5.5).");
                    }

                    return ParseEdDsaLegacyMaterial(ref reader);

                case PublicKeyAlgorithm.Ed25519:
                    return new Ed25519PublicKey(reader.ReadBytes(Ed25519PublicKey.EncodedLength, "Ed25519 public key"));

                case PublicKeyAlgorithm.Ed448:
                    return new Ed448PublicKey(reader.ReadBytes(Ed448Verifier.PublicKeyLength, "Ed448 public key"));

                default:
                    return null;
            }
        }

        private static Ed25519PublicKey ParseEdDsaLegacyMaterial(ref PacketBodyReader reader)
        {
            if (!reader.ReadCurveOid().AsSpan().SequenceEqual(Ed25519LegacyCurveOid))
            {
                throw FailClosedException.Unsupported("Unsupported EdDSALegacy curve (only Ed25519 is supported).");
            }

            // The MPI wraps the "native prefixed" point encoding verbatim (0x40 || 32-byte point),
            // per draft-koch-eddsa-for-openpgp §3. Round-tripping the MPI's value to its own wire
            // length reconstructs exactly those bytes.
            BigInteger pointValue = reader.ReadMpi(requireCanonical: false, out int encodedLength);
            byte[] pointField = Mpi.ToFixedLengthUnsignedBytes(pointValue, encodedLength - 2);
            if (pointField.Length != 33 || pointField[0] != 0x40)
            {
                throw new FailClosedException("Malformed Ed25519 public key point (expected a 0x40-prefixed 33-byte native encoding).");
            }

            return new Ed25519PublicKey(pointField.AsSpan(1).ToArray(), legacy: true);
        }

        private static string DescribeUnverifiable(PublicKeyAlgorithm algorithm)
        {
            switch (algorithm)
            {
                case PublicKeyAlgorithm.Ecdsa:
                    return "ECDSA (unsupported curve)";
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
                    return "Unknown (" + ((byte)algorithm).ToString(System.Globalization.CultureInfo.InvariantCulture) + ")";
            }
        }
    }
}
