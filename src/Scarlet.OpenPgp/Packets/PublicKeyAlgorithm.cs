namespace Scarlet.OpenPgp.Packets
{
    /// <summary>Public-key algorithm IDs (RFC 9580 §9.1). The signing algorithms here are verifiable; the encryption-only ones are recognized so a certificate's encryption subkeys can be skipped rather than rejected.</summary>
    internal enum PublicKeyAlgorithm : byte
    {
        RsaEncryptOrSign = 1,
        RsaEncryptOnly = 2,
        RsaSignOnly = 3,
        ElGamalEncryptOnly = 16,
        Dsa = 17,
        Ecdh = 18,
        Ecdsa = 19,

        /// <summary>
        /// "EdDSALegacy" - the v4/GnuPG convention (draft-koch-eddsa-for-openpgp, RFC 9580
        /// §5.5.5.5), with Ed25519 identified by a curve OID and values wrapped in MPIs. Not allowed
        /// with v6 keys or signatures.
        /// </summary>
        EdDsaLegacy = 22,

        X25519 = 25,
        X448 = 26,

        /// <summary>Native Ed25519 (RFC 9580 §5.5.5.9): a raw 32-octet public key and 64-octet signature.</summary>
        Ed25519 = 27,

        /// <summary>Native Ed448 (RFC 9580 §5.5.5.10): a raw 57-octet public key and 114-octet signature.</summary>
        Ed448 = 28,
    }
}
