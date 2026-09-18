namespace Scarlet.OpenPgp.Packets
{
    /// <summary>Public-key algorithm IDs (RFC 4880 §9.1 plus the EdDSA extension from draft-koch-eddsa-for-openpgp).</summary>
    internal enum PublicKeyAlgorithm : byte
    {
        RsaEncryptOrSign = 1,
        RsaSignOnly = 3,

        /// <summary>
        /// "EdDSALegacy" - the v4/GnuPG convention (draft-koch-eddsa-for-openpgp) this library
        /// targets, distinct from RFC 9580's v6-only algorithm ID 27 for native Ed25519.
        /// </summary>
        EdDsaLegacy = 22,
    }
}
