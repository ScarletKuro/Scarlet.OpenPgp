namespace Scarlet.OpenPgp.Packets
{
    /// <summary>Signature subpacket type values (RFC 9580 §5.2.3.7). The ones with a meaning for verification are read; the purely informational ones are listed so that a critical instance of them is not mistaken for an unknown critical subpacket.</summary>
    internal enum SignatureSubpacketType : byte
    {
        SignatureCreationTime = 2,
        SignatureExpirationTime = 3,
        ExportableCertification = 4,
        TrustSignature = 5,
        RegularExpression = 6,
        Revocable = 7,
        KeyExpirationTime = 9,
        PreferredSymmetricCiphers = 11,
        RevocationKey = 12,
        IssuerKeyId = 16,
        NotationData = 20,
        PreferredHashAlgorithms = 21,
        PreferredCompressionAlgorithms = 22,
        KeyServerPreferences = 23,
        PreferredKeyServer = 24,
        PrimaryUserId = 25,
        PolicyUri = 26,
        KeyFlags = 27,
        SignersUserId = 28,
        ReasonForRevocation = 29,
        Features = 30,
        SignatureTarget = 31,
        EmbeddedSignature = 32,
        IssuerFingerprint = 33,
        PreferredAeadAlgorithms = 34,
        IntendedRecipientFingerprint = 35,
        PreferredAeadCiphersuites = 39,
    }
}
