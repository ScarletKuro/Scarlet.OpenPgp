namespace Scarlet.OpenPgp.Packets
{
    /// <summary>Packet tag values (RFC 4880 §4.3). Only a subset is meaningful to a verify-only library.</summary>
    internal enum PacketTag : byte
    {
        PublicKeyEncryptedSessionKey = 1,
        Signature = 2,
        SymmetricKeyEncryptedSessionKey = 3,
        OnePassSignature = 4,
        SecretKey = 5,
        PublicKey = 6,
        SecretSubkey = 7,
        CompressedData = 8,
        SymmetricallyEncryptedData = 9,
        Marker = 10,
        LiteralData = 11,
        Trust = 12,
        UserId = 13,
        PublicSubkey = 14,
        UserAttribute = 17,
        SymmetricallyEncryptedIntegrityProtectedData = 18,
        ModificationDetectionCode = 19,
        Padding = 21,
    }
}
