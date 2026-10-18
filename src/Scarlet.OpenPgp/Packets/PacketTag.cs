namespace Scarlet.OpenPgp.Packets
{
    /// <summary>Packet tag values (RFC 4880 §4.3). Only the tags this verify-only library acts on; any other is handled by its raw value.</summary>
    internal enum PacketTag : byte
    {
        Signature = 2,
        SecretKey = 5,
        PublicKey = 6,
        CompressedData = 8,
        SymmetricallyEncryptedData = 9,
        Marker = 10,
        LiteralData = 11,
        Trust = 12,
        UserId = 13,
        PublicSubkey = 14,
        UserAttribute = 17,
        SymmetricallyEncryptedIntegrityProtectedData = 18,
        Padding = 21,
    }
}
