namespace Scarlet.OpenPgp.Packets
{
    /// <summary>Signature subpacket type values this library recognizes (RFC 4880 §5.2.3.1). Anything else is either safely skippable or, if critical, a fail-closed error.</summary>
    internal enum SignatureSubpacketType : byte
    {
        SignatureCreationTime = 2,
        SignatureExpirationTime = 3,
        KeyExpirationTime = 9,
        IssuerKeyId = 16,
        IssuerFingerprint = 33,
    }
}
