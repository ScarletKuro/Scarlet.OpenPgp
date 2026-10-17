namespace Scarlet.OpenPgp.Packets
{
    /// <summary>Signature type values relevant to a verify-only library (RFC 4880 §5.2.1). Only the two document-signing types are ever accepted for verifying content; the key-signature types are read only from the caller's own key block, to learn the key's expiration time.</summary>
    internal enum SignatureType : byte
    {
        /// <summary>Signature over an arbitrary binary document. Used for detached signatures.</summary>
        BinaryDocument = 0x00,

        /// <summary>Signature over a document after its text has been canonicalized. Used by clearsign.</summary>
        CanonicalTextDocument = 0x01,

        /// <summary>The first of the four User ID certification types (0x10-0x13).</summary>
        GenericCertification = 0x10,

        /// <summary>The last of the four User ID certification types (0x10-0x13).</summary>
        PositiveCertification = 0x13,

        /// <summary>Signature directly on a key, binding information (such as an expiration time) to it.</summary>
        DirectKey = 0x1F,
    }
}
