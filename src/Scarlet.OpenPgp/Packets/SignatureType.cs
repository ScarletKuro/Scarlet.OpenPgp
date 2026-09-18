namespace Scarlet.OpenPgp.Packets
{
    /// <summary>Signature type values relevant to a verify-only library (RFC 4880 §5.2.1). Only the two document-signing types are ever accepted for verification.</summary>
    internal enum SignatureType : byte
    {
        /// <summary>Signature over an arbitrary binary document. Used for detached signatures.</summary>
        BinaryDocument = 0x00,

        /// <summary>Signature over a document after its text has been canonicalized. Used by clearsign.</summary>
        CanonicalTextDocument = 0x01,
    }
}
