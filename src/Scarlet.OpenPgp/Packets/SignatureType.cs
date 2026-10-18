namespace Scarlet.OpenPgp.Packets
{
    /// <summary>Signature type IDs relevant to a verify-only library (RFC 9580 §5.2.1). Only the two document types are ever accepted for verifying content; the key-signature types are read only from the caller's own certificates, to learn which keys are valid, when, and for what.</summary>
    internal enum SignatureType : byte
    {
        /// <summary>Signature over an arbitrary binary document.</summary>
        BinaryDocument = 0x00,

        /// <summary>Signature over a text document with line endings canonicalized to CRLF. Used by clearsign and text-mode detached signatures.</summary>
        CanonicalTextDocument = 0x01,

        /// <summary>The first of the four User ID certification types (0x10-0x13).</summary>
        GenericCertification = 0x10,

        /// <summary>The last of the four User ID certification types (0x10-0x13).</summary>
        PositiveCertification = 0x13,

        /// <summary>Binds a subkey to its primary key; made by the primary key.</summary>
        SubkeyBinding = 0x18,

        /// <summary>The "back-signature" a signing subkey makes over its primary key, embedded in the subkey's binding signature.</summary>
        PrimaryKeyBinding = 0x19,

        /// <summary>Signature directly on a key, binding information (such as an expiration time) to it.</summary>
        DirectKey = 0x1F,

        /// <summary>Revokes the primary key.</summary>
        KeyRevocation = 0x20,

        /// <summary>Revokes a subkey.</summary>
        SubkeyRevocation = 0x28,

        /// <summary>Revokes earlier certifications over the same content: a User ID's certifications, or a Direct Key signature (RFC 9580 §5.2.1.14).</summary>
        CertificationRevocation = 0x30,
    }
}
