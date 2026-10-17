using Scarlet.OpenPgp.Hashing;
using Scarlet.OpenPgp.Internal;

namespace Scarlet.OpenPgp.Crypto.Rsa
{
    /// <summary>
    /// The DER encoding of the ASN.1 DigestInfo SEQUENCE header (algorithm OID + parameters +
    /// digest length octet) that precedes the raw hash in an RSA PKCS#1 v1.5 signature (RFC 8017
    /// §9.2 step 2). These are the standard, widely-published prefixes for SHA-256/384/512.
    /// </summary>
    internal static class DigestInfoPrefixes
    {
        private static readonly byte[] Sha256 =
        {
            0x30, 0x31, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
            0x00, 0x04, 0x20,
        };

        private static readonly byte[] Sha384 =
        {
            0x30, 0x41, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05,
            0x00, 0x04, 0x30,
        };

        private static readonly byte[] Sha512 =
        {
            0x30, 0x51, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05,
            0x00, 0x04, 0x40,
        };

        // SHA3-256 and SHA3-512: the same structure with OIDs 2.16.840.1.101.3.4.2.8 and .10
        // (RFC 9580 Table 24).
        private static readonly byte[] Sha3_256 =
        {
            0x30, 0x31, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x08, 0x05,
            0x00, 0x04, 0x20,
        };

        private static readonly byte[] Sha3_512 =
        {
            0x30, 0x51, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0A, 0x05,
            0x00, 0x04, 0x40,
        };

        public static byte[] Get(HashAlgorithmId algorithm)
        {
            switch (algorithm)
            {
                case HashAlgorithmId.Sha256:
                    return Sha256;
                case HashAlgorithmId.Sha384:
                    return Sha384;
                case HashAlgorithmId.Sha512:
                    return Sha512;
                case HashAlgorithmId.Sha3_256:
                    return Sha3_256;
                case HashAlgorithmId.Sha3_512:
                    return Sha3_512;
                default:
                    throw new FailClosedException("Unsupported hash algorithm for RSA-PKCS#1 v1.5: " + algorithm + ".");
            }
        }
    }
}
