namespace Scarlet.OpenPgp.Hashing
{
    /// <summary>Hash algorithm IDs (RFC 9580 §9.5). Only SHA2-224/256/384/512 and SHA3-256/512 are supported for verification - see <see cref="HashContext"/>; the rest are recognized only so unsupported-algorithm failures are clear rather than mysterious.</summary>
    internal enum HashAlgorithmId : byte
    {
        Md5 = 1,
        Sha1 = 2,
        Ripemd160 = 3,
        Sha256 = 8,
        Sha384 = 9,
        Sha512 = 10,
        Sha224 = 11,
        Sha3_256 = 12,
        Sha3_512 = 14,
    }
}
