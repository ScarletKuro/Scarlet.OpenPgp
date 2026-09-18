namespace Scarlet.OpenPgp.Hashing
{
    /// <summary>Hash algorithm IDs (RFC 4880 §9.4). Only SHA-256/384/512 are actually supported for verification - see <see cref="OpenPgpHash"/>; the rest are recognized only so unsupported-algorithm failures are clear rather than mysterious.</summary>
    internal enum HashAlgorithmId : byte
    {
        Md5 = 1,
        Sha1 = 2,
        Ripemd160 = 3,
        Sha256 = 8,
        Sha384 = 9,
        Sha512 = 10,
        Sha224 = 11,
    }
}
