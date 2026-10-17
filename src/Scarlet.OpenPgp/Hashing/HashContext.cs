using System;
using System.Security.Cryptography;
using Scarlet.OpenPgp.Internal;

namespace Scarlet.OpenPgp.Hashing
{
    /// <summary>
    /// An incremental hash over one of the supported OpenPGP hash algorithms, so signed data can be
    /// streamed through once instead of being buffered. SHA2-256/384/512 are the platform's own;
    /// SHA2-224 and SHA3 (which the platform lacks) are this library's <see cref="Sha224"/> and <see cref="KeccakHash"/>.
    /// </summary>
    /// <remarks>
    /// Only SHA2-224/256/384/512 and SHA3-256/512 are supported. MD5, SHA-1 and RIPEMD-160 are broken or
    /// deprecated for signatures (RFC 9580 §9.5);
    /// anything else fails closed rather than silently proceeding.
    /// </remarks>
    internal sealed class HashContext : IDisposable
    {
        private readonly Action<byte[], int, int> _update;
        private readonly Func<byte[]> _finish;
        private readonly IDisposable? _disposable;

        private HashContext(HashAlgorithmId algorithm, Action<byte[], int, int> update, Func<byte[]> finish, IDisposable? disposable)
        {
            Algorithm = algorithm;
            _update = update;
            _finish = finish;
            _disposable = disposable;
        }

        private HashContext(HashAlgorithmId algorithm, IncrementalHash platform)
            : this(algorithm, platform.AppendData, platform.GetHashAndReset, platform)
        {
        }

        private HashContext(HashAlgorithmId algorithm, KeccakHash keccak)
            : this(algorithm, keccak.Update, keccak.Finish, null)
        {
        }

        private HashContext(HashAlgorithmId algorithm, Sha224 sha224)
            : this(algorithm, sha224.Update, sha224.Finish, null)
        {
        }

        public HashAlgorithmId Algorithm { get; }

        /// <param name="algorithm">The hash algorithm.</param>
        /// <param name="allowSha1">
        /// Accept SHA-1, for a key's own self-signatures only (binding, back-, direct-key and revocation
        /// signatures). Many real v4 certificates still carry SHA-1 self-signatures. SHA-1's practical
        /// break is collisions, which need the victim to sign attacker-chosen data; a self-signature is
        /// made by the key owner over their own key, so only second-preimage resistance matters there,
        /// and SHA-1 still has that. Document signatures never accept SHA-1. Each algorithm's own
        /// minimum hash size still applies (see SignatureVerifier.GetIncompatibility), so in practice
        /// this means RSA self-signatures; a SHA-1 EdDSA/ECDSA/DSA self-signature can't be checked,
        /// which makes the key unusable rather than unrestricted.
        /// </param>
        public static HashContext Create(HashAlgorithmId algorithm, bool allowSha1 = false)
        {
            switch (algorithm)
            {
                case HashAlgorithmId.Sha1 when allowSha1:
                    return new HashContext(algorithm, IncrementalHash.CreateHash(HashAlgorithmName.SHA1));
                case HashAlgorithmId.Sha224:
                    return new HashContext(algorithm, new Sha224());
                case HashAlgorithmId.Sha256:
                    return new HashContext(algorithm, IncrementalHash.CreateHash(HashAlgorithmName.SHA256));
                case HashAlgorithmId.Sha384:
                    return new HashContext(algorithm, IncrementalHash.CreateHash(HashAlgorithmName.SHA384));
                case HashAlgorithmId.Sha512:
                    return new HashContext(algorithm, IncrementalHash.CreateHash(HashAlgorithmName.SHA512));
                case HashAlgorithmId.Sha3_256:
                    return new HashContext(algorithm, KeccakHash.CreateSha3_256());
                case HashAlgorithmId.Sha3_512:
                    return new HashContext(algorithm, KeccakHash.CreateSha3_512());
                default:
                    throw FailClosedException.Unsupported("Unsupported hash algorithm: " + algorithm + ".");
            }
        }

        /// <summary>Whether <paramref name="algorithm"/> can be computed by <see cref="Create"/> for a document signature.</summary>
        public static bool IsSupported(HashAlgorithmId algorithm)
        {
            switch (algorithm)
            {
                case HashAlgorithmId.Sha224:
                case HashAlgorithmId.Sha256:
                case HashAlgorithmId.Sha384:
                case HashAlgorithmId.Sha512:
                case HashAlgorithmId.Sha3_256:
                case HashAlgorithmId.Sha3_512:
                    return true;
                default:
                    return false;
            }
        }

        /// <summary>The digest size in bits, used to enforce the per-algorithm minimum hash strength rules of RFC 9580 §5.2.3.</summary>
        public static int DigestBits(HashAlgorithmId algorithm)
        {
            switch (algorithm)
            {
                case HashAlgorithmId.Sha1:
                    return 160;
                case HashAlgorithmId.Sha224:
                    return 224;
                case HashAlgorithmId.Sha256:
                case HashAlgorithmId.Sha3_256:
                    return 256;
                case HashAlgorithmId.Sha384:
                    return 384;
                case HashAlgorithmId.Sha512:
                case HashAlgorithmId.Sha3_512:
                    return 512;
                default:
                    throw FailClosedException.Unsupported("Unsupported hash algorithm: " + algorithm + ".");
            }
        }

        /// <summary>The salt size a v6 signature must use with <paramref name="algorithm"/> (RFC 9580 Table 23).</summary>
        public static int V6SaltSize(HashAlgorithmId algorithm)
        {
            switch (algorithm)
            {
                case HashAlgorithmId.Sha256:
                case HashAlgorithmId.Sha224:
                case HashAlgorithmId.Sha3_256:
                    return 16;
                case HashAlgorithmId.Sha384:
                    return 24;
                case HashAlgorithmId.Sha512:
                case HashAlgorithmId.Sha3_512:
                    return 32;
                default:
                    throw FailClosedException.Unsupported("Hash algorithm " + algorithm + " cannot be used with a v6 signature.");
            }
        }

        public void Update(byte[] data) => Update(data, 0, data.Length);

        public void Update(byte[] data, int offset, int count) => _update(data, offset, count);

        public byte[] Finish() => _finish();

        public void Dispose() => _disposable?.Dispose();
    }
}
