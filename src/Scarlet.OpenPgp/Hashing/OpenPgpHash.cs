using System.Security.Cryptography;
using Scarlet.OpenPgp.Internal;

namespace Scarlet.OpenPgp.Hashing
{
    /// <summary>Dispatches to the concrete hash implementation for a given OpenPGP hash algorithm ID. Only SHA-256/384/512 are supported (RFC 4880 §9.4 lists more, but SPEC.md scopes this library to those three); anything else fails closed rather than silently proceeding with a weaker algorithm.</summary>
    internal static class OpenPgpHash
    {
        public static byte[] ComputeHash(HashAlgorithmId algorithm, byte[] data)
        {
            switch (algorithm)
            {
                case HashAlgorithmId.Sha256:
                    using (SHA256 sha256 = SHA256.Create())
                    {
                        return sha256.ComputeHash(data);
                    }

                case HashAlgorithmId.Sha384:
                    using (SHA384 sha384 = SHA384.Create())
                    {
                        return sha384.ComputeHash(data);
                    }

                case HashAlgorithmId.Sha512:
                    using (SHA512 sha512 = SHA512.Create())
                    {
                        return sha512.ComputeHash(data);
                    }

                default:
                    throw new FailClosedException("Unsupported hash algorithm: " + algorithm + ".");
            }
        }
    }
}
