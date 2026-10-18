using Scarlet.OpenPgp.Internal;

namespace Scarlet.OpenPgp.Verification
{
    /// <summary>
    /// The key-signature checking work one certificate may still cause - shared by every copy of
    /// that certificate in a key input, so repeating a certificate with small variations can't
    /// multiply the work a single certificate is allowed.
    /// </summary>
    /// <remarks>
    /// Work is counted in units of about one Ed25519 check (0.3 ms): each check costs its key's
    /// <see cref="Crypto.VerificationKey.CheckCost"/> plus the hashing of what it covers. Counting
    /// checks alone let a key that makes each one expensive (a 16384-bit RSA key with a large
    /// exponent: 75 ms a check) turn a 114 KiB key file into five minutes of work.
    /// </remarks>
    internal sealed class CheckBudget
    {
        /// <summary>
        /// The most work one certificate may need, across all its copies: about 2.5 s at worst.
        /// Real certificates need one check per self-signature, plus one per third-party
        /// certification that names no signed issuer - a few thousand Ed25519 or RSA-4096 checks fit.
        /// </summary>
        public const int MaxCost = 8192;

        /// <summary>How many hashed octets cost one unit: hashing measured about 160 MB/s, so 0.3 ms hashes 48 KiB; 32 KiB leaves a margin.</summary>
        public const int HashedBytesPerUnit = 32 * 1024;

        private long _spent;

        public void Spend(int cost)
        {
            _spent += cost;
            if (_spent > MaxCost)
            {
                throw new FailClosedException("The certificate needs too much signature checking; it is too large, repeated too often, flooded with signatures, or its key makes every check too expensive.");
            }
        }
    }
}
