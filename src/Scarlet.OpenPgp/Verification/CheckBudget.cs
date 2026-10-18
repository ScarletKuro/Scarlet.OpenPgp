using Scarlet.OpenPgp.Internal;

namespace Scarlet.OpenPgp.Verification
{
    /// <summary>
    /// The key-signature checks one certificate may still spend - shared by every copy of that
    /// certificate in a key input, so repeating a certificate with small variations can't multiply
    /// the work a single certificate is allowed.
    /// </summary>
    internal sealed class CheckBudget
    {
        /// <summary>The most key-signature checks one certificate may need, across all its copies. Real certificates need one per self-signature, plus one per third-party certification that names no signed issuer.</summary>
        public const int MaxSignatureChecks = 4096;

        private int _spent;

        public void Spend()
        {
            if (++_spent > MaxSignatureChecks)
            {
                throw new FailClosedException("The certificate needs more than " + MaxSignatureChecks + " signature checks; it is too large, repeated too often, or flooded with signatures.");
            }
        }
    }
}
