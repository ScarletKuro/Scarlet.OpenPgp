using System;

namespace Scarlet.OpenPgp.Internal
{
    /// <summary>
    /// Thrown internally whenever input is malformed, ambiguous, or contains unknown-but-critical
    /// data. Never allowed to escape the library's public surface: <see cref="OpenPgpVerifier"/>
    /// catches it at the boundary and converts it into a failed verification result, per the
    /// "fail closed, never crash on attacker-controlled input" non-negotiable in SPEC.md.
    /// </summary>
    internal sealed class FailClosedException : Exception
    {
        public FailClosedException(string message) : base(message)
        {
        }

        public FailClosedException(string message, Exception innerException) : base(message, innerException)
        {
        }
    }
}
