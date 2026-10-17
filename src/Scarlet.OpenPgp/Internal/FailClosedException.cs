using System;

namespace Scarlet.OpenPgp.Internal
{
    /// <summary>
    /// Thrown internally whenever input is malformed, ambiguous, or contains unknown-but-critical
    /// data. Never allowed to escape the library's public surface: <see cref="OpenPgpVerifier"/>
    /// catches it at the boundary and converts it into a failed verification result, per the
    /// "fail closed, never crash on attacker-controlled input" non-negotiable in SPEC.md.
    /// </summary>
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Design", "CA1064:Exceptions should be public", Justification = "Never escapes the library: OpenPgpVerifier turns it into a VerificationResult.")]
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Design", "CA1032:Implement standard exception constructors", Justification = "Internal; every throw site supplies a message.")]
    internal sealed class FailClosedException : Exception
    {
        public FailClosedException(string message) : base(message)
        {
        }

        public FailClosedException(string message, Exception innerException) : base(message, innerException)
        {
        }

        /// <summary>The input is well-formed but uses a version, algorithm, or feature this library doesn't support (as opposed to being malformed).</summary>
        public bool IsUnsupported { get; private set; }

        public static FailClosedException Unsupported(string message) => new FailClosedException(message) { IsUnsupported = true };
    }
}
