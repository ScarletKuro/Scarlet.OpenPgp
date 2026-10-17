namespace Scarlet.OpenPgp.Cli;

/// <summary>
/// Process exit codes for the <c>scarlet-openpgp</c> CLI. The usage-error/success values follow
/// common shell conventions (BSD <c>sysexits.h</c>-style: 64 = usage error) so scripts can react
/// sensibly without knowing anything about this tool specifically. <see cref="VerificationFailed"/>
/// is deliberately distinct from <see cref="InputError"/>: "the signature does not verify" is a
/// normal, expected outcome for a verification tool, not an error condition.
/// </summary>
internal static class ExitCodes
{
    /// <summary>The signature verified successfully.</summary>
    public const int Success = 0;

    /// <summary>Everything parsed fine, but the signature did not verify.</summary>
    public const int VerificationFailed = 1;

    /// <summary>The command line itself was not understood (missing/unknown flags).</summary>
    public const int UsageError = 64;

    /// <summary>A named file could not be read, or was not parseable OpenPGP/armor at all.</summary>
    public const int InputError = 65;

    /// <summary>Anything else unhandled internally. Should be rare - most failures map above.</summary>
    public const int UnexpectedError = 70;
}