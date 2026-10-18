using System.Text;

namespace Scarlet.OpenPgp.Cli;

/// <summary>
/// The CLI's testable composition seam. <see cref="Program.Main"/> is a thin wrapper around this
/// so tests can inject streams and writers instead of touching the real console. Stdout
/// stays clean (script-friendly) and carries only the verified signed text, as raw UTF-8; every
/// diagnostic goes to stderr, prefixed "Scarlet.OpenPgp: ", with control characters escaped.
/// </summary>
internal sealed class OpenPgpCliApplication
{
    private static readonly UTF8Encoding StrictUtf8 = new(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true);

    private readonly Stream _stdout;
    private readonly TextWriter _stderr;

    /// <param name="stdout">
    /// Where --output - writes the signed text: a byte stream, not a <see cref="TextWriter"/>. The
    /// console's writer encodes with the console code page even when redirected (437 on Windows),
    /// which turned fullwidth digits into ASCII ones and Cyrillic into "?" - output differing from
    /// what the signature covers.
    /// </param>
    /// <param name="stderr">Where diagnostics go.</param>
    public OpenPgpCliApplication(Stream stdout, TextWriter stderr)
    {
        _stdout = stdout;
        _stderr = stderr;
    }

    public int Run(string[] args)
    {
        if (args.Length == 1 && (args[0] == "--help" || args[0] == "-h"))
        {
            WriteUsage();
            return ExitCodes.Success;
        }

        if (!OpenPgpCliOptions.TryParse(args, out OpenPgpCliOptions? options, out string? parseError))
        {
            _stderr.WriteLine("Scarlet.OpenPgp: " + Escape(parseError));
            WriteUsage();
            return ExitCodes.UsageError;
        }

        try
        {
            return RunVerify(options);
        }
#pragma warning disable CA1031 // Do not catch general exception types: this is the process's last-resort handler.
        catch (Exception ex)
#pragma warning restore CA1031
        {
            // Last-resort safety net: anything that isn't one of the specific, expected
            // failure modes handled inside RunVerify (a bad input file, a failed/successful
            // verification) still gets a clean exit code and message instead of crashing the
            // process with a raw stack trace.
            _stderr.WriteLine("Scarlet.OpenPgp: unexpected error: " + Escape(ex.Message));
            return ExitCodes.UnexpectedError;
        }
    }

    private int RunVerify(OpenPgpCliOptions options)
    {
        // Keys and detached signatures may be armored or binary; the library tells them apart.
        byte[] publicKeys;
        byte[] signatureFileBytes;
        try
        {
            publicKeys = File.ReadAllBytes(options.KeyPath);
            signatureFileBytes = File.ReadAllBytes(options.SignaturePath);
        }
        catch (Exception ex) when (ex is IOException || ex is UnauthorizedAccessException)
        {
            _stderr.WriteLine("Scarlet.OpenPgp: could not read input file: " + Escape(ex.Message));
            return ExitCodes.InputError;
        }

        VerificationResult result;
        if (options.DataPath is not null)
        {
            try
            {
                // Streamed: release artifacts can be far larger than is sensible to hold in memory.
                using FileStream data = File.OpenRead(options.DataPath);
                result = OpenPgpVerifier.VerifyDetached(data, signatureFileBytes, publicKeys);
            }
            catch (Exception ex) when (ex is IOException || ex is UnauthorizedAccessException)
            {
                _stderr.WriteLine("Scarlet.OpenPgp: could not read input file: " + Escape(ex.Message));
                return ExitCodes.InputError;
            }
        }
        else
        {
            // Decode strictly: a lenient decoder would silently turn invalid UTF-8 into U+FFFD, so
            // different files could verify as the same signed text.
            string clearsignedMessage;
            try
            {
                clearsignedMessage = StrictUtf8.GetString(signatureFileBytes);
            }
            catch (DecoderFallbackException)
            {
                _stderr.WriteLine("Scarlet.OpenPgp: signature file is not valid UTF-8.");
                return ExitCodes.InputError;
            }

            result = OpenPgpVerifier.VerifyClearsign(clearsignedMessage, publicKeys);
        }

        if (!result.IsValid)
        {
            _stderr.WriteLine("Scarlet.OpenPgp: signature verification failed (" + result.Status + "): " + Escape(result.Message));
            if (result.SignerFingerprint is not null)
            {
                _stderr.WriteLine("Scarlet.OpenPgp: signing key " + result.SignerFingerprint);
            }

            return result.Status is VerificationStatus.MalformedInput or VerificationStatus.InvalidPublicKey
                ? ExitCodes.InputError
                : ExitCodes.VerificationFailed;
        }

        if (options.OutputPath is not null && result.SignedText is not null && !TryWriteSignedText(options.OutputPath, result.SignedText))
        {
            return ExitCodes.InputError;
        }

        _stderr.WriteLine("Scarlet.OpenPgp: signature verified.");
        _stderr.WriteLine("Scarlet.OpenPgp: signing key " + result.SignerFingerprint
                          + (result.SignerFingerprint == result.PrimaryKeyFingerprint ? string.Empty : " (subkey of " + result.PrimaryKeyFingerprint + ")"));
        _stderr.WriteLine("Scarlet.OpenPgp: signed " + result.SignatureCreationTime?.ToString("u", System.Globalization.CultureInfo.InvariantCulture));
        return ExitCodes.Success;
    }

    private bool TryWriteSignedText(string outputPath, string signedText)
    {
        if (outputPath == "-")
        {
            byte[] bytes = StrictUtf8.GetBytes(signedText);
            _stdout.Write(bytes, 0, bytes.Length);
            _stdout.Flush();
            return true;
        }

        try
        {
            File.WriteAllBytes(outputPath, StrictUtf8.GetBytes(signedText));
            return true;
        }
        catch (Exception ex) when (ex is IOException || ex is UnauthorizedAccessException)
        {
            _stderr.WriteLine("Scarlet.OpenPgp: could not write output file: " + Escape(ex.Message));
            return false;
        }
    }

    /// <summary>
    /// <paramref name="message"/> with control and formatting characters written as XXXX. Messages
    /// can quote the input (an armor line, a file name), and a terminal escape sequence printed raw
    /// could rewrite the screen - erase the failure and show "signature verified." instead.
    /// </summary>
    private static string Escape(string message)
    {
        var builder = new StringBuilder(message.Length);
        foreach (char c in message)
        {
            if (char.IsControl(c) || char.IsSurrogate(c) || System.Globalization.CharUnicodeInfo.GetUnicodeCategory(c) == System.Globalization.UnicodeCategory.Format)
            {
                builder.Append("\\u").Append(((int)c).ToString("X4", System.Globalization.CultureInfo.InvariantCulture));
            }
            else
            {
                builder.Append(c);
            }
        }

        return builder.ToString();
    }

    private void WriteUsage()
    {
        _stderr.WriteLine("Usage: scarlet-openpgp verify --key <pubkey.asc> --signature <file.asc|.sig> [--data <file> | --output <file|->]");
        _stderr.WriteLine();
        _stderr.WriteLine("  Verifies a detached signature when --data is given (--signature names the");
        _stderr.WriteLine("  detached signature, --data names the file it signs), or a self-contained");
        _stderr.WriteLine("  clearsigned message when --data is omitted (--signature names that message).");
        _stderr.WriteLine();
        _stderr.WriteLine("  --output (clearsign only) writes exactly the signed text, after successful");
        _stderr.WriteLine("  verification only, to a file or to stdout with \"-\". Consume that output,");
        _stderr.WriteLine("  not the original .asc file: only the signed text is authenticated.");
    }
}