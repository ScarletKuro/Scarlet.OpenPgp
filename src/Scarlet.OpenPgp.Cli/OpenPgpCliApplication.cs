using System;
using System.IO;

namespace Scarlet.OpenPgp.Cli
{
    /// <summary>
    /// The CLI's testable composition seam. <see cref="Program.Main"/> is a thin wrapper around this
    /// so tests can inject <see cref="TextWriter"/>s instead of touching the real console. Stdout
    /// stays clean (script-friendly); every diagnostic goes to stderr, prefixed "Scarlet.OpenPgp: ".
    /// </summary>
    internal sealed class OpenPgpCliApplication
    {
        private readonly TextWriter _stdout;
        private readonly TextWriter _stderr;

        public OpenPgpCliApplication(TextWriter stdout, TextWriter stderr)
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
                _stderr.WriteLine("Scarlet.OpenPgp: " + parseError);
                WriteUsage();
                return ExitCodes.UsageError;
            }

            try
            {
                return RunVerify(options!);
            }
            catch (Exception ex)
            {
                // Last-resort safety net: anything that isn't one of the specific, expected
                // failure modes handled inside RunVerify (a bad input file, a failed/successful
                // verification) still gets a clean exit code and message instead of crashing the
                // process with a raw stack trace.
                _stderr.WriteLine("Scarlet.OpenPgp: unexpected error: " + ex.Message);
                return ExitCodes.UnexpectedError;
            }
        }

        private int RunVerify(OpenPgpCliOptions options)
        {
            string publicKeyArmor;
            string signatureArmorOrClearsignedMessage;
            try
            {
                publicKeyArmor = File.ReadAllText(options.KeyPath);
                signatureArmorOrClearsignedMessage = File.ReadAllText(options.SignaturePath);
            }
            catch (Exception ex) when (ex is IOException || ex is UnauthorizedAccessException)
            {
                _stderr.WriteLine("Scarlet.OpenPgp: could not read input file: " + ex.Message);
                return ExitCodes.InputError;
            }

            bool verified;
            if (options.DataPath is not null)
            {
                byte[] data;
                try
                {
                    data = File.ReadAllBytes(options.DataPath);
                }
                catch (Exception ex) when (ex is IOException || ex is UnauthorizedAccessException)
                {
                    _stderr.WriteLine("Scarlet.OpenPgp: could not read input file: " + ex.Message);
                    return ExitCodes.InputError;
                }

                verified = OpenPgpVerifier.VerifyDetached(data, signatureArmorOrClearsignedMessage, publicKeyArmor);
            }
            else
            {
                verified = OpenPgpVerifier.VerifyClearsign(signatureArmorOrClearsignedMessage, publicKeyArmor);
            }

            if (verified)
            {
                _stderr.WriteLine("Scarlet.OpenPgp: signature verified.");
                return ExitCodes.Success;
            }

            _stderr.WriteLine("Scarlet.OpenPgp: signature verification failed.");
            return ExitCodes.VerificationFailed;
        }

        private void WriteUsage()
        {
            _stderr.WriteLine("Usage: scarlet-openpgp verify --key <pubkey.asc> --signature <file.asc|.sig> [--data <file>]");
            _stderr.WriteLine();
            _stderr.WriteLine("  Verifies a detached signature when --data is given (--signature names the");
            _stderr.WriteLine("  detached signature, --data names the file it signs), or a self-contained");
            _stderr.WriteLine("  clearsigned message when --data is omitted (--signature names that message).");
        }
    }
}
