namespace Scarlet.OpenPgp.Cli
{
    /// <summary>Parsed command-line options for the <c>verify</c> subcommand. Manual parsing, matching the tiny surface of this tool - no argument-parsing package is warranted for one subcommand and three flags.</summary>
    internal sealed class OpenPgpCliOptions
    {
        private OpenPgpCliOptions(string keyPath, string signaturePath, string? dataPath)
        {
            KeyPath = keyPath;
            SignaturePath = signaturePath;
            DataPath = dataPath;
        }

        public string KeyPath { get; }

        public string SignaturePath { get; }

        /// <summary>When present, verify a detached signature over this file. When absent, <see cref="SignaturePath"/> names a self-contained clearsigned message.</summary>
        public string? DataPath { get; }

        public static bool TryParse(string[] args, out OpenPgpCliOptions? options, out string? error)
        {
            options = null;
            error = null;

            if (args.Length == 0)
            {
                error = "no command given";
                return false;
            }

            if (args[0] != "verify")
            {
                error = "unknown command \"" + args[0] + "\" (expected \"verify\")";
                return false;
            }

            string? key = null;
            string? signature = null;
            string? data = null;

            for (int i = 1; i < args.Length; i++)
            {
                switch (args[i])
                {
                    case "--key":
                        if (++i >= args.Length)
                        {
                            error = "--key requires a path argument";
                            return false;
                        }

                        key = args[i];
                        break;

                    case "--signature":
                        if (++i >= args.Length)
                        {
                            error = "--signature requires a path argument";
                            return false;
                        }

                        signature = args[i];
                        break;

                    case "--data":
                        if (++i >= args.Length)
                        {
                            error = "--data requires a path argument";
                            return false;
                        }

                        data = args[i];
                        break;

                    default:
                        error = "unknown argument \"" + args[i] + "\"";
                        return false;
                }
            }

            if (key is null)
            {
                error = "missing required --key <path>";
                return false;
            }

            if (signature is null)
            {
                error = "missing required --signature <path>";
                return false;
            }

            options = new OpenPgpCliOptions(key, signature, data);
            return true;
        }
    }
}
