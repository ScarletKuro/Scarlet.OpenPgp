using System.Diagnostics.CodeAnalysis;
using System.Text;
using SharpFuzz;

namespace Scarlet.OpenPgp.Fuzz;

/// <summary>
/// libFuzzer entry point. Each target feeds the fuzzer's input to one of the public API's
/// attacker-facing inputs while keeping the others fixed, and turns any violated invariant into an
/// exception - which libFuzzer reports as a crash and saves as a reproducer.
/// </summary>
/// <remarks>
/// Invariants: the public API never throws (every malformed input must come back as a failed
/// <see cref="VerificationResult"/>), and data that differs from what was signed never verifies.
/// The target is chosen with the SCARLET_FUZZ_TARGET environment variable, because
/// libfuzzer-dotnet passes the harness only a single argument.
/// </remarks>
internal static class Program
{
    private static readonly string SeedDirectory = Path.Combine(AppContext.BaseDirectory, "Seeds");
    private static readonly byte[] Data = File.ReadAllBytes(Path.Combine(SeedDirectory, "data.txt"));
    private static readonly byte[] Signature = File.ReadAllBytes(Path.Combine(SeedDirectory, "data.txt.sig"));
    private static readonly byte[] Keys = File.ReadAllBytes(Path.Combine(SeedDirectory, "keyring-both.gpg"));

    private static readonly Dictionary<string, Action<ReadOnlySpan<byte>>> Targets = new(StringComparer.Ordinal)
    {
        ["signature"] = input => OpenPgpVerifier.VerifyDetached(Data, input, Keys),
        ["keys"] = input => OpenPgpVerifier.VerifyDetached(Data, Signature, input),
        ["clearsign"] = input => OpenPgpVerifier.VerifyClearsign(Encoding.UTF8.GetString(input), Keys),
        ["data"] = input =>
        {
            VerificationResult result = OpenPgpVerifier.VerifyDetached(input, Signature, Keys);
            if (result.IsValid && !input.SequenceEqual(Data))
            {
                throw new InvalidOperationException("Data that differs from the signed data verified.");
            }
        },
    };

    private static int Main(string[] args)
    {
        // "replay <target> <file-or-directory>...": run inputs directly, without libFuzzer - to
        // reproduce a crash, or to smoke-test the harness against a corpus.
        if (args is ["replay", _, ..])
        {
            if (!TryResolveTarget(args[1], out Action<ReadOnlySpan<byte>>? replayTarget))
            {
                return 64;
            }

            int count = 0;
            foreach (string path in args.Skip(2).SelectMany(p => Directory.Exists(p) ? Directory.EnumerateFiles(p, "*", SearchOption.AllDirectories) : [p]))
            {
                replayTarget(File.ReadAllBytes(path));
                count++;
            }

            Console.WriteLine("Replayed " + count + " input(s) against '" + args[1] + "' without a failure.");
            return 0;
        }

        if (!TryResolveTarget(Environment.GetEnvironmentVariable("SCARLET_FUZZ_TARGET") ?? string.Empty, out Action<ReadOnlySpan<byte>>? target))
        {
            return 64;
        }

        Fuzzer.LibFuzzer.Run(span => target(span));
        return 0;
    }

    private static bool TryResolveTarget(string name, [NotNullWhen(true)] out Action<ReadOnlySpan<byte>>? target)
    {
        if (Targets.TryGetValue(name, out target))
        {
            return true;
        }

        Console.Error.WriteLine("Unknown fuzz target '" + name + "'. Expected one of: " + string.Join(", ", Targets.Keys) + ".");
        return false;
    }
}
