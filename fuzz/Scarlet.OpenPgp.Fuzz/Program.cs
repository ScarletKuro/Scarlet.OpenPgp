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
    // Every fixture certificate, parsed once: signature and clearsign seeds from any fixture then
    // find their signer and reach the cryptographic checks (the data won't match theirs, but the
    // parsing and verification paths still run).
    // Not every *.gpg fixture is a key (Debian's Release.gpg is a signature), so keep the ones that parse.
    private static readonly OpenPgpKeyRing AllKeys = OpenPgpKeyRing.Parse(
        Directory.EnumerateFiles(Path.Combine(SeedDirectory, "keys"), "*.gpg", SearchOption.AllDirectories)
            .OrderBy(path => path, StringComparer.Ordinal)
            .Select(File.ReadAllBytes)
            .Where(bytes => OpenPgpKeyRing.TryParse(bytes, out _, out _))
            .SelectMany(bytes => bytes)
            .ToArray());

    private static readonly Dictionary<string, Action<ReadOnlySpan<byte>>> Targets = new(StringComparer.Ordinal)
    {
        ["signature"] = input => OpenPgpVerifier.VerifyDetached(Data, input, AllKeys),
        ["keys"] = input => OpenPgpVerifier.VerifyDetached(Data, Signature, input),
        ["clearsign"] = input => OpenPgpVerifier.VerifyClearsign(Encoding.UTF8.GetString(input), AllKeys),
        ["data"] = input =>
        {
            VerificationResult result = OpenPgpVerifier.VerifyDetached(input, Signature, AllKeys);
            if (result.IsValid && !input.SequenceEqual(Data))
            {
                throw new InvalidOperationException("Data that differs from the signed data verified.");
            }
        },

        // Differential: this library's verifier against BouncyCastle's on the same input.
        ["ed25519"] = Differential.Ed25519,
        ["ed448"] = Differential.Ed448,
        ["ecdsa-p256"] = Differential.EcdsaP256,
        ["rsa2048"] = Differential.Rsa2048,
    };

    private static int Main(string[] args)
    {
        // "seeds <target> <directory>": write a differential target's seed corpus (Wycheproof's valid vectors).
        if (args is ["seeds", var seedTarget, var seedDirectory])
        {
            Console.WriteLine("Wrote " + Differential.WriteSeeds(seedTarget, seedDirectory) + " seed(s) for '" + seedTarget + "'.");
            return 0;
        }

        // "selftest <target> <directory> <iterations>": random byte-level mutations of the inputs in
        // a directory, without libFuzzer - a quick local check that also runs on Windows.
        if (args is ["selftest", var testTarget, var testDirectory, var iterationText]
            && TryResolveTarget(testTarget, out Action<ReadOnlySpan<byte>>? selftest)
            && int.TryParse(iterationText, out int iterations))
        {
            byte[][] corpus = Directory.EnumerateFiles(testDirectory).OrderBy(p => p, StringComparer.Ordinal).Select(File.ReadAllBytes).ToArray();
            var random = new Random(9580);
            for (int i = 0; i < iterations; i++)
            {
                byte[] input = (byte[])corpus[random.Next(corpus.Length)].Clone();
                for (int flips = random.Next(1, 4); flips > 0 && input.Length > 0; flips--)
                {
                    input[random.Next(input.Length)] ^= (byte)(1 << random.Next(8));
                }

                selftest(input);
            }

            Console.WriteLine("Ran " + iterations + " mutated input(s) against '" + testTarget + "' without a failure.");
            return 0;
        }

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
