# Scarlet.OpenPgp.Fuzz

Coverage-guided fuzzing of the public API with [SharpFuzz](https://github.com/Metalnem/sharpfuzz)
and libFuzzer. Each target feeds the fuzzer's bytes to one attacker-facing input and keeps the rest
fixed (`Seeds/`: a two-signer detached signature and its keyring):

| `SCARLET_FUZZ_TARGET` | Fuzzed input | Invariant |
|---|---|---|
| `signature` | detached signature (armored or binary) | never throws |
| `keys` | public key input (armored or binary) | never throws |
| `clearsign` | whole clearsigned message | never throws |
| `data` | the signed data | never throws; altered data never verifies |

CI runs every target weekly, on demand (`.github/workflows/fuzz.yml`), and for a few minutes on
pull requests.

## Running locally (Linux)

```bash
dotnet tool install --global SharpFuzz.CommandLine --version 2.3.0
# libfuzzer-dotnet: https://github.com/Metalnem/libfuzzer-dotnet/releases
dotnet publish fuzz/Scarlet.OpenPgp.Fuzz -c Release -o out/fuzz
sharpfuzz out/fuzz/Scarlet.OpenPgp.dll
SCARLET_FUZZ_TARGET=signature ./libfuzzer-dotnet --target_path=dotnet --target_arg=out/fuzz/Scarlet.OpenPgp.Fuzz.dll corpus/
```

## Reproducing a crash

No libFuzzer needed:

```bash
dotnet run --project fuzz/Scarlet.OpenPgp.Fuzz -c Release -- replay <target> <crash-file-or-directory>
```

The in-suite counterpart is `tests/Scarlet.OpenPgp.Tests/Fuzzing/MutationFuzzTests.cs`, a
deterministic mutation fuzzer that runs with every test run (scale it with
`SCARLET_FUZZ_ITERATIONS`).
