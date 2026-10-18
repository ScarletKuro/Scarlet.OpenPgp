# Scarlet.OpenPgp.Fuzz

Coverage-guided fuzzing with [SharpFuzz](https://github.com/Metalnem/sharpfuzz) and libFuzzer, in
two kinds of target.

**Public API targets** feed the fuzzer's bytes to one attacker-facing input and keep the rest fixed
(`Seeds/`: a two-signer detached signature and its keyring):

| `SCARLET_FUZZ_TARGET` | Fuzzed input | Invariant |
|---|---|---|
| `signature` | detached signature (armored or binary) | never throws |
| `keys` | public key input (armored or binary) | never throws |
| `clearsign` | whole clearsigned message | never throws |
| `data` | the signed data | never throws; altered data never verifies |

**Differential targets** (`Differential.cs`) give the same key, signature and message to this
library's verifier and to BouncyCastle's, and fail on any disagreement. They are seeded with
Wycheproof's valid vectors, so the fuzzer works on near-valid signatures - where a verifier that
accepts a forgery, or rejects a genuine signature, shows up.

| `SCARLET_FUZZ_TARGET` | Input layout | Fails when |
|---|---|---|
| `ed25519` | public key (32) · signature (64) · message | the verifiers disagree (except a small-order key, which only this library rejects) |
| `ed448` | public key (57) · signature (114) · message | the verifiers disagree (same exception) |
| `ecdsa-p256` | SEC 1 point (65) · r (32) · s (32) · digest | the verifiers disagree (except a point not in uncompressed form, which only this library rejects) |
| `rsa2048` | signature (256) · message, under a fixed Wycheproof key, SHA-256 | this library accepts what BouncyCastle rejects (BouncyCastle is more lenient about the DigestInfo encoding, so only that direction counts) |

CI runs every target weekly, on demand (`.github/workflows/fuzz.yml`), and for a few minutes on
pull requests.

## Running locally (Linux)

```bash
dotnet tool install --global SharpFuzz.CommandLine --version 2.3.0
# libfuzzer-dotnet: https://github.com/Metalnem/libfuzzer-dotnet/releases
dotnet publish fuzz/Scarlet.OpenPgp.Fuzz -c Release -o out/fuzz
dotnet out/fuzz/Scarlet.OpenPgp.Fuzz.dll seeds ed25519 corpus/   # differential targets only; others seed from TestAssets
sharpfuzz out/fuzz/Scarlet.OpenPgp.dll
SCARLET_FUZZ_TARGET=ed25519 ./libfuzzer-dotnet --target_path=dotnet --target_arg=out/fuzz/Scarlet.OpenPgp.Fuzz.dll corpus/
```

## Without libFuzzer (any OS)

```bash
# Reproduce a crash, or replay a corpus:
dotnet run --project fuzz/Scarlet.OpenPgp.Fuzz -c Release -- replay <target> <crash-file-or-directory>
# Random bit flips over a corpus - a quick local check:
dotnet run --project fuzz/Scarlet.OpenPgp.Fuzz -c Release -- selftest <target> <corpus-directory> <iterations>
```

The in-suite counterpart is `tests/Scarlet.OpenPgp.Tests/Fuzzing/MutationFuzzTests.cs`, a
deterministic mutation fuzzer that runs with every test run (scale it with
`SCARLET_FUZZ_ITERATIONS`).
