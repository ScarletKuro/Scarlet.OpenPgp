# Scarlet.OpenPgp.Cli

A NativeAOT-published command-line wrapper around [Scarlet.OpenPgp](../Scarlet.OpenPgp/README.md) -
a single small native binary, no .NET runtime required at the point of use.

```bash
scarlet-openpgp verify --key pubkey.asc --signature release.sig --data release.tar.gz
scarlet-openpgp verify --key pubkey.asc --signature release.asc   # self-contained clearsigned message
scarlet-openpgp verify --key pubkey.asc --signature SHASUMS256.txt.asc --output SHASUMS256.txt
```

`--data` is only needed for a detached signature; omit it when `--signature` names a self-contained
clearsigned message.

`--output <file>` (clearsign only; `-` for stdout) writes exactly the signed text, and only when
verification succeeds. Consume that output, never the original `.asc`: only the signed text is
authenticated. The `.asc` file itself must be valid UTF-8.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Signature verified |
| 1 | Signature did not verify |
| 64 | Usage error (bad command line) |
| 65 | An input file could not be read or parsed |
| 70 | Unexpected internal error |

All diagnostics go to stderr, prefixed `Scarlet.OpenPgp: `; stdout stays clean.

## Publishing

```bash
dotnet publish -r win-x64 -c Release    # or linux-x64, osx-arm64, etc.
```
