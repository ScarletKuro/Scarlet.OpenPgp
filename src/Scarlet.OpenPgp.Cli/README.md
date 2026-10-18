# Scarlet.OpenPgp.Cli

Verify OpenPGP signatures from the command line: detached or clearsigned, against keys you supply.
A .NET tool built on [Scarlet.OpenPgp](https://github.com/ScarletKuro/Scarlet.OpenPgp), compiled
with Native AOT, so it starts instantly, for Windows and Linux (glibc and musl) on x64 and arm64
and for Apple silicon Macs.

## Install

```bash
dotnet tool install -g Scarlet.OpenPgp.Cli
scarlet-openpgp --help

# or run it once without installing
dnx Scarlet.OpenPgp.Cli verify --key pubkey.asc --signature release.sig --data release.tar.gz
```

Requires the .NET 10 SDK to install. The Native AOT builds need no .NET runtime to run; other
platforms (Intel Macs, FreeBSD, 32-bit ARM, ...) get a build that runs on the .NET 10 runtime.

## Usage

```bash
scarlet-openpgp verify --key pubkey.asc --signature release.sig --data release.tar.gz
scarlet-openpgp verify --key pubkey.asc --signature release.asc   # self-contained clearsigned message
scarlet-openpgp verify --key pubkey.asc --signature SHASUMS256.txt.asc --output SHASUMS256.txt
```

`--data` is only needed for a detached signature; omit it when `--signature` names a self-contained
clearsigned message. The data file is streamed, so large artifacts are fine. `--key` and a detached
`--signature` may be ASCII-armored (`.asc`) or binary (`.gpg`, `.sig`), and `--key` may hold several
certificates (a keyring). Verification uses the current time.

`--output <file>` (clearsign only; `-` for stdout) writes exactly the signed text as UTF-8, and only
when verification succeeds. Consume that output, never the original `.asc`: only the signed text is
authenticated. The `.asc` file itself must be valid UTF-8. `--output -` writes the bytes straight to
stdout, so the console's code page can't change the text.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Signature verified |
| 1 | Signature did not verify (bad signature, unknown signer, expired or revoked key, ...) |
| 64 | Usage error (bad command line) |
| 65 | An input file could not be read, is not well-formed OpenPGP (including unsigned text around a clearsigned message), holds no usable key, or exceeds the input limits |
| 70 | Unexpected internal error |

All diagnostics go to stderr, prefixed `Scarlet.OpenPgp: `: on success the signing key's fingerprint
(and its primary key's, for a subkey) and the signature time; on failure the reason. Control
characters from the input are escaped (`\u001B`), so a hostile file can't rewrite the terminal.
Stdout stays clean except for `--output -`.

## Scope and security

Verify-only: no signing, encryption, keyservers or trust management - you decide which keys to trust
by passing them. See the [security policy](https://github.com/ScarletKuro/Scarlet.OpenPgp/blob/master/SECURITY.md)
for what it is tested against and how to report a vulnerability.
