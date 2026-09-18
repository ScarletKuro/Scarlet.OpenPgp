# Scarlet.OpenPgp

A pure C#, zero-dependency, verify-only OpenPGP (RFC 4880) implementation for .NET — check
clearsigned messages and detached signatures without shelling out to `gpg` or pulling in
BouncyCastle.

## Quick start

```csharp
bool ok = OpenPgpVerifier.VerifyClearsign(clearsignedText, publicKeyArmor);
```

```bash
scarlet-openpgp verify --key pubkey.asc --signature release.sig --data release.tar.gz
```

## Scope

- Verifies clearsigned messages and detached signatures.
- Supports Ed25519 (EdDSA) and RSA-PKCS#1 v1.5, OpenPGP v4 keys/signatures.
- Verify-only: no signing, key generation, encryption, or key management. The caller supplies
  exactly the public key(s) they already trust.

📖 Full docs: [src/Scarlet.OpenPgp/README.md](src/Scarlet.OpenPgp/README.md) ·
[src/Scarlet.OpenPgp.Cli/README.md](src/Scarlet.OpenPgp.Cli/README.md)

See [SPEC.md](SPEC.md) for the full design rationale and non-goals.
