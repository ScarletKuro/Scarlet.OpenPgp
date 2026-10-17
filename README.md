# Scarlet.OpenPgp

A pure C#, zero-dependency, verify-only OpenPGP (RFC 9580 / RFC 4880) implementation for .NET —
check clearsigned messages and detached signatures without shelling out to `gpg` or pulling in
BouncyCastle.

## Quick start

```csharp
VerificationResult result = OpenPgpVerifier.VerifyClearsign(clearsignedText, publicKeys);
if (result.IsValid)
{
    // Use result.SignedText from here on - never the original clearsignedText.
}
```

```bash
scarlet-openpgp verify --key pubkey.asc --signature release.sig --data release.tar.gz
```

## Scope

- Clearsigned messages and detached signatures (binary or text mode), ASCII-armored or binary.
- v4 and v6 keys and signatures: RSA, DSA, ECDSA (NIST and brainpool curves), Ed25519 (legacy and
  native) and Ed448.
- Signing subkeys, key flags, expiration and revocation are honored; keyrings with several
  certificates and signatures with several signers work.
- Verify-only: no signing, key generation, encryption, or trust management. The caller supplies
  exactly the public key(s) they already trust.

📖 Full docs: [src/Scarlet.OpenPgp/README.md](src/Scarlet.OpenPgp/README.md) ·
[src/Scarlet.OpenPgp.Cli/README.md](src/Scarlet.OpenPgp.Cli/README.md) ·
[fuzz/Scarlet.OpenPgp.Fuzz/README.md](fuzz/Scarlet.OpenPgp.Fuzz/README.md)

See [SPEC.md](SPEC.md) for the full design rationale and non-goals.
