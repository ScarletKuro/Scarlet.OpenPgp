# Scarlet.OpenPgp

A pure C#, zero-dependency, verify-only OpenPGP (RFC 4880 v4) implementation.

```csharp
using Scarlet.OpenPgp;

bool ok = OpenPgpVerifier.VerifyClearsign(clearsignedText, publicKeyArmor);

bool ok2 = OpenPgpVerifier.VerifyDetached(fileBytes, signatureArmor, publicKeyArmor);
```

## Scope

- Ed25519 (EdDSA) and RSA-PKCS#1 v1.5 signatures, v4 keys.
- Clearsigned messages and detached signatures.
- No signing, key generation, encryption, or key management. Supply exactly the public key you
  already trust; this library does not decide whether to trust it.
- Zero external NuGet dependencies. Targets `netstandard2.0` for broad compatibility, plus
  `net10.0` so it can be properly AOT/trim-analyzed when consumed by an AOT-published app.

See the repository root [SPEC.md](../../SPEC.md) for the full design rationale, non-goals, and
testing requirements.
