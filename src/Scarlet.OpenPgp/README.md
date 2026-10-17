# Scarlet.OpenPgp

A pure C#, zero-dependency, verify-only OpenPGP (RFC 4880 v4) implementation.

```csharp
using Scarlet.OpenPgp;

bool ok = OpenPgpVerifier.VerifyClearsign(clearsignedText, publicKeyArmor, out string signedText);
// Use signedText from here on - never the original clearsignedText.

bool ok2 = OpenPgpVerifier.VerifyDetached(fileBytes, signatureArmor, publicKeyArmor);
```

Only use `signedText` from a clearsigned message. The input also contains unsigned text, such as
dash-escaping and the signature block's own armor headers, so reading data straight out of the
`.asc` file means trusting text nobody signed.

## Scope

- Ed25519 (EdDSA) and RSA-PKCS#1 v1.5 signatures, v4 keys.
- Clearsigned messages and detached signatures.
- No signing, key generation, encryption, or key management. Supply exactly the public key you
  already trust; this library does not decide whether to trust it.
- Time is checked too: a signature past its own expiration time, a signature older than its key,
  and a key past the expiration set by its most recent valid self-signature all fail. A key that
  has expired fails *now* even for signatures it made while still valid, the same policy as apt.
  Revocation is not checked.
- Zero external NuGet dependencies. Targets `netstandard2.0` for broad compatibility, plus
  `net10.0` so it can be properly AOT/trim-analyzed when consumed by an AOT-published app.

See the repository root [SPEC.md](../../SPEC.md) for the full design rationale, non-goals, and
testing requirements.
