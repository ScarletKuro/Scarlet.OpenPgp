# Security policy

## Reporting a vulnerability

Please report vulnerabilities privately through GitHub:
**Security → Report a vulnerability** on
[ScarletKuro/Scarlet.OpenPgp](https://github.com/ScarletKuro/Scarlet.OpenPgp/security/advisories/new).
Don't open a public issue for anything that could change a verification verdict.

Include the inputs (key, signature, data) that reproduce the problem, the verdict you got, and
the one you expected. Inputs can be attached to the advisory; they stay private.

## Supported versions

Only the latest release receives security fixes.

## What counts as a vulnerability

Scarlet.OpenPgp verifies signatures against public keys the caller already trusts. Anything that
makes it give the wrong answer for those inputs is in scope, in particular:

- **A wrong "valid" verdict:** a forged or altered signature, data or text that verifies; a
  signature accepted from a key that is revoked, expired, not bound to the certificate, or not
  allowed to sign; a signature accepted from a key the caller didn't supply.
- **A restriction that can be removed:** changing unsigned parts of a certificate (unhashed
  subpackets, packet order, framing, the quick-check bytes, packet re-encoding) so that a
  revocation, expiration or key-flag restriction no longer applies.
- **Clearsigned text confusion:** `SignedText` (or the CLI's output) differing from what the
  signature actually covers.
- **Resource exhaustion:** an input that crashes the process, hangs, or uses memory or time out
  of proportion to its size, beyond the documented limits.

Out of scope:

- Which keys to trust. The library never decides that; the caller supplies the keys.
- Timing side channels. Verification only handles public data: public keys, signatures and
  signed content.
- A key that is rejected when it should be accepted (fail closed). Please still report it as a
  normal issue if it affects a real-world key.

## Assurance

The library hasn't had an independent security audit. What it has:

- Hand-written regression tests for every finding from code reviews, each confirmed to fail on
  the code before the fix.
- All [Wycheproof](https://github.com/C2SP/wycheproof) vectors for the supported algorithms,
  run in CI.
- Interoperability fixtures from GnuPG, OpenPGP.js (v6) and BouncyCastle, plus real release
  signatures (Debian, Node.js, Tor Browser, Bun).
- Mutation fuzzing in CI, and differential fuzzing against BouncyCastle
  ([fuzz/Scarlet.OpenPgp.Fuzz](fuzz/Scarlet.OpenPgp.Fuzz/README.md)).
