# Scarlet.OpenPgp — Project Spec

## Origin / context

This project grew out of work on a sibling repo, `Scarlet.Bun` (a NuGet package that pins the Bun
JavaScript runtime into .NET builds). While hardening `Scarlet.Bun`'s download path with SHA-256 checksum
verification, we discussed going further and verifying the upstream project's GPG signature over its
checksums file too. We concluded that wasn't worth doing *for Bun specifically*, because Bun doesn't publish
its signing key fingerprint through any authoritative channel (no mention in their docs/SECURITY.md — the
key is only discoverable by extracting it from a release signature and cross-checking a public keyserver).
Even Bun's own official installer does zero signature verification. So the trust-bootstrapping problem would
remain no matter how good the verification code was.

That side investigation surfaced a separate, more interesting idea: **there's no good zero-dependency,
fully-managed .NET library for verifying OpenPGP signatures.** Existing options in the .NET ecosystem are:
- Shell out to `gpg`/`gpg.exe` — not installed by default on Windows, inconsistent across CI images.
- Pull in [BouncyCastle](https://www.bouncycastle.org/csharp/) — mature and correct, but general-purpose,
  heavy, and not designed with trimming/NativeAOT in mind.

`Scarlet.OpenPgp` is that gap: a small, pure-managed, **verify-only** OpenPGP library, plus a NativeAOT CLI
that ships as a single small native binary with no .NET runtime dependency at the point of use — useful for
CI pipelines and build scripts that want to verify a release signature without installing GnuPG.

This is an **independent project**, not a dependency of `Scarlet.Bun`. It does not need to solve Bun's
key-distribution problem or integrate with `Scarlet.Bun` at all. Think of it as: "given a signature, a
message, and a public key you already trust (however you obtained that trust), tell me if the signature is
valid." What the caller does with that answer, and how they came to trust the key, is entirely their problem.

## Naming

- Library: `Scarlet.OpenPgp`
- CLI tool: `Scarlet.OpenPgp.Cli`

We chose `OpenPgp` over `Gpg`/`OpenGpg` deliberately: "GPG" refers to GnuPG, a specific tool this library
does not wrap or mimic. This library implements the **OpenPGP standard** (RFC 4880 / RFC 9580) directly, so
`OpenPgp` is the accurate name — it also matches existing ecosystem convention (BouncyCastle's namespace for
this is `Org.BouncyCastle.Bcpg.OpenPgp`; PGPainless follows the same logic).

## Current implementation (supersedes the v1 scope below)

The original v1 brief follows unchanged for its rationale. The implementation has since grown past it:

- **Formats:** OpenPGP v4 (RFC 4880) and v6 (RFC 9580) keys and signatures, including v6 salted
  hashing, v6 fingerprints, and RFC 9580's armor rules (optional, unchecked CRC24) and cleartext
  framework (only well-formed `Hash` headers, whose contents are ignored).
- **Algorithms:** RSA PKCS#1 v1.5 (2048-16384 bits), DSA (2048+ bits, 224/256-bit q), ECDSA on NIST
  P-256/384/521 and brainpoolP256r1/384r1/512r1, EdDSALegacy Ed25519, native Ed25519 and Ed448.
- **Hashes:** SHA2-224/256/384/512 and SHA3-256/512 for data signatures. SHA-1 is accepted only for
  a certificate's own self-signatures (see `HashContext`); MD5, SHA-1 and RIPEMD-160 data
  signatures are rejected (RFC 9580 §9.5).
- **Inputs:** signatures and keys may be ASCII-armored or binary. Key input may hold several
  certificates and signature input several signatures; the result is valid when any signature
  verifies against any supplied key.
- **Certificates:** signing subkeys (binding signature plus back-signature required), key flags,
  key/subkey expiration from the newest valid self-signature (a v6 key requires a Direct Key
  signature), signature expiration, and revocations contained in the supplied certificates. Hard
  revocations (compromised, no reason) invalidate every signature; soft ones (superseded, retired)
  only signatures made after them. Third-party certifications and designated revokers are ignored.
- **Data:** detached signatures stream the data once (`Stream` and async overloads), binary (0x00)
  and text-mode (0x01) signatures alike.
- **Result:** a `VerificationResult` with a status, a reason, the signer and primary fingerprints,
  the signature time and, for clearsign, the signed text.
- **Testing:** real release artifacts (Bun, Tor Browser, GnuPG, Node.js, Debian), GnuPG 2.4.9 output
  for every algorithm and certificate scenario, RFC 9580 / RFC 8032 / NIST vectors, BouncyCastle
  cross-validation, a deterministic mutation fuzzer in the test suite, and a SharpFuzz/libFuzzer
  harness (`fuzz/`) run in CI. The test project is also published and run as Native AOT with trim/AOT
  warnings as errors.

Still out of scope: signing, encryption, inline-signed (one-pass) messages, trust chains, third-party
revocations, LibrePGP v5 keys, and v3 keys/signatures.

## Goal (v1 scope)

A pure C# (zero external NuGet dependencies), verify-only OpenPGP implementation covering the common
real-world case well, rather than the entire spec badly. Concretely:

**In scope for v1:**
- Verify a **clearsigned** message (`-----BEGIN PGP SIGNED MESSAGE-----` ... `-----BEGIN PGP SIGNATURE-----`
  ... `-----END PGP SIGNATURE-----`) against a given ASCII-armored public key.
- Verify a **detached signature** (a `.sig`/`.asc` file plus the original file/bytes it signs) against a
  given ASCII-armored public key.
- Support the two most common signature algorithms in the wild:
  1. **Ed25519 (EdDSA)** — used by newer projects (this is what Bun uses).
  2. **RSA with PKCS#1 v1.5 padding** — still the majority for older/established projects, package
     repositories, and many release-signing setups.
- Target OpenPGP **v4** keys and signatures (RFC 4880) — this is what the overwhelming majority of
  real-world signatures use today.
- Ship as a NativeAOT-publishable CLI: `scarlet-openpgp verify --key pubkey.asc --signature file.asc
  [--data file]` (exact CLI shape is a design decision for whoever picks this up — the point is a trimmed,
  dependency-free, cross-platform native binary with a clean exit code contract: 0 = verified, non-zero =
  not verified or error, with a clear stderr message either way).

**Explicitly out of scope for v1** (call these out as non-goals, don't scope-creep into them):
- Signing, key generation, encryption/decryption. This is verify-only.
- Key management: keyrings, trust chains, web-of-trust, revocation checking. The caller supplies exactly the
  public key(s) they already trust; this library does not manage trust.
- OpenPGP **v6** keys/signatures (RFC 9580, the 2024 "crypto refresh" — new key/signature versions, AEAD,
  new curve representations). Worth being *aware* of since it exists and may matter for v2, but not needed
  for v1 — essentially no real-world signed release artifacts use it yet.
- DSA and ECDSA (NIST curves). Reasonable v2 candidates since some real-world signers use them, but not
  required for v1. RSA is easier than Ed25519 to add if you want a stronger v1 (see below), so RSA is in
  scope but ECDSA/DSA are deferred.
- Performance / constant-time arithmetic / side-channel resistance. **This matters and is worth stating
  explicitly**: because this library only ever handles public keys and public signatures (never a private
  key, never a secret to protect), the traditional "don't roll your own crypto" timing-side-channel concern
  mostly does not apply here. A correctness-first implementation using `System.Numerics.BigInteger` for all
  modular arithmetic (both the Ed25519 field prime `2^255 - 19` and RSA's modulus) is an acceptable choice
  for v1 — it will not be as fast as a hand-optimized fixed-width implementation, but for verifying a
  handful of signatures in a build script or CI step, that's irrelevant. Do not over-engineer for
  performance; prioritize correctness and clarity.

## Why this is safer than typical "roll your own crypto" advice suggests

Worth internalizing before starting: the usual reason not to write your own crypto is that hand-rolled
implementations leak secrets through timing/cache side channels during operations that touch private key
material (signing, decryption). **None of that applies to a verify-only library** — there is no private key
anywhere in this codebase, ever. The failure modes here are much more contained:
- A bug causes a valid signature to be rejected → annoying, breaks someone's build, easy to notice and fix.
- A bug causes an invalid signature to be accepted → bad, but exactly as bad as not verifying at all, not
  worse. It doesn't leak anything or compromise anything beyond the (already unverified without this tool)
  status quo.

This does **not** mean sloppy correctness is fine — a library whose entire purpose is "tell people whether
to trust this artifact" needs to be right. It means the specific *class* of catastrophic crypto bug (secret
key extraction via timing attack) isn't the risk profile here; the risk is ordinary implementation
correctness, which is addressed by thorough testing against official test vectors (see Testing section).

## Technical breakdown

This splits into two genuinely separate pieces of work:

### 1. OpenPGP framing (mechanical, well-specified, no cryptography)

- **ASCII armor decoding**: parse `-----BEGIN PGP ...-----` / `-----END PGP ...-----` blocks, base64-decode
  the body, verify the trailing CRC24 checksum line (RFC 4880 §6).
- **Packet header parsing**: both old-format and new-format packet tags, including partial-body-length
  encoding (RFC 4880 §4.2). You need at minimum: Public-Key packet (tag 6), Signature packet (tag 2), and
  enough general packet-skipping logic to safely ignore packet types you don't care about (User ID, User
  Attribute, unhashed trust packets, subkeys) without choking on them.
- **Public key packet parsing (v4)**: version, creation time, public-key algorithm ID, and the
  algorithm-specific public key material:
  - RSA: modulus `n` and exponent `e`, encoded as OpenPGP MPIs.
  - EdDSA (Ed25519): a curve OID (identifying Ed25519) followed by the native-encoded public point.
- **Signature packet parsing (v4)**: version, signature type (0x00 = binary document, 0x01 = canonical text
  document — clearsign uses 0x01), public-key algorithm, hash algorithm, hashed and unhashed subpacket
  arrays. For v1 you mainly need to extract: issuer key ID / issuer fingerprint (to match against the
  supplied public key), and the raw signature MPIs/values themselves. Unknown subpacket types must be safely
  skippable (per spec, only subpackets with the "critical" bit set that you don't understand should cause a
  failure — everything else is safely ignorable).
- **Clearsign canonicalization** (RFC 4880 §7, §5.2.1): before hashing, the signed text needs
  dash-unescaping (lines in the message body starting with `-` are armored as `- -`, undo that), trailing
  whitespace stripped from each line, and line endings normalized to CRLF regardless of the source file's
  actual line endings.
- **Signature hash computation** (RFC 4880 §5.2.4): the hash isn't just "hash the message" — it covers the
  canonicalized document content, followed by the signature packet's own hashed-subpacket data, its version,
  type, and algorithm bytes, and a final length trailer. Get this wrong and every signature will fail to
  verify even with correct point/RSA math underneath, so it's worth writing a focused unit test for the
  exact byte sequence being hashed, independent of the actual signature verification.

### 2. Cryptographic verification (the actual math)

- **Hashing**: SHA-256/SHA-384/SHA-512 — already in `System.Security.Cryptography`, no work needed here.
- **RSA-PKCS#1 v1.5 verification** (RFC 8017 §8.2.2 / §9.2): modular exponentiation of the signature value
  using the public exponent and modulus (straightforward with `BigInteger.ModPow`), then verify the
  recovered padded value matches the expected PKCS#1 v1.5 structure (`00 01 FF...FF 00 <DigestInfo ASN.1
  DER prefix for the hash algorithm> <hash>`). This is genuinely simpler than Ed25519 — no elliptic curve
  math, just modexp and a byte-structure check. Consider implementing this first as a warm-up / to validate
  the packet-parsing layer before tackling Ed25519.
- **Ed25519 (EdDSA) verification** (RFC 8032 §5.1.7): this is the real cryptographic core.
  - Finite field arithmetic modulo `p = 2^255 - 19`. Using `BigInteger` for this is fine for v1
    (correctness over speed, per the non-goals above).
  - Point decompression from the compressed 32-byte public key encoding.
  - Point addition/doubling on the twisted Edwards curve (using extended coordinates is the standard
    approach for avoiding costly modular inversions per operation, but even a naive affine-coordinate
    implementation is acceptable for v1 given the performance non-goal).
  - Scalar multiplication.
  - The final verification equation: `[8][S]B == [8]R + [8][k]A` (or the equivalent unblinded form) using
    SHA-512 internally as specified.
  - RFC 8032 Appendix contains full pseudocode and, critically, **official test vectors** — use them.

### Public API (as implemented)

```csharp
namespace Scarlet.OpenPgp;

public static class OpenPgpVerifier
{
    // Clearsigned message; on success result.SignedText is exactly the authenticated text - the only
    // part of the input callers may use. Keys: armored string, or armored/binary bytes.
    public static VerificationResult VerifyClearsign(string clearsignedMessage, string publicKeys);
    public static VerificationResult VerifyClearsign(string clearsignedMessage, ReadOnlySpan<byte> publicKeys);

    // Detached signature(s), armored or binary, over in-memory or streamed data.
    public static VerificationResult VerifyDetached(ReadOnlySpan<byte> data, string signature, string publicKeys);
    public static VerificationResult VerifyDetached(ReadOnlySpan<byte> data, ReadOnlySpan<byte> signature, ReadOnlySpan<byte> publicKeys);
    public static VerificationResult VerifyDetached(Stream data, string signature, string publicKeys);
    public static VerificationResult VerifyDetached(Stream data, ReadOnlySpan<byte> signature, ReadOnlySpan<byte> publicKeys);
    public static Task<VerificationResult> VerifyDetachedAsync(Stream data, ReadOnlyMemory<byte> signature, ReadOnlyMemory<byte> publicKeys, CancellationToken cancellationToken = default);
}

public sealed class VerificationResult
{
    public bool IsValid { get; }
    public VerificationStatus Status { get; }      // Valid, BadSignature, KeyExpired, KeyRevoked, ...
    public string Message { get; }
    public string? SignerFingerprint { get; }      // the signing (sub)key
    public string? PrimaryKeyFingerprint { get; }  // the certificate
    public DateTimeOffset? SignatureCreationTime { get; }
    public string? SignedText { get; }             // clearsign only
}
```

## Project structure (mirroring `Scarlet.Bun`'s layout, adjust as needed)

```
Scarlet.OpenPgp/
├── src/
│   ├── Scarlet.OpenPgp/           # Core library. Target netstandard2.0 for the widest possible
│   │                               # consumer compatibility (matches Scarlet.Bun.Core's reasoning).
│   │                               # Zero PackageReference entries other than the SDK-provided BCL.
│   └── Scarlet.OpenPgp.Cli/        # NativeAOT-published CLI. Target a modern net TFM (net10.0-class).
├── tests/
│   └── Scarlet.OpenPgp.Tests/      # Unit tests - see Testing section below.
├── README.md
├── LICENSE                         # MIT, matching Scarlet.Bun's precedent, unless told otherwise.
└── SPEC.md                         # This file.
```

## Testing requirements

This is the part that cannot be shortcut, precisely because it's a security-relevant library other people
may end up depending on:

1. **RFC 8032 official Ed25519 test vectors** — implement and pass all of them before trusting the Ed25519
   path at all.
2. **RFC 8017 / known-good RSA-PKCS#1 v1.5 test vectors**, or generate fixtures by signing known messages
   with a known test key using a trusted reference implementation.
3. **Real-world cross-validation**: generate test fixtures by having real `gpg` (or an established library
   like BouncyCastle, used only in the test project, never in the shipped library) sign test messages with
   both an Ed25519 test key and an RSA test key, commit those fixtures (signed message + public key +
   expected verify result), and assert `Scarlet.OpenPgp` agrees. Do this for both clearsign and detached
   signature forms.
4. **Negative/malformed-input tests**: truncated packets, corrupted signatures, wrong key, tampered message
   content after signing, unknown critical subpackets — all of these must fail closed (return `false` /
   throw a clear exception), never silently succeed or crash with an unhandled exception on attacker-
   controlled input. Treat all signature/key/message input as untrusted.
5. Before calling v1 "done," verify against at least one *real* upstream project's actual release signature
   (e.g., Bun's `SHASUMS256.txt` + `SHASUMS256.txt.asc`, which is Ed25519 and was the original motivating
   example) and confirm the result matches real `gpg --verify` on the same inputs.

## Open questions for whoever picks this up

- Exact CLI argument shape and output format (plain text vs. `--json` for scripting, matching the kind of
  design decisions `Scarlet.Bun.Cli` made — worth glancing at that sibling repo for tone/conventions, though
  there's no code-sharing relationship).
- Whether to expose the packet-parsing layer as a public API (useful for inspecting a key/signature without
  verifying, e.g. "what key ID signed this") or keep it entirely internal behind `OpenPgpVerifier`.
- ~~Whether v2 should add ECDSA and/or DSA~~ and ~~RFC 9580 (v6) support~~: done (see "Current
  implementation"). OpenPGP has no RSA-PSS.
- Whether to expose per-signature results when an input holds several signatures (today the result
  reports the first valid one, or the most informative failure).
- Whether to honor third-party revocations by designated revokers whose certificates are also supplied.

## Non-negotiables (carry these forward regardless of who implements this)

- **Zero *third-party* NuGet dependencies** in `Scarlet.OpenPgp` itself (the core library). This is the
  entire point of the project. The one exception is **`System.Memory`**, referenced only on the
  `netstandard2.0` target build (`net10.0` has `Span<T>`/`ReadOnlySpan<T>` natively and needs no such
  reference) — it's a Microsoft-shipped BCL compatibility shim, not a third-party dependency in the sense
  this rule is guarding against, and it's what makes `OpenPgpVerifier.VerifyDetached` take
  `ReadOnlySpan<byte>` (matching this doc's own original API sketch) instead of a plain `byte[]` on every
  target. Test project dependencies (test framework, and optionally BouncyCastle *only* for generating
  cross-validation fixtures in tests) are fine too.
- **Verify-only.** Do not scope-creep into signing or key management.
- **Fail closed.** Any parsing ambiguity, unknown-but-critical data, or malformed input must result in a
  verification failure, never a silent pass.
- **Text surrounding a detached signature or key block is tolerated; around a clearsigned message it is
  not.** For a detached signature or a public key block, `AsciiArmorReader.Read` ignores content before the
  BEGIN line and after the matching END line (a mail/commentary preamble, unrelated trailing text, even a
  second concatenated block) and reports on the first well-formed block it finds. That is harmless there,
  because the signed data is supplied separately and checked as given. A clearsigned message is different:
  its signed content sits in the same text, so any tolerated-but-unsigned text is text a caller can mistake
  for signed content (e.g. an injected line in a `SHASUMS256.txt.asc` that a script then searches for a
  checksum). GnuPG gets away with tolerating it because it can output the verified text; this library
  instead parses clearsigned messages strictly: only blank lines may precede the BEGIN line or follow
  the END line, only well-formed `Hash` armor headers are accepted (RFC 9580 §7.1; their contents are
  ignored per §6.2.2.3), body lines starting with `-` must be dash-escaped, and a bare CR is rejected.
  `VerifyClearsign` also returns the signed text, and callers must use only that text. Malformed *content
  inside* a matched block (bad base64, a packet body with unexpected trailing bytes, a non-signature
  packet among the signatures) fails closed everywhere. The CRC24 line is not checked: RFC 9580 §6.1
  forbids rejecting armor over it, and it never protected against tampering anyway.
- **Signature and key lifetimes are enforced.** A signature past its hashed signature-expiration time, a
  signature created before its key, and a key or subkey past the expiration set by its most recent
  self-signature that verifies all fail verification - a key must be valid both now and when it signed.
  Key expiration, flags and revocations are only read from signatures that verify against the primary
  key, never from unverified packets in the block.
- **Bounded work on hostile input.** RSA moduli are capped at 16384 bits (and exponents at 256 bits),
  DSA primes at 16384 bits, so no input can make a single verification take minutes.
- **Correctness over performance**, but still write clean, readable code — this will be read and audited by
  people deciding whether to trust it. `Span<T>`/`ReadOnlySpan<T>` are fair game where they reduce
  allocations without hurting readability (see "Performance follow-up" below), but don't chase performance
  work that isn't backed by a measurement.

## Performance follow-up (not done in v1, noted for whoever picks this up next)

v1 prioritized correctness and used plain `byte[]` throughout the packet/MPI framing layer (one array per
packet body, one per MPI, etc.) — reasonable for verifying a handful of signatures in a build script, but
there are real allocation hot spots if this ever needs to verify many signatures quickly:

- `Packets/PacketReader.cs` — allocates a `MemoryStream` + `byte[]` per packet. Could instead return
  `ReadOnlyMemory<byte>` slices into the original input buffer for non-partial-length packets (the common
  case), only falling back to a copy when partial-body chunks actually need concatenating.
- `Packets/Mpi.cs` — `ReadFrom`/`ToUnsignedBigInteger`/`ToFixedLengthUnsignedBytes` each allocate a fresh
  array to reverse byte order for `BigInteger`. Could take `ReadOnlySpan<byte>` instead of `byte[]` to at
  least avoid one intermediate copy at each call site, though the byte-reversal allocation itself is
  probably unavoidable without dropping to `stackalloc` for small (≤64-byte) MPIs.
- Ed25519 now uses extended (inversion-free) coordinates and Ed448 projective ones; the next step for
  either would be fixed-width field arithmetic instead of `BigInteger`.
- `Crypto/Ed25519/Ed25519Verifier.cs`'s `Concat`/`LittleEndianToBigInteger` helpers, and the equivalent
  spots in `Crypto/Rsa/RsaPkcs1Verifier.cs` — same story, small allocations that `stackalloc` + `Span<byte>`
  could avoid for the fixed-size (32/64-byte) Ed25519 values.
- None of this will matter next to the cost of the actual `BigInteger` modular exponentiation/field
  arithmetic in `RsaPkcs1Verifier`/`Ed25519Verifier` (the RFC8032 field/curve math is the real hot path, and
  `Span<T>` doesn't help there — that would need fixed-width arithmetic instead of `BigInteger`, a much
  bigger change explicitly deferred per the performance non-goal above).

**Before doing any of this: add a benchmark project (`BenchmarkDotNet`, test-only dependency, not referenced
by the shipped library) and measure first.** Guessing at allocation hot spots without a baseline is exactly
the kind of premature optimization this doc's non-goals warn against — do the measurement, then decide
which of the above (if any) is worth the added complexity.
