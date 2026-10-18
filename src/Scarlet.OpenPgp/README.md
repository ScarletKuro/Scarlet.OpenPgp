# Scarlet.OpenPgp

A pure C#, zero-dependency, verify-only OpenPGP implementation (RFC 9580, and RFC 4880 v4).

```csharp
using Scarlet.OpenPgp;

// Clearsigned: on success, SignedText is exactly what was signed.
VerificationResult clearsigned = OpenPgpVerifier.VerifyClearsign(clearsignedText, publicKeys);
if (clearsigned.IsValid)
{
    Use(clearsigned.SignedText);
}

// Detached, signature and keys armored (.asc) or binary (.sig/.gpg); data streamed, never buffered.
using FileStream data = File.OpenRead("release.tar.gz");
VerificationResult detached = OpenPgpVerifier.VerifyDetached(data, File.ReadAllBytes("release.tar.gz.sig"), File.ReadAllBytes("keys.gpg"));
Console.WriteLine(detached);                    // e.g. "KeyExpired: The signing subkey expired at ..."
Console.WriteLine(detached.SignerFingerprint);  // the (sub)key that signed
```

To verify several signatures against the same keys, parse them once. That checks the certificates'
self-signatures a single time, rejects malformed key data up front, and lets you inspect the keys:

```csharp
OpenPgpKeyRing keyRing = OpenPgpKeyRing.Parse(File.ReadAllBytes("keys.gpg")); // throws OpenPgpFormatException if malformed
foreach (OpenPgpCertificate certificate in keyRing.Certificates)
{
    OpenPgpKeyStatus status = certificate.PrimaryKey.GetStatus(); // as of now; pass a time to judge another moment
    Console.WriteLine($"{certificate.PrimaryKey.Fingerprint} {certificate.PrimaryKey.Algorithm}: {status}");
}

VerificationResult result = OpenPgpVerifier.VerifyDetached(data, signature, keyRing);
```

A successful parse means the key data is well-formed, not that every key may sign: a key can be
revoked, expired, unbound or carry self-signatures that can't be checked. `GetStatus` reports that
for a given moment, with the same rules verification applies. Certificate input is bounded (16,384
packets per copy and 4,096 signature checks per certificate across all its copies, 16,384
certificates), so a certificate flooded with signatures or repeated thousands of times is rejected
rather than processed.

The key ring is immutable and thread-safe. Expiration, revocation timing and key flags are still
judged at each verification, so a key that expires while your application runs stops verifying.
Every `Verify*` overload takes an optional `verificationTime` to judge them at a different moment
instead, e.g. to pin the clock in tests or check what a signature's status was when you received it.

Only use `SignedText` from a clearsigned message. The input also contains unsigned text, such as
dash-escaping and the signature block's own armor headers, so reading data straight out of the
`.asc` file means trusting text nobody signed.

## Verifying someone else's releases

The typical use: your application downloads a third party's release and must know it is the real
one, even if the download went through an attacker (a hijacked mirror, a MITM). The signature
proves the files came from whoever holds the key - so everything rests on the key, and on checking
what the signature actually covers.

1. **Pin the publisher's key.** Ship their public key with your application, or fetch it once over
   a channel you trust and check its fingerprint against one the publisher announced elsewhere.
   Never download the key from the same place as the release: whoever can swap the files can swap
   the key. Parse it once with `OpenPgpKeyRing.Parse` at startup, so a broken key fails loudly.
2. **Check who signed.** If your key ring holds more than one publisher, compare
   `result.PrimaryKeyFingerprint` with the one you expect for this release.
3. **Verify what you will use.** For a detached signature, stream the exact file you are about to
   install into `VerifyDetached` - not a second download of it. Many publishers instead sign a list
   of hashes (`SHASUMS256.txt.asc`): verify that, take the hash from `SignedText` only, and compare
   it with the SHA-256 of your downloaded file.
4. **Reject replays.** A valid signature proves the release is genuine, not that it is current. An
   attacker can serve an older release - with its own, perfectly valid signature - to keep you on
   a vulnerable version. Check that `SignatureCreationTime` is not older than the release you
   already have or expect, or check the version inside the signed content.
5. **Treat every status other than `Valid` as a rejection.** `KeyExpired` and `KeyRevoked` mean the
   publisher's key can no longer vouch for anything; update the pinned key through your own release
   process when the publisher rotates it.

```csharp
// Once, at startup: the publisher's key, shipped with the application.
OpenPgpKeyRing publisher = OpenPgpKeyRing.Parse(PinnedPublisherKey);

// For each download: the signed hash list, then the file it vouches for.
VerificationResult result = OpenPgpVerifier.VerifyClearsign(File.ReadAllText("SHASUMS256.txt.asc"), publisher);
if (result is not { IsValid: true, SignedText: string signedText, SignatureCreationTime: DateTimeOffset signedAt }
    || result.PrimaryKeyFingerprint != ExpectedFingerprint
    || signedAt < LastInstalledReleaseSignedAt)
{
    throw new InvalidOperationException("Release signature rejected: " + result);
}

string? expectedHash = signedText.Split("\r\n")
    .Select(line => line.Split("  "))
    .Where(fields => fields.Length == 2 && fields[1] == fileName)
    .Select(fields => fields[0])
    .SingleOrDefault();
using FileStream download = File.OpenRead(downloadedPath);
string actualHash = Convert.ToHexString(SHA256.HashData(download)).ToLowerInvariant();
if (expectedHash != actualHash)
{
    throw new InvalidOperationException(fileName + " is not the file the publisher signed.");
}
```

## Scope

- Clearsigned messages, and detached signatures over binary (0x00) or text-mode (0x01) data.
- v4 and v6 (RFC 9580) keys and signatures: RSA PKCS#1 v1.5, DSA, ECDSA on NIST P-256/384/521 and
  brainpoolP256r1/384r1/512r1, EdDSALegacy Ed25519, native Ed25519 and Ed448. Hashes SHA2-224/256/
  384/512 and SHA3-256/512; MD5, SHA-1 and RIPEMD-160 signatures are rejected.
- Signatures and keys may be ASCII-armored or binary. Key input may hold several certificates and
  signature input several signatures: the result is valid when any signature verifies against any
  supplied key.
- Signing subkeys need a binding signature with the sign flag and a valid back-signature; a primary
  key whose self-signature lacks the sign flag can't sign data.
- Time is checked: a signature past its own expiration time, a signature older than its key, and a
  key or subkey past the expiration set by its newest valid self-signature all fail. A key that has
  expired fails *now* even for signatures it made while still valid, the same policy as apt.
- Revocations in the supplied certificates are honored: "compromised" (or no reason) invalidates
  every signature; "superseded" and "retired" only signatures made after the revocation. A revoked
  self-signature (User ID or Direct Key) no longer counts, and a revocation applies wherever it
  sits in the key data.
- Revocations only count if they're in the key data you supply. A certificate's fingerprint
  identifies its primary key only, not its list of signatures: anyone who handles a certificate
  can *delete* a revocation or an expiring self-signature without changing the fingerprint. Adding
  unsigned data can't change a verdict, and a revocation or self-signature that can't be parsed or
  checked makes the key unusable rather than disappearing. A deleted one, though, is
  indistinguishable from one that never existed. So if you refresh a certificate from an
  untrusted source, checking its fingerprint doesn't prove you've seen its latest revocations.
- No signing, key generation, encryption, or trust management. Supply exactly the keys you already
  trust; this library does not decide whether to trust them.
- Nothing throws on bad input: every failure is a `VerificationResult` with a `Status` and `Message`.
- Zero external NuGet dependencies. Targets `netstandard2.0` for broad compatibility, plus
  `net10.0` so it can be properly AOT/trim-analyzed when consumed by an AOT-published app.

See the repository root [SPEC.md](../../SPEC.md) for the full design rationale, non-goals, and
testing requirements.
