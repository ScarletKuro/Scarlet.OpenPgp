# OpenPGP test fixtures - manifest

This file describes every fixture folder under `TestAssets/`. It is the contract for the tests:
for each folder it lists the files, where they came from, the algorithms and fingerprints
involved, what GnuPG 2.4.9 (libgcrypt 1.12.0) says about them, and what a **strict
verifier** (this library) is expected to return.

Assembled on **2026-10-17** ("today" below). All times are UTC.

## Conventions

* `TestAssets/.gitattributes` sets `* -text`: every fixture is stored and checked out
  byte-for-byte (no CRLF/LF conversion). Never re-save fixture files in an editor.
* Each `real-world/*` and `gnupg-generated/*` folder also has:
  * `gpg-output.txt`: the exact commands and the complete, unedited `gpgv` / `gpg --verify` output,
    with `[exit code: N]`. Commands were run inside the folder with `TZ=UTC` and a throwaway
    `GNUPGHOME`. `gpgv --keyring ./X.gpg` uses only that keyring file. `gpg --verify`
    lines come from a fresh `GNUPGHOME` where only the named public key file was imported.
    gpg housekeeping lines ("trustdb created", "keybox created", "running with faked system time")
    were removed.
  * `gpg-packets.txt`: `gpg --show-keys` of the certificate and `gpg --list-packets` of the
    signatures. For clearsigned files, only the armored signature block was fed to `--list-packets`.
  * Sometimes `public-key.packets.txt`: `gpg --list-packets` of the certificate. It shows
    self-signatures, key flags, expirations, back-signatures and revocations.
* Important gpg behaviour to know when reading the outputs:
  * **`gpgv` only checks the cryptography.** It reports "Good signature" with exit 0 even when
    the key is expired or revoked. **`gpg --verify`** shows the key-validity warnings, but also
    exits 0 for expired/revoked keys. Only an *expired signature* (subpacket 3) or a bad/missing
    signature makes gpg return a non-zero exit code. Exit code 1 means BAD or expired signature.
    Exit code 2 means a signature could not be checked (missing key or unsupported packet).
  * Where this file's "Expected (strict)" differs from gpg's exit code, the difference is
    intentional. It follows the library's policy: key/subkey must not be expired **at verification
    time**; hard revocation invalidates everything; soft revocation invalidates signatures made
    after the revocation; RFC 9580 §9.5 bans recent SHA-1 signatures.
* Algorithm IDs: 1 RSA, 17 DSA, 19 ECDSA, 22 EdDSA (legacy, v4 "Ed25519Legacy"),
  27 Ed25519 (native), 28 Ed448 (native). Hash IDs: 2 SHA-1, 8 SHA2-256, 9 SHA2-384,
  10 SHA2-512, 11 SHA2-224.
* Signature types: 0x00 binary document, 0x01 canonical text document, 0x13 positive
  certification, 0x18 subkey binding, 0x19 primary-key binding (back-signature), 0x1F direct key,
  0x20 key revocation, 0x28 subkey revocation, 0x30 certification revocation.
* Revocation reason codes (subpacket 29): 0x00 no reason, 0x01 superseded (soft),
  0x02 compromised (hard), 0x03 retired (soft). gpg's interactive menu numbers differ from the
  wire codes ("1 = compromised" is wire 0x02, "2 = superseded" is wire 0x01).

## Shared data file (`gnupg-generated/*/data.txt`, `v4-textmode/data-lf.txt`)

All generated fixtures sign the same 222-byte UTF-8 file with LF line endings
(SHA-256 `e6c603c5b9d043bb3cd5ce932c99660e94419049f1a5a3c089b801134608fdd0`):

```
Scarlet.OpenPgp fixture data␊
This line ends with three trailing spaces␠␠␠␊
- this line starts with a dash␊
-----BEGIN PGP SIGNATURE----- (not a real armor line)␊
From the start of a line␊
␉Tab-indented line␊
Unicode: café ✓␊          (é = C3 A9, ✓ = E2 9C 93; file ends with a final LF)
```

Each `data.txt.clearsign.asc` made by gpg from this file shows:

* the lines starting with `-` **and** the `From ` line are dash-escaped (`- `);
* the three trailing spaces are kept in the cleartext but are **not hashed**. RFC 9580 §7.2 says
  trailing spaces/tabs are removed before hashing a cleartext signature;
* an extra empty line before `-----BEGIN PGP SIGNATURE-----`. The signed text therefore ends
  with `✓\r\n` (the line break just before the armor line is not part of the signed text);
* armor header `Hash: SHA256` (or SHA384/SHA512 as noted). There is no `Version:` header. Armor
  checksums (`=XXXX`) are present.

---

# Part 1 - real-world release artifacts (`real-world/`)

These are real project artifacts, downloaded unchanged on 2026-10-17.

## real-world/tor-browser-subkey

Scenario: armored detached RSA signature made by a **signing subkey**. The certificate has
**8 signing subkeys** (expired, revoked and current), several primary self-signatures, and
third-party certification revocations.

| File | Source |
|---|---|
| `sha256sums-signed-build.txt` (5719 B) | https://dist.torproject.org/torbrowser/15.0.25/sha256sums-signed-build.txt |
| `sha256sums-signed-build.txt.asc` (833 B) | https://dist.torproject.org/torbrowser/15.0.25/sha256sums-signed-build.txt.asc |
| `tor-browser-developers.asc` (39452 B) | https://keys.openpgp.org/vks/v1/by-fingerprint/EF6E286DDA85EA2A4BA7DE684E2C6E8793298290 (as downloaded) |
| `tor-browser-developers.gpg` (19913 B) | `gpg --export` of the imported `.asc` (binary, one certificate) |

* Primary: `EF6E286DDA85EA2A4BA7DE684E2C6E8793298290`, rsa4096, created 2014-12-15, flags C
  (certify only). **Expires 2030-11-18**. That date comes from the newest of 5 uid
  self-signatures (0x13, created 2026-08-11, "key expires after 15y342d4h19m"). Older
  self-signatures carry older expirations, and the 2014 one has none. A verifier must use the
  newest self-signature.
* Signing subkey used: `022DA248432D2A0E0F54E65E316C1FACD62D07D9` (key ID 316C1FACD62D07D9),
  rsa4096, created 2026-08-11, flags S. **Expires 2028-11-28** (binding signature 0x18 of
  2026-08-11, "2y110d"). It has an embedded 0x19 back-signature (subpacket 32, SHA512).
* Other subkeys (all rsa4096, flags S) the verifier must *not* use for this signature:
  `CAAE408AEBE2288E96FC5D5E157432CF78A65729` expires **2026-10-26** (still valid today, expires in 9 days);
  `A4300A6BC93C0877A4451486D1483FA6C3C07136` expired 2018-08-24;
  `110775B5D101FB36BC6C911BEB774491D9FF06E2` expired 2022-01-04;
  `613188FC5BE2176E3ED54901E53D989A9E2D47BF` expired 2024-09-13;
  `BA1EE421BBB45263180E1FC72E1AC68ED40814E0` expired 2017-08-25;
  `5242013F02AFC851B1C736B87017ADCEF65C2036` expired 2017-08-25;
  `05FA44253F6C19A8B7F518D42D000988589839A3` **revoked 2015-08-26 with reason 0x02 (compromised = hard)**
  (0x28 subkey revocation).
* The uid also has 8 third-party **0x30 certification revocations** issued by other keys
  (`DB99B20C6AFAC3E9`, `3D55875AB7A642B7`, ...). These are not key revocations and must be
  ignored (they cannot be verified with this keyring anyway).
* Signature: 1 packet, v4, alg 1 (RSA), **hash 10 (SHA2-512)**, type 0x00 (binary), armored
  detached, created **2026-10-12T23:14:34Z**. Issuer fingerprint subpacket = signing subkey.
* gpg: `gpgv: Good signature from "Tor Browser Developers (signing key) <torbrowser@torproject.org>"`, `[exit code: 0]`.
  `gpg --verify` additionally prints `Primary key fingerprint: EF6E 286D ...` / `Subkey fingerprint: 022D A248 ...`, exit 0.
* **Expected (strict): VALID**, signer = subkey 022D...07D9 of primary EF6E...8290. This is
  only true until 2028-11-28, when the subkey expires. After that date the expected result becomes
  INVALID (key expired), so a test that should keep passing must pin the verification time.

## real-world/gnupg-npth-multisig

Scenario: **binary** detached `.sig` with **two signature packets**, plus a keyring with
**six** certificates (EdDSA, RSA and **brainpool ECDSA**).

| File | Source |
|---|---|
| `npth-1.8.tar.bz2` (317739 B) | https://gnupg.org/ftp/gcrypt/npth/npth-1.8.tar.bz2 |
| `npth-1.8.tar.bz2.sig` (238 B) | https://gnupg.org/ftp/gcrypt/npth/npth-1.8.tar.bz2.sig |
| `gnupg-signature-keys.asc` (6466 B) | https://gnupg.org/signature_key.asc (6 certs, one armor block) |
| `gnupg-signature-keys.gpg` (4714 B) | `gpg --export` of all 6 (binary keyring) |

Certificates in the keyring (all v4, primary keys only, flags SC):

| Fingerprint | Algo | Created | Expires | UID |
|---|---|---|---|---|
| `6DAA6E64A76D2840571B4902528897B826403ADA` | ed25519 (EdDSA 22) | 2020-08-24 | 2030-06-30 | Werner Koch (dist signing 2020) |
| `AC8E115BF73E2D8D47FA9908E98E9B2D19C6C8BD` | ed25519 (EdDSA 22) | 2021-05-19 | 2027-04-04 | Niibe Yutaka (GnuPG Release Key) |
| `3B761AE4E63BF3519CE7D63BECB664CBE1332EEF` | rsa3072 | 2025-05-09 | 2033-03-03 | Alexander Kulbartsch (GnuPG Release Key) - has a designated revoker (02F3...A208) |
| `D02AE49173BDAD56E4F88223707E56D3DEF4115C` | ed25519 (EdDSA 22) | 2026-07-20 | 2036-06-30 | Ingo Klöcker (Release Signing Key 2026) (UTF-8 uid) |
| `02F38DFF731FF97CB039A1DA549E695E905BA208` | brainpoolP256r1 (ECDSA 19) | 2021-10-15 | 2029-12-31 | GnuPG.com (Release Signing Key 2021) |
| `1493269DE61F124AA69A316E3ADF34EBDBB200A4` | brainpoolP384r1 (ECDSA 19) | 2026-02-23 | 2034-02-23 | GnuPG.com (Release Signing Key 2026) |

Signature packets in `npth-1.8.tar.bz2.sig` (binary, old-format CTB 0x88, 2 x 119 bytes):

1. Werner Koch `6DAA...3ADA`, alg 22 EdDSA, hash 8 SHA2-256, type 0x00, created **2024-11-12T10:57:19Z**.
   The MPI `s` is only **252 bits** long (leading zero bits stripped), so the parser must left-pad it
   to 32 bytes.
2. Niibe Yutaka `AC8E...C8BD`, alg 22 EdDSA, hash 8 SHA2-256, type 0x00, created **2024-11-13T00:50:53Z**.

* gpg (`gpgv --keyring ./gnupg-signature-keys.gpg npth-1.8.tar.bz2.sig npth-1.8.tar.bz2`):
  `gpgv: Good signature from "Werner Koch (dist signing 2020)"` then
  `gpgv: Good signature from "Niibe Yutaka (GnuPG Release Key)"`, `[exit code: 0]`.
* **Expected (strict): VALID, both signatures good.** Niibe's key expires 2027-04-04, so after
  that date his signature becomes INVALID (key expired) and Werner's stays valid until 2030-06-30.
* No small real-world file signed by the brainpool keys was found. Their self-signatures
  (ECDSA over brainpoolP256r1/P384r1) still exercise brainpool parsing and certificate checks.

## real-world/nodejs-clearsign-rsa

Scenario: **RSA clearsigned** message (Node.js v26.12.0 `SHASUMS256.txt.asc`), plus the same
release's **binary detached** `SHASUMS256.txt.sig`.

| File | Source |
|---|---|
| `SHASUMS256.txt` (3171 B) | https://nodejs.org/dist/v26.12.0/SHASUMS256.txt |
| `SHASUMS256.txt.asc` (4053 B) | https://nodejs.org/dist/v26.12.0/SHASUMS256.txt.asc |
| `SHASUMS256.txt.sig` (566 B) | https://nodejs.org/dist/v26.12.0/SHASUMS256.txt.sig |
| `richard-lau.asc` (5613 B) | https://raw.githubusercontent.com/nodejs/release-keys/main/keys/C82FA3AE1CBEDC6BE46B9360C43CEC45C17AB93C.asc |
| `richard-lau.gpg` (4084 B) | `gpg --export` of the above |

* Key: primary `C82FA3AE1CBEDC6BE46B9360C43CEC45C17AB93C`, rsa4096, created 2019-10-28, flags SC,
  **no expiration**. It has 2 uids ("Richard Lau <richard.lau@ibm.com>", "Richard Lau <rlau@redhat.com>")
  and an encryption-only subkey `C4960C6DAA2AEBC352F3E5B8E140F61BC5979DCC` (rsa4096, flags E, must not
  be used for verification).
* The signer was identified from the signature's issuer-fingerprint subpacket (subpacket 33).
  The key was then fetched by that full fingerprint.
* `SHASUMS256.txt.asc`: clearsigned, `Hash: SHA256`, 1 signature packet, alg 1 RSA, hash 8,
  type **0x01**, created **2026-10-14T15:21:32Z**, issued by the primary key.
* `SHASUMS256.txt.sig`: binary detached, 1 packet, alg 1 RSA, hash 8, type 0x00, created
  **2026-10-14T15:21:34Z**.
* gpg:
  * `gpgv --keyring ./richard-lau.gpg SHASUMS256.txt.asc` prints
    `gpgv: Good signature from "Richard Lau <richard.lau@ibm.com>"` / `aka "Richard Lau <rlau@redhat.com>"`
    and `[exit code: 0]`. It also prints `WARNING: not a detached signature; file 'SHASUMS256.txt' was NOT verified!`
    because a same-named file sits next to it. This warning is harmless.
  * `gpgv ... SHASUMS256.txt.sig SHASUMS256.txt` prints `Good signature`, `[exit code: 0]`.
* **Expected (strict): VALID for both.** The cleartext body recovered from the clearsigned file
  equals `SHASUMS256.txt` (LF line endings in the file).

## real-world/debian-trixie-release

Scenario: Debian 13.7 "trixie" archive metadata. This covers an **armored detached signature with
3 signature packets** and a **clearsigned message with 3 signatures**. The signers are 2 RSA
**signing subkeys** of different certificates plus 1 EdDSA primary key.

| File | Source |
|---|---|
| `Release` (138612 B) | https://deb.debian.org/debian/dists/stable/Release (snapshot of 2026-10-17; Date: Sat, 12 Sep 2026 07:55:41 UTC) |
| `Release.gpg` (1760 B) | https://deb.debian.org/debian/dists/stable/Release.gpg |
| `InRelease` (140421 B) | https://deb.debian.org/debian/dists/stable/InRelease |
| `archive-key-12.asc` | https://ftp-master.debian.org/keys/archive-key-12.asc |
| `archive-key-13.asc` | https://ftp-master.debian.org/keys/archive-key-13.asc |
| `release-13.asc` | https://ftp-master.debian.org/keys/release-13.asc |
| `debian-keyring.gpg` (18360 B) | binary keyring holding the 3 certificates above |
| `archive-key-13-only.gpg` (8698 B) | binary keyring with **only** the trixie archive key (partial-keyring case) |

| Certificate | Primary (algo, created, expires) | Signing subkey (flags S) |
|---|---|---|
| Debian Archive Automatic Signing Key (12/bookworm) | `B8B80B5B623EAB6AD8775C45B7C5D7D6350947F8` rsa4096, 2023-01-21, exp 2031-01-19 | `4CB50190207B4758A3F73A796ED0E7B82643E131` rsa4096, exp **2031-01-19** |
| Debian Archive Automatic Signing Key (13/trixie) | `04B54C3CDCA79751B16BC6B5225629DF75B188BD` rsa4096, 2025-03-30, exp 2035-03-28 | `B8E5F13176D2A7A75220028078DBA3BC47EF2265` rsa4096, exp **2035-03-28** |
| Debian Stable Release Key (13/trixie) | `41587F7DB8C774BCCF131416762F67A0B2C39DE4` ed25519 (EdDSA 22), 2025-03-24, exp **2033-03-22**, signs with the primary | - |

The two archive keys list 5 designated revokers (subpacket 12, "Revocable by"). Ignore them.

Signatures (all v4, hash 8 SHA2-256):

| | `Release.gpg` (armored detached, type 0x00) | `InRelease` (clearsigned, `Hash: SHA256`, type 0x01) |
|---|---|---|
| 1 | RSA, subkey 4CB5...E131 (bookworm), 2026-09-12T07:56:17Z | RSA, subkey 4CB5...E131, 2026-09-12T07:56:18Z |
| 2 | RSA, subkey B8E5...2265 (trixie), 2026-09-12T07:56:17Z | RSA, subkey B8E5...2265, 2026-09-12T07:56:19Z |
| 3 | EdDSA, primary 4158...9DE4, 2026-09-12T07:57:47Z (`s` MPI 251 bits) | EdDSA, primary 4158...9DE4, 2026-09-12T07:57:47Z |

* gpg with `debian-keyring.gpg`: three `Good signature` lines, `[exit code: 0]`, for both
  `Release.gpg Release` and `InRelease`.
* gpg with `archive-key-13-only.gpg`: `Can't check signature: No public key` (bookworm),
  `Good signature from "Debian Archive Automatic Signing Key (13/trixie) <ftpmaster@debian.org>"`,
  `Can't check signature: No public key` (release key), `[exit code: 2]`.
* **Expected (strict):** full keyring: **VALID, 3/3 good**. Trixie-only keyring: 1 good + 2 unknown
  signers. The overall verdict depends on the API's multi-signature policy: "at least one valid
  signature from a provided key" gives VALID, "all signatures must verify" gives INVALID. Test both
  if the API exposes per-signature results.

---

# Part 2 - GnuPG-generated fixtures (`gnupg-generated/`)

How they were generated: gpg 2.4.9 with `--batch --pinentry-mode loopback --passphrase ''` and a
throwaway `GNUPGHOME`. `--faked-system-time <T>!` froze the clock, so creation, expiration and
revocation times are deterministic. Unless noted, keys were created at **2025-01-01T00:00:00Z** (Unix
1735689600) and signatures at **2025-01-02T12:00:00Z** (Unix 1735819200). All keys and signatures
are **v4**. Every signature carries an issuer-fingerprint subpacket (33, v4) in the hashed area and
an issuer key ID subpacket (16) in the unhashed area. Files follow this pattern:

* `public-key.asc` / `public-key.gpg`: armored and binary export of the certificate;
* `data.txt.asc`: armored detached signature (type 0x00);
* `data.txt.sig`: binary detached signature (type 0x00);
* `data.txt.clearsign.asc`: clearsigned `data.txt` (type 0x01).

Each of these holds exactly **one** signature packet unless stated otherwise.

## 2.1 Primary-key signatures per algorithm (`v4-<algo>`)

Every key is a single primary key with flags **SC** (0x03), no subkeys and no expiration. All
three signature files are made by the primary key. For every file, gpg prints
`gpgv: Good signature from "Scarlet <algo> <<algo>@example.org>"` and `[exit code: 0]`.
**Expected (strict): VALID for every file.**

| Folder | Primary fingerprint | Pubkey algo | Hash (`data.txt.{asc,sig,clearsign.asc}`) | Extra files |
|---|---|---|---|---|
| `v4-rsa3072` | `61E00ACDA21367249EBCFF8CC35ACCBC40F4CE54` | 1 RSA 3072 | 8 SHA2-256 | `data.txt.sha512.sig` (10), `data.txt.sha384.sig` (9), `data.txt.sha224.sig` (11), `data.txt.sha1.sig` (2) - binary detached |
| `v4-dsa2048` | `3BFC0236D528CB2B88825338ED8005C4CFDD2E2C` | 17 DSA 2048 (q = 256 bits) | 8 SHA2-256 | - |
| `v4-dsa3072` | `99DA89BA18421DE078CB2EE4B825B73F1A8A48F4` | 17 DSA 3072 | 8 SHA2-256 | - |
| `v4-ecdsa-nistp256` | `227F94A7ECE5D9B722876D9458F417BCC59F56B4` | 19 ECDSA NIST P-256 | 8 SHA2-256 | - |
| `v4-ecdsa-nistp384` | `62064211128E8D9969943641F6F407BCC7DBBDAE` | 19 ECDSA NIST P-384 | 9 SHA2-384 | - |
| `v4-ecdsa-nistp521` | `EFCB8696145F9024EE2BFAD888AC494F4C6A15B2` | 19 ECDSA NIST P-521 | 10 SHA2-512 | - |
| `v4-ecdsa-brainpoolp256r1` | `87F81D3CBF16A5EE36D9CC2DA0ED38FC69CAE187` | 19 ECDSA brainpoolP256r1 | 8 SHA2-256 | - |
| `v4-ecdsa-brainpoolp384r1` | `199F9E7E04F340CE7E4CE152A3C9142A7E15E0F0` | 19 ECDSA brainpoolP384r1 | 9 SHA2-384 | - |
| `v4-ecdsa-brainpoolp512r1` | `042C74706EBAFF3E5EFB151FF7673F1DF215896A` | 19 ECDSA brainpoolP512r1 | 10 SHA2-512 | - |
| `v4-eddsa-ed25519-legacy` | `F94DD31C085818C5887DD8C4F62AB74245BDF00E` | 22 EdDSA (Ed25519Legacy, OID 1.3.6.1.4.1.11591.15.1) | 8 SHA2-256 | `data.txt.sha512.sig` (10) |

Notes:
* Exception to "VALID for every file": `v4-rsa3072/data.txt.sha1.sig` (SHA-1, created 2025-01-02).
  gpg says `Good signature` with exit 0. **Expected (strict): INVALID / rejected** under RFC 9580
  §9.5: "Implementations MUST NOT validate any recent signature that depends on MD5, SHA-1, or
  RIPEMD-160". If the library chooses to allow SHA-1, treat this file as the policy test.
  `data.txt.sha224.sig` (SHA2-224) is VALID.
* ECDSA/DSA `r`/`s` MPIs are sometimes shorter than the field size (for example 254-bit values in
  `v4-signing-subkey`, 255-bit `s` in `v4-dsa2048`). They need left-padding.
* Exact packet details (begin-of-digest bytes, MPI bit lengths) are in each folder's `gpg-packets.txt`.

## 2.2 `v4-signing-subkey`: signing via a subkey, certify-only primary

* Primary `9DB4A83ABF3FF7BAE1E205862DEEF822DFBFB6CB`, rsa3072, flags **C only (0x01)**, created 2025-01-01T00:00:00Z.
* Signing subkey `CC4D3084176105CC24EB67687B8B6791D30CB959` (key ID 7B8B6791D30CB959), **nistp256 ECDSA**,
  flags **S (0x02)**, created 2025-01-01T00:01:00Z, no expiration. The binding signature 0x18 contains
  an embedded **0x19 back-signature** (subpacket 32: "signature: v4, class 0x19, algo 19, digest algo 8").
* Encryption subkey `1131267B3EB47637B93DDB0DE4E7A829531EB00B`, cv25519 (ECDH), flags **E (0x0C)**,
  created 2025-01-01T00:02:00Z. It must never be accepted as a signer.
* `public-key.packets.txt` has the full certificate packet dump.
* Signatures `data.txt.asc` / `data.txt.sig` (type 0x00) and `data.txt.clearsign.asc` (0x01) use
  alg 19, hash 8, are created 2025-01-02T12:00:00Z, and carry issuer fingerprint = **subkey** CC4D...B959.
* gpg: `gpgv:                using ECDSA key CC4D3084176105CC24EB67687B8B6791D30CB959` /
  `gpgv: Good signature from "Scarlet Subkey <subkey@example.org>"`, `[exit code: 0]` for all 3.
* **Expected (strict): VALID** (signer = signing subkey; primary 9DB4...B6CB).
* Scenario 9 (signature by the certify-only primary) **could not be produced**:
  `gpg -u 9DB4A83ABF3FF7BAE1E205862DEEF822DFBFB6CB! --detach-sign` fails with
  `gpg: skipped "9DB4...B6CB!": Unusable secret key` / `gpg: signing failed: Unusable secret key`
  (exit 2). gpg refuses to sign data with a key that lacks the S flag.

## 2.3 `v4-textmode`: text-mode (0x01) detached signatures, LF vs CRLF

Key: `3AB36259BA08956C0472DFEB9409386295E89F80`, ed25519 (EdDSA 22), flags SC, created 2025-01-01.
All signatures use hash 8, are created 2025-01-02T12:00:00Z, and are made by the primary key.

| File | What |
|---|---|
| `data-lf.txt` | the shared data file (LF), SHA-256 `e6c603c5...08fdd0` |
| `data-crlf.txt` | the same text with CRLF line endings (229 B), SHA-256 `746d6f61...0c77c` |
| `data-lf-trailing-ws-stripped.txt` | LF version with the trailing spaces removed from line 2 (219 B) |
| `data-lf.txt.textmode.sig` | `gpg --textmode --detach-sign data-lf.txt`, binary, **type 0x01** |
| `data-lf.txt.textmode.asc` | same, armored, type 0x01 |
| `data-crlf.txt.textmode.sig` | `gpg --textmode --detach-sign data-crlf.txt`, binary, type 0x01 |
| `data-lf.txt.binary.sig` | non-textmode signature of `data-lf.txt` (type 0x00) |
| `data-crlf.txt.binary.sig` | non-textmode signature of `data-crlf.txt` (type 0x00) |

gpg verdicts (`gpgv --keyring ./public-key.gpg <sig> <data>`):

| Signature | Data | gpg | Exit | Expected (strict) |
|---|---|---|---|---|
| data-lf.txt.textmode.sig | data-lf.txt | Good signature | 0 | VALID |
| data-lf.txt.textmode.asc | data-lf.txt | Good signature | 0 | VALID |
| data-crlf.txt.textmode.sig | data-crlf.txt | Good signature | 0 | VALID |
| data-lf.txt.textmode.sig | **data-crlf.txt** | Good signature | 0 | VALID (0x01 canonicalises line endings to CRLF) |
| data-crlf.txt.textmode.sig | **data-lf.txt** | Good signature | 0 | VALID |
| data-lf.txt.textmode.sig | data-lf-trailing-ws-stripped.txt | **BAD signature** | 1 | INVALID. Detached 0x01 signatures do **not** strip trailing whitespace; only the cleartext framework does |
| data-lf.txt.binary.sig | data-lf.txt | Good signature | 0 | VALID |
| data-crlf.txt.binary.sig | data-crlf.txt | Good signature | 0 | VALID |
| data-lf.txt.binary.sig | data-crlf.txt | **BAD signature** | 1 | INVALID (0x00 is byte-exact) |
| data-crlf.txt.binary.sig | data-lf.txt | **BAD signature** | 1 | INVALID |

## 2.4 `v4-multi-signer`: one detached signature / clearsign made by two keys

* Signer A: `6DB026C45610A2FDE7F5FB52D848DB657D349208`, ed25519 (EdDSA 22), flags SC, "Scarlet Signer A <signer-a@example.org>".
* Signer B: `A020E82754904E60FDAA1EA10972DC74CD762769`, rsa3072, flags SC, "Scarlet Signer B <signer-b@example.org>".
* Keyrings: `keyring-both.{asc,gpg}` (A then B), `keyring-a-only.{asc,gpg}`, `keyring-b-only.{asc,gpg}`.
  The `.asc` versions hold several certificates in one armor block.
* Signatures, made with `-u A -u B` (hash 8, 2025-01-02T12:00:00Z), each holding **2 signature
  packets in the order A (alg 22) then B (alg 1)**:
  `data.txt.asc` (armored detached, 0x00), `data.txt.sig` (binary detached, 0x00),
  `data.txt.clearsign.asc` (clearsigned, 0x01, a single `Hash: SHA256` header).

| Keyring | gpgv output (all three files the same) | Exit | Expected (strict) |
|---|---|---|---|
| keyring-both | `Good signature from "Scarlet Signer A ..."` + `Good signature from "Scarlet Signer B ..."` | 0 | VALID, 2/2 |
| keyring-a-only | `Good signature from "Scarlet Signer A ..."` + `Can't check signature: No public key` | 2 | A valid, B unknown signer. VALID under "any provided key verified", INVALID under "all must verify" |
| keyring-b-only | `Can't check signature: No public key` + `Good signature from "Scarlet Signer B ..."` | 2 | B valid, A unknown signer (same policy note) |

## 2.5 `v4-expired-key`: key expired since the signature was made

* Key `545CBD1CAAA8DAEC91870466B2A3A82232517473`, ed25519, flags SC, created **2020-01-01T00:00:00Z**,
  key-expiration subpacket "1y0d0h0m" (31536000 s), so it **expired 2020-12-31T00:00:00Z**.
* `data.txt.while-valid.{sig,asc,clearsign.asc}`: hash 8, created **2020-06-01T12:00:00Z**, while the key was valid.
* A signature made *after* expiry could not be produced. With faked time 2021-06-01 gpg refuses:
  `gpg: no default secret key: Unusable secret key` / `signing failed: Unusable secret key`.
* gpgv: `Good signature from "Scarlet Expired Key <expired-key@example.org>"`, `[exit code: 0]` (gpgv ignores expiry).
* gpg --verify: `Good signature from "Scarlet Expired Key <expired-key@example.org>" [expired]` /
  `gpg: Note: This key has expired!`, `[exit code: 0]`.
* **Expected (strict): INVALID (key expired at verification time).** The signature itself is
  cryptographically good: with a pinned verification time before 2020-12-31 the expected result is VALID.

## 2.6 `v4-expired-signature`: signature expiration subpacket

* Key `86157C13E679089AF133BE536D975BDE5DB498C1`, ed25519, flags SC, created 2020-01-01, no key expiration.
* `data.txt.expired-1d.{sig,asc,clearsign.asc}`: created **2020-01-02T12:00:00Z**, **critical**
  hashed subpacket 3 "sig expires after 1d0h0m", so the signature **expired 2020-01-03T12:00:00Z**.
  gpg: `gpgv: Expired signature from "Scarlet Sig Expire <sig-expire@example.org>"` /
  `gpgv: Signature expired Fri Jan  3 12:00:00 2020 GMT`, **`[exit code: 1]`**.
  **Expected (strict): INVALID (signature expired).**
* `data.txt.expires-2099.{sig,asc,clearsign.asc}`: created 2020-01-02T12:00:00Z, critical subpacket 3
  "79y19d0h0m", so it expires **2099-01-01T12:00:00Z**.
  gpg: `Good signature ...` / `Signature expires Thu Jan  1 12:00:00 2099 GMT`, `[exit code: 0]`.
  **Expected (strict): VALID** (a critical subpacket 3 must be understood, not rejected as unknown-critical).

## 2.7 Revoked primary keys: `v4-revoked-key-hard`, `v4-revoked-key-soft`

Both: ed25519 primary, flags SC, created 2020-01-01T00:00:00Z. Key revocation signature **0x20**
created **2020-03-01T12:00:00Z**. Each folder has:
* `public-key.{asc,gpg}`: the certificate **including** the 0x20 revocation;
* `public-key-unrevoked.{asc,gpg}`: the same certificate exported before revocation (control);
* `data.txt.before-revocation.{sig,asc,clearsign.asc}`, created **2020-02-01T12:00:00Z**;
* `data.txt.after-revocation.{sig,asc,clearsign.asc}`, created **2020-04-01T12:00:00Z**. gpg only
  refuses to sign with a revoked key, so this one was made before the revocation was applied,
  with a later faked clock.

| Folder | Fingerprint | Revocation reason (subpacket 29) |
|---|---|---|
| `v4-revoked-key-hard` | `DD1658A38D9EB40A29B2F815C83B6D337E988A5A` | **0x02 key compromised** ("Key material compromised (fixture)") - hard |
| `v4-revoked-key-soft` | `E30EE8CD98A4B2561EBD6854A827C7816A626447` | **0x01 key superseded** ("Superseded by a new key (fixture)") - soft |

gpg: `gpgv` says `Good signature` with exit 0 for every file (no revocation check). `gpg --verify`
says `Good signature ...` + `WARNING: This key has been revoked by its owner!` +
`reason for revocation: Key has been compromised` (or `Key is superseded`) + `revocation comment: ...`,
**exit 0** for all files.

| Folder | Signature | Expected (strict) |
|---|---|---|
| hard | before-revocation | **INVALID** (hard revocation invalidates all signatures, past and future) |
| hard | after-revocation | **INVALID** |
| soft | before-revocation | **VALID** (made before the soft revocation took effect) |
| soft | after-revocation | **INVALID** (made after the revocation time) |
| either | any, with `public-key-unrevoked.*` | VALID (control) |

## 2.8 Revoked signing subkeys: `v4-revoked-subkey-hard`, `v4-revoked-subkey-soft`

Both: ed25519 primary with flags **C only**, created 2020-01-01T00:00:00Z. The ed25519 signing
subkey has flags **S** and was created 2020-01-01T00:01:00Z. Its binding signature 0x18 carries a
0x19 back-signature (EdDSA, SHA2-512). The **subkey** is revoked with 0x28 at **2020-03-01T12:00:00Z**.
The primary key is not revoked. Files are as in 2.7 (signatures are made by the subkey).

| Folder | Primary | Signing subkey | Reason |
|---|---|---|---|
| `v4-revoked-subkey-hard` | `5CC3136133F4130E3FD67A4A19BCF7846D1BCEF0` | `F476D06770DD92E25DCBD4022B499F4C19C6CB03` | **0x02 compromised** (hard) |
| `v4-revoked-subkey-soft` | `E2C042C4C5362753CE168B1855F6342C0C7B4C27` | `9164E55270C6EBE8E57D5A7D11106F925C161A3B` | **0x01 superseded** (soft) |

gpg: `gpgv` says `Good signature` with exit 0 for all. `gpg --verify` says `Good signature ...` +
`WARNING: This subkey has been revoked by its owner!` + `reason for revocation: ...`, exit 0.

**Expected (strict):** hard: before = **INVALID**, after = **INVALID**. Soft: before = **VALID**,
after = **INVALID**. With `public-key-unrevoked.*`, all are VALID.

## 2.9 `v4-expired-subkey`: signing subkey expired (via its binding signature)

* Primary `D59EE7B65D68E9E585A7727D6BB80F9D564622CB`, ed25519, flags **C**, created 2020-01-01, no expiration.
* Signing subkey `DE2992042C99BF46FCEB89C2546143853CEA7B81` (key ID 546143853CEA7B81), **nistp256 ECDSA**,
  flags S, created 2020-01-01T00:01:00Z. The binding signature has "key expires after 1y0d0h0m",
  so the subkey **expired 2020-12-31T00:01:00Z**. The binding signature itself does not expire.
* `data.txt.while-valid.{sig,asc,clearsign.asc}`: alg 19, hash 8, created 2020-06-01T12:00:00Z.
  A signature after expiry could not be produced (gpg: `Unusable secret key`).
* gpgv: `Good signature from "Scarlet Expired Subkey <expired-subkey@example.org>"`, exit 0.
  gpg --verify: `Good signature ...` + `gpg: Note: This key has expired!` and both fingerprints, exit 0.
* **Expected (strict): INVALID (signing subkey expired at verification time)**. With a verification
  time before 2020-12-31 the result is VALID. The primary key is still valid, so the failure must
  come from the subkey's own expiration.

## 2.10 `librepgp-v5-ed448-unsupported`: negative, non-RFC-9580 key version

gpg 2.4 can only make Ed448 keys in LibrePGP mode (`--compliance=gnupg`). That produces a **v5**
key and **v5** signatures, which are neither v4 nor RFC 9580 v6. Note that the signature uses alg
**22** with the Ed448 OID (1.3.101.113), not alg 28.

* Key `C87F3887595E494FE65A8FD6053DC65AEA4063420463D7CC43112B84D8BA20F8` (32-byte v5 fingerprint), ed448, flags SC.
* `data.txt.sig` / `.asc` / `.clearsign.asc`: v5 signatures, hash 10 SHA2-512, created 2025-01-02T12:00:00Z.
* gpg: `Good signature from "Scarlet Ed448 v5 <ed448@example.org>"`, exit 0 (gpg understands its own v5).
* **Expected (strict): not verifiable.** The library should report an unsupported key/signature
  version (or skip the v5 packets) cleanly, without crashing or throwing a parser exception. The
  result must never be VALID.

---

# Part 3 - RFC 9580 Appendix A vectors (`rfc9580/`)

Source: https://www.rfc-editor.org/rfc/rfc9580.txt (fetched 2026-10-17). Blocks were copied with the
3-space indentation removed and LF line endings. The plain-text RFC on rfc-editor.org has no form
feeds or "Wouters, et al." page-break lines inside these blocks. That was checked for lines
7575-8095, so nothing had to be stripped. Armor blocks are byte-identical to the RFC, and **none has
a CRC24 checksum line** (optional in RFC 9580 §6.1).

| File | RFC section | Content |
|---|---|---|
| `a1-v4-ed25519legacy-key.asc` | A.1 (RFC lines 7608-7612) | v4 EdDSA-legacy public key, armored. **Bare key packet only**: no user ID, no self-signature. New-format CTB 0xC6 |
| `a1-v4-ed25519legacy-key.gpg` | A.1 hex dump (lines 7601-7604) | same packet, binary, **old-format CTB 0x98** (53 bytes). Same packet body as the armored version, different header encoding |
| `a2-v4-ed25519legacy-sig.asc` | A.2 (lines 7644-7648) | v4 EdDSA-legacy signature, armored |
| `a2-v4-ed25519legacy-sig.sig` | A.2 hex dump (lines 7635-7640) | same, binary (96 bytes, CTB 0x88). Identical to the dearmored `.asc` |
| `a2-signed-data.txt` | A.2 text | the 7 bytes `OpenPGP` (no newline) |
| `a3-v6-certificate.asc` | A.3 (lines 7670-7681) | v6 certificate: Ed25519 (alg 27) primary + v6 direct-key self-signature 0x1F + X25519 (alg 25) subkey + v6 subkey binding 0x18 |
| `a3-v6-certificate.gpg` | A.3 | dearmored binary of the above (424 bytes) |
| `a6-cleartext-signed.asc` | A.6 (lines 7953-7967) | v6 cleartext-signed message (dash-escaped lines, **no `Hash:` header**) |
| `a7-inline-signed.asc` | A.7 (lines 8082-8091) | the same message and signature as an inline-signed message (v6 one-pass-sig + literal + v6 sig) - data only |
| `a6-a7-message.txt` | A.6/A.7 | the signed text with LF endings (`What we need from the grocery store:\n\n- tofu\n- vegetables\n- noodles\n`). Equals the A.7 literal-data body and the cleartext recovered from A.6 |

Facts and expected verdicts:

* **A.1 key**: fingerprint `C959BDBAFA32A2F89A153B678CFDE12197965A9A`, key ID `8CFDE12197965A9A`,
  created 2014-08-19T14:28:27Z (Unix 1408458507), alg 22, curve OID 2B06010401DA470F01 (Ed25519 legacy).
* **A.2 signature**: v4, type 0x00, alg 22, hash 8 SHA2-256, created 2015-09-16T12:24:53Z. Hashed area:
  creation time only. **No issuer fingerprint**: the unhashed area has only issuer key ID
  8CFDE12197965A9A, so the key must be matched by key ID. `r`/`s` are given in the RFC.
  **Expected: VALID over `a2-signed-data.txt` with the A.1 key.** Caveat: A.1 is a bare primary key
  with no self-signature or user ID. If the library requires a transferable public key (uid +
  self-signature), it will reject A.1 as a certificate. In that case use a low-level packet API, or
  expect "invalid certificate". gpg cannot verify this vector: it will not import a key without a
  user ID (`gpg: key 8CFDE12197965A9A: new key but contains no user ID - skipped`). `gpgv` reports
  `Can't check signature: No public key`, exit 2. gpg also prints `no valid OpenPGP data found.`
  for the checksum-less armored A.2, although it still decodes the signature.
* **A.3 certificate**: primary fingerprint (v6, 32 bytes)
  `CB186C4F0609A697E4D52DFA6C722B0C1F1E27C18A56708F6525EC27BAD9ACC9`, subkey fingerprint
  `12C83F1E706F6308FE151A417743A1F033790E93E9978488D1DB378DA9930885`. Both keys were created 2022-11-30T16:08:03Z
  (0x63877FE3). It has no user ID: v6 key properties live in the direct-key signature (A.3.1 gives the
  exact hashed data stream). **Expected: valid v6 certificate.** The primary is signing-capable
  (key flags 0x03 in the direct-key signature). The X25519 subkey (flags 0x0C, encryption) must not
  be accepted as a signer.
* **A.6 cleartext**: v6 signature, type **0x01**, alg **27 Ed25519**, hash **10 SHA2-512**, created
  **2022-12-13T16:08:03Z**, 32-byte **salt** `76495F50218890F7F5E2EE3C1822514F70500F551D86E5C921E404E34A53FBAC`,
  issuer fingerprint v6 = A.3 primary. The signed text is the CRLF-canonical form of
  `a6-a7-message.txt` (RFC lines 8011-8030 show the exact hashed bytes; the SHA2-512 digest is at
  lines 8073-8074). **Expected: VALID with `a3-v6-certificate.*`.** The missing `Hash:` header must
  be accepted (RFC 9580 §6.2.2.3: the Hash armor header is deprecated and SHOULD NOT be emitted for v6 signatures).
* **A.7 inline-signed**: **Expected: VALID with A.3** if inline-signed messages are supported. Otherwise
  it is only data (this library is verify-only for detached and cleartext signatures). The hashed
  data is identical to A.6.
* gpg 2.4.9 cannot handle v6. `gpgv --keyring ./a3-v6-certificate.gpg a6-cleartext-signed.asc` prints
  `gpgv: packet(2) with unknown version 6` / `gpgv: no signature found`, `[exit code: 2]`.
  For A.7 it prints `gpgv: onepass_sig with unknown version 6`, exit 2. (See `rfc9580/gpg-output.txt`.)
* RFC 9580 has **no v4 Ed25519 (alg 27) sample**. A.1/A.2 use EdDSA-legacy alg 22. The only
  alg 27 vectors are the v6 ones above. The A.4/A.5 secret keys were deliberately not copied
  (verify-only library).

---

# Scenarios not produced (and why)

| Requested | Status |
|---|---|
| Signature made by a **certify-only primary** (scenario 9) | Not producible with gpg 2.4.9: `-u <fpr>!` gives `Unusable secret key`. |
| Signature made **after** key/subkey expiry | gpg refuses to sign with an expired key or subkey (`Unusable secret key`), even with a faked clock. Only "signed while valid, verified after expiry" exists (2.5, 2.9). |
| Encryption-only subkey used as signer | gpg will not sign with it. `v4-signing-subkey` and `nodejs-clearsign-rsa` contain E-only subkeys a verifier must ignore. |
| **v6 keys/signatures, native Ed25519 (alg 27) / Ed448 (alg 28)** made by GnuPG | gpg 2.4.9 does not implement RFC 9580 v6 or algs 27/28. v6/alg 27 coverage comes only from the RFC vectors (Part 3). No Ed448 (alg 28) or v4-alg-27 vector is available. The only Ed448 material is the LibrePGP v5 negative fixture (2.10). Other tools (Sequoia `sq`, RNP) are not installed, and running downloaded binaries or containers was out of scope. |
| Real-world ECDSA (NIST/brainpool) **data** signature | None found in a small file. Brainpool certificates (with brainpool self-signatures) are in `gnupg-npth-multisig`. NIST/brainpool data signatures are covered by Part 2.1. |
| Real-world v6 key | None found in a cheap, small, verifiable form. |
| curl `.asc` | Skipped because curl tarballs are several MB. Armored detached RSA signatures are covered by `tor-browser-subkey` (subkey) and `debian-trixie-release/Release.gpg` (3 signatures). |
| Debian/GnuPG/Tor/Node artifacts are snapshots | Upstream files change over time. These fixtures are frozen copies; re-downloading may produce different bytes. |

## openpgpjs-v6

v6 (RFC 9580) keys and signatures from OpenPGP.js 6.3.2 - an independent implementation, so v6
support is checked against a real producer rather than only the RFC vectors and certificates
assembled in tests. Run by `Fixtures/OpenPgpJsInteropTests.cs`. Each folder holds `public-key.asc`,
`data.txt` (LF endings, a line with trailing spaces, a line starting with a dash), a binary detached
signature `data.txt.sig`, a text-mode detached signature `data.txt.textmode.asc` and a clearsigned
`data.txt.clearsign.asc`. Keys created 2026-01-01, signatures made 2026-01-02, nothing expires.

| Folder | Key |
|---|---|
| v6-ed25519 | Ed25519 primary (algorithm 27) signs |
| v6-ed448 | Ed448 primary (28) signs |
| v6-ed25519-signing-subkey | Ed25519 signing subkey (v6 binding + back-signature) signs |
| v6-rsa3072 | RSA 3072 primary signs |
| v6-ecdsa-nistp256 | ECDSA P-256 primary signs |

Regenerate with `npm install --save-exact openpgp@6.3.2` and `node generate.mjs <folder>`; v6
salts and keys are random, so the fingerprints in the tests must be updated from its output.

## wycheproof

Project Wycheproof's signature-verification vectors (https://github.com/C2SP/wycheproof,
`testvectors_v1`, Apache License 2.0 - copied as `wycheproof/LICENSE`), run by
`Crypto/WycheproofTests.cs` against each verifier: Ed25519 (151 vectors), Ed448 (87), ECDSA on
NIST P-256/384/521 and brainpoolP256/384/512r1 in IEEE P1363 form (1,750), DSA 2048/3072 (524), and
RSA PKCS#1 v1.5 2048/3072/4096 with SHA-2 and SHA-3 (3,620). An "invalid" vector must never
verify; a "valid" one must.

Vendored, not downloaded in CI, so the build is deterministic and an upstream change can't alter
it without a reviewed commit. To refresh: download the same file names from
`https://raw.githubusercontent.com/C2SP/wycheproof/main/testvectors_v1/` over the existing ones,
run the tests, and investigate any disagreement before committing.

## Time-sensitivity summary (for tests that use the real clock)

| Fixture | Becomes INVALID on (key/subkey expiry) |
|---|---|
| tor-browser-subkey | 2028-11-28 (signing subkey 022D...07D9) |
| gnupg-npth-multisig | Niibe sig: 2027-04-04; Werner sig: 2030-06-30 |
| debian-trixie-release | bookworm subkey sig: 2031-01-19; release-13 sig: 2033-03-22; trixie subkey sig: 2035-03-28 |
| nodejs-clearsign-rsa | never (no expiration) |
| gnupg-generated (non-expiry folders) | never (no expirations), except 2.6's `expires-2099` signature on 2099-01-01T12:00:00Z |

Prefer passing a fixed verification time if the API allows it.
