using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using Scarlet.OpenPgp.Armor;
using Scarlet.OpenPgp.Internal;
using Scarlet.OpenPgp.Packets;
using Scarlet.OpenPgp.Signing;

namespace Scarlet.OpenPgp
{
    /// <summary>
    /// The public keys you trust, parsed once and reusable for any number of verifications. Every
    /// certificate's self-signatures are checked cryptographically once, here, so repeated
    /// verifications don't redo that work.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Parsing succeeds when the input is well-formed key data holding at least one supported
    /// certificate; input that isn't (bad armor or packets, the wrong kind of data, a certificate
    /// over the size limits) is rejected here. A successful parse does not mean every key may sign:
    /// a key can be well-formed yet unusable - revoked, expired, unbound, or carrying self-signatures
    /// that can't be checked or that contradict each other. That is decided per use, against a
    /// time; <see cref="OpenPgpKey.GetStatus"/> reports it for inspection.
    /// </para>
    /// <para>
    /// Immutable and safe to share between threads. Whether a key is expired, revoked as of a
    /// signature's time, or allowed to sign is decided at each verification, so a key that expires
    /// while the application runs stops verifying.
    /// </para>
    /// </remarks>
    public sealed class OpenPgpKeyRing
    {
        private const string PublicKeyLabel = "PUBLIC KEY BLOCK";

        private OpenPgpKeyRing(KeyRing inner)
        {
            Inner = inner;
            Certificates = Array.AsReadOnly(inner.Certificates.Select(c => new OpenPgpCertificate(c)).ToArray());
        }

        /// <summary>The certificates in the key ring, in input order, copies of the same certificate merged. Certificates this library can't use (an unsupported key version or algorithm) are left out.</summary>
        public IReadOnlyList<OpenPgpCertificate> Certificates { get; }

        internal KeyRing Inner { get; }

        /// <summary>Parses ASCII-armored public key(s): one or more certificates, in one or several armor blocks.</summary>
        /// <exception cref="ArgumentNullException"><paramref name="armoredKeys"/> is <c>null</c>.</exception>
        /// <exception cref="OpenPgpFormatException">The input contains no usable certificate.</exception>
        public static OpenPgpKeyRing Parse(string armoredKeys)
        {
            if (armoredKeys is null)
            {
                throw new ArgumentNullException(nameof(armoredKeys));
            }

            return ParseOrThrow(() => PacketInput.Decode(armoredKeys, PublicKeyLabel));
        }

        /// <summary>Parses public key(s), ASCII-armored (.asc) or binary (.gpg): one or more certificates.</summary>
        /// <exception cref="OpenPgpFormatException">The input contains no usable certificate.</exception>
        public static OpenPgpKeyRing Parse(ReadOnlySpan<byte> keys)
        {
            byte[] copy = keys.ToArray();
            return ParseOrThrow(() => PacketInput.Decode(copy, PublicKeyLabel));
        }

        /// <summary>Parses ASCII-armored public key(s), reporting failure instead of throwing.</summary>
        /// <param name="armoredKeys">The armored keys; <c>null</c> fails like any other unusable input.</param>
        /// <param name="keyRing">The key ring, when parsing succeeded.</param>
        /// <param name="error">Why parsing failed, when it did.</param>
        public static bool TryParse([NotNullWhen(true)] string? armoredKeys, [NotNullWhen(true)] out OpenPgpKeyRing? keyRing, [NotNullWhen(false)] out string? error)
        {
            if (armoredKeys is null)
            {
                keyRing = null;
                error = "The public key input is null.";
                return false;
            }

            return TryParse(() => PacketInput.Decode(armoredKeys, PublicKeyLabel), out keyRing, out error);
        }

        /// <summary>Parses public key(s), ASCII-armored or binary, reporting failure instead of throwing.</summary>
        /// <param name="keys">The armored or binary keys.</param>
        /// <param name="keyRing">The key ring, when parsing succeeded.</param>
        /// <param name="error">Why parsing failed, when it did.</param>
        public static bool TryParse(ReadOnlySpan<byte> keys, [NotNullWhen(true)] out OpenPgpKeyRing? keyRing, [NotNullWhen(false)] out string? error)
        {
            byte[] copy = keys.ToArray();
            return TryParse(() => PacketInput.Decode(copy, PublicKeyLabel), out keyRing, out error);
        }

        private static OpenPgpKeyRing ParseOrThrow(Func<byte[]> decode)
        {
            if (!TryParse(decode, out OpenPgpKeyRing? keyRing, out string? error))
            {
                throw new OpenPgpFormatException(error);
            }

            return keyRing;
        }

        private static bool TryParse(Func<byte[]> decode, [NotNullWhen(true)] out OpenPgpKeyRing? keyRing, [NotNullWhen(false)] out string? error)
        {
            try
            {
                keyRing = new OpenPgpKeyRing(KeyRing.Parse(decode()));
                error = null;
                return true;
            }
            catch (FailClosedException ex)
            {
                keyRing = null;
                error = "The public key input is unusable: " + ex.Message;
                return false;
            }
        }
    }

    /// <summary>A certificate (transferable public key): a primary key, its User IDs, and its subkeys. Read-only.</summary>
    public sealed class OpenPgpCertificate
    {
        internal OpenPgpCertificate(Certificate certificate)
        {
            PrimaryKey = new OpenPgpKey(certificate, certificate.Primary);
            Subkeys = Array.AsReadOnly(certificate.Keys.Skip(1).Select(k => new OpenPgpKey(certificate, k)).ToArray());
            UserIds = Array.AsReadOnly(certificate.UserIds.ToArray());
        }

        /// <summary>The primary key, whose fingerprint identifies the certificate.</summary>
        public OpenPgpKey PrimaryKey { get; }

        /// <summary>The subkeys this library could parse, in certificate order - signing and encryption subkeys alike.</summary>
        public IReadOnlyList<OpenPgpKey> Subkeys { get; }

        /// <summary>The User IDs (e.g. "Name &lt;email&gt;") bound by a valid self-signature. Informational only: nothing here vouches that the name is true.</summary>
        public IReadOnlyList<string> UserIds { get; }

        /// <summary>The primary key's fingerprint.</summary>
        public override string ToString() => PrimaryKey.Fingerprint;
    }

    /// <summary>A primary key or subkey of an <see cref="OpenPgpCertificate"/>. Read-only.</summary>
    public sealed class OpenPgpKey
    {
        private readonly Certificate _certificate;
        private readonly PublicKeyPacket _key;

        internal OpenPgpKey(Certificate certificate, PublicKeyPacket key)
        {
            _certificate = certificate;
            _key = key;
        }

        /// <summary>The fingerprint, uppercase hex (40 characters for v4 keys, 64 for v6).</summary>
        public string Fingerprint => _key.Fingerprint.ToString();

        /// <summary>The 64-bit key ID, uppercase hex.</summary>
        public string KeyId => string.Concat(_key.Fingerprint.KeyId.Select(b => b.ToString("X2", System.Globalization.CultureInfo.InvariantCulture)));

        /// <summary>The key version: 4 (RFC 4880) or 6 (RFC 9580).</summary>
        public int Version => _key.Version;

        /// <summary>A human-readable algorithm description, e.g. "RSA 4096", "ECDSA NIST P-256", "Ed25519".</summary>
        public string Algorithm => _key.AlgorithmDescription;

        /// <summary>Whether this library can verify signatures made with this key's algorithm. Encryption-only keys (ECDH, X25519, ...) can't make signatures.</summary>
        public bool SupportsVerification => _key.CanVerify;

        /// <summary>When the key was created.</summary>
        public DateTimeOffset CreatedAt => _key.CreatedAt;

        /// <summary>
        /// Whether the certificate contains a valid revocation of this key. A soft revocation
        /// ("superseded", "retired") still lets signatures made before it verify.
        /// </summary>
        public bool IsRevoked => _certificate.IsRevoked(_key);

        /// <summary>
        /// The key's standing at <paramref name="at"/>: whether a signature it made then would be
        /// accepted as far as the key is concerned (not revoked, not expired, bound and allowed to
        /// sign), why not if not, and when it expires. The same rules verification applies.
        /// </summary>
        /// <param name="at">The moment to judge; the current time when <c>null</c>.</param>
        public OpenPgpKeyStatus GetStatus(DateTimeOffset? at = null)
        {
            DateTimeOffset when = at ?? DateTimeOffset.UtcNow;
            DateTimeOffset? expiresAt = KeyValidity.GetExpiration(_certificate, _key, when);
            if (!_key.CanVerify)
            {
                return new OpenPgpKeyStatus(when, VerificationStatus.UnsupportedAlgorithm, "The key's algorithm (" + Algorithm + ") can't make signatures this library verifies.", expiresAt);
            }

            (VerificationStatus status, string message) = KeyValidity.CheckSigningKey(_certificate, _key, when, when);
            return new OpenPgpKeyStatus(when, status, message, expiresAt);
        }

        /// <summary>The fingerprint.</summary>
        public override string ToString() => Fingerprint;
    }

    /// <summary>A key's standing at one moment (see <see cref="OpenPgpKey.GetStatus"/>).</summary>
    public sealed class OpenPgpKeyStatus
    {
        internal OpenPgpKeyStatus(DateTimeOffset evaluatedAt, VerificationStatus status, string message, DateTimeOffset? expiresAt)
        {
            EvaluatedAt = evaluatedAt;
            Status = status;
            Message = message;
            ExpiresAt = expiresAt;
        }

        /// <summary>The moment the key was judged at.</summary>
        public DateTimeOffset EvaluatedAt { get; }

        /// <summary>
        /// <see cref="VerificationStatus.Valid"/> when the key may sign at <see cref="EvaluatedAt"/>;
        /// otherwise why not, e.g. <see cref="VerificationStatus.KeyExpired"/>,
        /// <see cref="VerificationStatus.KeyRevoked"/> or <see cref="VerificationStatus.KeyNotValidForSigning"/>.
        /// </summary>
        public VerificationStatus Status { get; }

        /// <summary>Whether the key may sign at <see cref="EvaluatedAt"/>: <see cref="Status"/> is <see cref="VerificationStatus.Valid"/>.</summary>
        public bool CanSign => Status == VerificationStatus.Valid;

        /// <summary>A human-readable explanation of <see cref="Status"/>.</summary>
        public string Message { get; }

        /// <summary>
        /// When the key expires, per its self-signature in effect at <see cref="EvaluatedAt"/> (or
        /// its newest one, if none is in effect any more). <c>null</c> means no expiration is set -
        /// or that none can be determined because the self-signatures are unusable, which
        /// <see cref="Status"/> then reports; check <see cref="CanSign"/> before reading this as
        /// "never expires".
        /// </summary>
        public DateTimeOffset? ExpiresAt { get; }

        /// <summary>The status and message, for logging.</summary>
        public override string ToString() => Status + ": " + Message;
    }

    /// <summary>Public key input that contains no usable certificate.</summary>
    public sealed class OpenPgpFormatException : FormatException
    {
        /// <summary>Creates the exception.</summary>
        public OpenPgpFormatException()
        {
        }

        /// <summary>Creates the exception with a message.</summary>
        public OpenPgpFormatException(string message)
            : base(message)
        {
        }

        /// <summary>Creates the exception with a message and inner exception.</summary>
        public OpenPgpFormatException(string message, Exception innerException)
            : base(message, innerException)
        {
        }
    }
}
