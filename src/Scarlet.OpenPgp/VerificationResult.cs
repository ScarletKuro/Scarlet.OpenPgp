using System;

namespace Scarlet.OpenPgp
{
    /// <summary>Why a verification succeeded or failed.</summary>
    public enum VerificationStatus
    {
        /// <summary>A signature verified against one of the supplied keys.</summary>
        Valid = 0,

        /// <summary>The signature or clearsigned message is not well-formed OpenPGP (bad armor, packets, or clearsign framing).</summary>
        MalformedInput,

        /// <summary>The supplied public key input contains no usable certificate.</summary>
        InvalidPublicKey,

        /// <summary>None of the supplied keys made any of the signatures.</summary>
        NoMatchingKey,

        /// <summary>The signature uses an algorithm, hash, version, or feature this library does not support or considers too weak.</summary>
        UnsupportedAlgorithm,

        /// <summary>The cryptographic check failed: the data or the signature was altered, or a different key made it.</summary>
        BadSignature,

        /// <summary>The signature is not of the kind the call expects (e.g. a key signature, or a binary signature where clearsign needs a text one).</summary>
        WrongSignatureType,

        /// <summary>The signature is past its own expiration time.</summary>
        SignatureExpired,

        /// <summary>The signature's creation time is impossible for its key (e.g. before the key was created).</summary>
        InvalidSignatureTime,

        /// <summary>The signing key (or its primary key) has expired, or had expired when it made the signature.</summary>
        KeyExpired,

        /// <summary>The signing key (or its primary key) has been revoked.</summary>
        KeyRevoked,

        /// <summary>The key exists but is not valid for signing data: no sign flag, no valid binding or back-signature, or no valid self-signature.</summary>
        KeyNotValidForSigning,
    }

    /// <summary>The outcome of an OpenPGP signature verification.</summary>
    public sealed class VerificationResult
    {
        internal VerificationResult(
            VerificationStatus status,
            string message,
            string? signerFingerprint = null,
            string? primaryKeyFingerprint = null,
            DateTimeOffset? signatureCreationTime = null,
            string? signedText = null)
        {
            Status = status;
            Message = message;
            SignerFingerprint = signerFingerprint;
            PrimaryKeyFingerprint = primaryKeyFingerprint;
            SignatureCreationTime = signatureCreationTime;
            SignedText = signedText;
        }

        /// <summary>Whether a signature verified. Equivalent to <see cref="Status"/> being <see cref="VerificationStatus.Valid"/>.</summary>
        public bool IsValid => Status == VerificationStatus.Valid;

        /// <summary>The outcome; anything other than <see cref="VerificationStatus.Valid"/> says why verification failed.</summary>
        public VerificationStatus Status { get; }

        /// <summary>A human-readable explanation of <see cref="Status"/>.</summary>
        public string Message { get; }

        /// <summary>
        /// The fingerprint (uppercase hex) of the key that made the signature - a subkey when a
        /// signing subkey was used. Also set on failures that got as far as identifying the key
        /// (e.g. <see cref="VerificationStatus.KeyExpired"/>).
        /// </summary>
        public string? SignerFingerprint { get; }

        /// <summary>The fingerprint (uppercase hex) of the signer's primary key, which identifies the certificate.</summary>
        public string? PrimaryKeyFingerprint { get; }

        /// <summary>When the signature says it was made.</summary>
        public DateTimeOffset? SignatureCreationTime { get; }

        /// <summary>
        /// For a verified clearsigned message, exactly the signed text: dash-unescaped, trailing spaces
        /// and tabs removed, lines separated by CRLF, with no line break after the last line. This is
        /// the only part of a clearsigned message that is authenticated - consume this, never the
        /// original input. <c>null</c> otherwise.
        /// </summary>
        public string? SignedText { get; }

        /// <summary>The status and message, for logging.</summary>
        public override string ToString() => Status + ": " + Message;
    }
}
