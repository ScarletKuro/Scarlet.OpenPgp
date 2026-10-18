using System;
using System.Buffers;
using System.Diagnostics.CodeAnalysis;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Scarlet.OpenPgp.Armor;
using Scarlet.OpenPgp.Clearsign;
using Scarlet.OpenPgp.Internal;
using Scarlet.OpenPgp.Verification;

namespace Scarlet.OpenPgp
{
    /// <summary>
    /// Verifies OpenPGP signatures (RFC 9580 and RFC 4880; v4 and v6 keys and signatures; RSA, DSA,
    /// ECDSA, Ed25519 and Ed448). The caller supplies exactly the public keys they already trust;
    /// this type does no trust-chain evaluation.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Signatures and keys may be ASCII-armored or binary; key input may hold several certificates
    /// and signature input several signatures. The result is valid when any signature verifies
    /// against any supplied key. Signing subkeys are supported (binding and back-signatures are
    /// checked), and so are key flags, key and signature expiration, and revocations contained in
    /// the supplied certificates.
    /// </para>
    /// <para>
    /// Nothing here throws on bad input: every parsing ambiguity, unknown-but-critical subpacket, or
    /// malformed input yields a failed <see cref="VerificationResult"/> with a reason.
    /// </para>
    /// </remarks>
    public static class OpenPgpVerifier
    {
        private const string SignatureLabel = "SIGNATURE";
        private const int StreamBufferSize = 81920;

        /// <summary>
        /// Verifies a clearsigned message. On success, <see cref="VerificationResult.SignedText"/>
        /// holds exactly the signed text - the only part of the message that is authenticated.
        /// </summary>
        /// <param name="clearsignedMessage">The complete clearsigned message. Nothing but blank lines may precede its BEGIN line or follow its END line.</param>
        /// <param name="publicKeys">The trusted ASCII-armored public key(s).</param>
        /// <param name="verificationTime">The moment expiration, revocation and future-dated signatures are judged against; the current time when <c>null</c>.</param>
        public static VerificationResult VerifyClearsign(string clearsignedMessage, string publicKeys, DateTimeOffset? verificationTime = null)
        {
            return VerifyClearsign(clearsignedMessage, ParseKeys(publicKeys), verificationTime);
        }

        /// <inheritdoc cref="VerifyClearsign(string, string, DateTimeOffset?)"/>
        /// <param name="clearsignedMessage">The complete clearsigned message.</param>
        /// <param name="publicKeys">The trusted public key(s), ASCII-armored or binary.</param>
        /// <param name="verificationTime">The moment expiration, revocation and future-dated signatures are judged against; the current time when <c>null</c>.</param>
        public static VerificationResult VerifyClearsign(string clearsignedMessage, ReadOnlySpan<byte> publicKeys, DateTimeOffset? verificationTime = null)
        {
            return VerifyClearsign(clearsignedMessage, ParseKeys(publicKeys), verificationTime);
        }

        /// <inheritdoc cref="VerifyClearsign(string, string, DateTimeOffset?)"/>
        /// <param name="clearsignedMessage">The complete clearsigned message.</param>
        /// <param name="keyRing">The trusted keys, parsed once with <see cref="OpenPgpKeyRing.Parse(string)"/>.</param>
        /// <param name="verificationTime">The moment expiration, revocation and future-dated signatures are judged against; the current time when <c>null</c>.</param>
        public static VerificationResult VerifyClearsign(string clearsignedMessage, OpenPgpKeyRing keyRing, DateTimeOffset? verificationTime = null)
        {
            return VerifyClearsign(clearsignedMessage, Keys(keyRing), verificationTime);
        }

        /// <summary>Verifies detached signature(s) over in-memory data.</summary>
        /// <param name="data">The signed data.</param>
        /// <param name="signature">The ASCII-armored detached signature(s).</param>
        /// <param name="publicKeys">The trusted ASCII-armored public key(s).</param>
        /// <param name="verificationTime">The moment expiration, revocation and future-dated signatures are judged against; the current time when <c>null</c>.</param>
        public static VerificationResult VerifyDetached(ReadOnlySpan<byte> data, string signature, string publicKeys, DateTimeOffset? verificationTime = null)
        {
            return VerifyDetached(data, ParseSignatures(signature), ParseKeys(publicKeys), verificationTime);
        }

        /// <inheritdoc cref="VerifyDetached(ReadOnlySpan{byte}, string, string, DateTimeOffset?)"/>
        /// <param name="data">The signed data.</param>
        /// <param name="signature">The detached signature(s), ASCII-armored (.asc) or binary (.sig).</param>
        /// <param name="publicKeys">The trusted public key(s), ASCII-armored or binary.</param>
        /// <param name="verificationTime">The moment expiration, revocation and future-dated signatures are judged against; the current time when <c>null</c>.</param>
        public static VerificationResult VerifyDetached(ReadOnlySpan<byte> data, ReadOnlySpan<byte> signature, ReadOnlySpan<byte> publicKeys, DateTimeOffset? verificationTime = null)
        {
            return VerifyDetached(data, ParseSignatures(signature), ParseKeys(publicKeys), verificationTime);
        }

        /// <inheritdoc cref="VerifyDetached(ReadOnlySpan{byte}, string, string, DateTimeOffset?)"/>
        /// <param name="data">The signed data.</param>
        /// <param name="signature">The ASCII-armored detached signature(s).</param>
        /// <param name="keyRing">The trusted keys.</param>
        /// <param name="verificationTime">The moment expiration, revocation and future-dated signatures are judged against; the current time when <c>null</c>.</param>
        public static VerificationResult VerifyDetached(ReadOnlySpan<byte> data, string signature, OpenPgpKeyRing keyRing, DateTimeOffset? verificationTime = null)
        {
            return VerifyDetached(data, ParseSignatures(signature), Keys(keyRing), verificationTime);
        }

        /// <inheritdoc cref="VerifyDetached(ReadOnlySpan{byte}, string, string, DateTimeOffset?)"/>
        /// <param name="data">The signed data.</param>
        /// <param name="signature">The detached signature(s), ASCII-armored (.asc) or binary (.sig).</param>
        /// <param name="keyRing">The trusted keys.</param>
        /// <param name="verificationTime">The moment expiration, revocation and future-dated signatures are judged against; the current time when <c>null</c>.</param>
        public static VerificationResult VerifyDetached(ReadOnlySpan<byte> data, ReadOnlySpan<byte> signature, OpenPgpKeyRing keyRing, DateTimeOffset? verificationTime = null)
        {
            return VerifyDetached(data, ParseSignatures(signature), Keys(keyRing), verificationTime);
        }

        /// <summary>Verifies detached signature(s) over data read from <paramref name="data"/>, which is read to its end once and never buffered whole.</summary>
        /// <param name="data">The signed data. Not disposed.</param>
        /// <param name="signature">The ASCII-armored detached signature(s).</param>
        /// <param name="publicKeys">The trusted ASCII-armored public key(s).</param>
        /// <param name="verificationTime">The moment expiration, revocation and future-dated signatures are judged against; the current time when <c>null</c>.</param>
        public static VerificationResult VerifyDetached(Stream data, string signature, string publicKeys, DateTimeOffset? verificationTime = null)
        {
            return VerifyDetached(data, ParseSignatures(signature), ParseKeys(publicKeys), verificationTime);
        }

        /// <inheritdoc cref="VerifyDetached(Stream, string, string, DateTimeOffset?)"/>
        /// <param name="data">The signed data. Not disposed.</param>
        /// <param name="signature">The detached signature(s), ASCII-armored (.asc) or binary (.sig).</param>
        /// <param name="publicKeys">The trusted public key(s), ASCII-armored or binary.</param>
        /// <param name="verificationTime">The moment expiration, revocation and future-dated signatures are judged against; the current time when <c>null</c>.</param>
        public static VerificationResult VerifyDetached(Stream data, ReadOnlySpan<byte> signature, ReadOnlySpan<byte> publicKeys, DateTimeOffset? verificationTime = null)
        {
            return VerifyDetached(data, ParseSignatures(signature), ParseKeys(publicKeys), verificationTime);
        }

        /// <inheritdoc cref="VerifyDetached(Stream, string, string, DateTimeOffset?)"/>
        /// <param name="data">The signed data. Not disposed.</param>
        /// <param name="signature">The ASCII-armored detached signature(s).</param>
        /// <param name="keyRing">The trusted keys.</param>
        /// <param name="verificationTime">The moment expiration, revocation and future-dated signatures are judged against; the current time when <c>null</c>.</param>
        public static VerificationResult VerifyDetached(Stream data, string signature, OpenPgpKeyRing keyRing, DateTimeOffset? verificationTime = null)
        {
            return VerifyDetached(data, ParseSignatures(signature), Keys(keyRing), verificationTime);
        }

        /// <inheritdoc cref="VerifyDetached(Stream, string, string, DateTimeOffset?)"/>
        /// <param name="data">The signed data. Not disposed.</param>
        /// <param name="signature">The detached signature(s), ASCII-armored (.asc) or binary (.sig).</param>
        /// <param name="keyRing">The trusted keys.</param>
        /// <param name="verificationTime">The moment expiration, revocation and future-dated signatures are judged against; the current time when <c>null</c>.</param>
        public static VerificationResult VerifyDetached(Stream data, ReadOnlySpan<byte> signature, OpenPgpKeyRing keyRing, DateTimeOffset? verificationTime = null)
        {
            return VerifyDetached(data, ParseSignatures(signature), Keys(keyRing), verificationTime);
        }

        /// <summary>Asynchronously verifies detached signature(s) over data read from <paramref name="data"/>, which is read to its end once and never buffered whole.</summary>
        /// <param name="data">The signed data. Not disposed.</param>
        /// <param name="signature">The ASCII-armored detached signature(s).</param>
        /// <param name="publicKeys">The trusted ASCII-armored public key(s).</param>
        /// <param name="verificationTime">The moment expiration, revocation and future-dated signatures are judged against; the current time when <c>null</c>.</param>
        /// <param name="cancellationToken">Cancels reading <paramref name="data"/>.</param>
        public static Task<VerificationResult> VerifyDetachedAsync(Stream data, string signature, string publicKeys, DateTimeOffset? verificationTime = null, CancellationToken cancellationToken = default)
        {
            return VerifyDetachedAsync(data, ParseSignatures(signature), ParseKeys(publicKeys), verificationTime, cancellationToken);
        }

        /// <inheritdoc cref="VerifyDetachedAsync(Stream, string, string, DateTimeOffset?, CancellationToken)"/>
        /// <param name="data">The signed data. Not disposed.</param>
        /// <param name="signature">The detached signature(s), ASCII-armored (.asc) or binary (.sig).</param>
        /// <param name="publicKeys">The trusted public key(s), ASCII-armored or binary.</param>
        /// <param name="verificationTime">The moment expiration, revocation and future-dated signatures are judged against; the current time when <c>null</c>.</param>
        /// <param name="cancellationToken">Cancels reading <paramref name="data"/>.</param>
        public static Task<VerificationResult> VerifyDetachedAsync(Stream data, ReadOnlyMemory<byte> signature, ReadOnlyMemory<byte> publicKeys, DateTimeOffset? verificationTime = null, CancellationToken cancellationToken = default)
        {
            return VerifyDetachedAsync(data, ParseSignatures(signature.Span), ParseKeys(publicKeys.Span), verificationTime, cancellationToken);
        }

        /// <inheritdoc cref="VerifyDetachedAsync(Stream, string, string, DateTimeOffset?, CancellationToken)"/>
        /// <param name="data">The signed data. Not disposed.</param>
        /// <param name="signature">The ASCII-armored detached signature(s).</param>
        /// <param name="keyRing">The trusted keys.</param>
        /// <param name="verificationTime">The moment expiration, revocation and future-dated signatures are judged against; the current time when <c>null</c>.</param>
        /// <param name="cancellationToken">Cancels reading <paramref name="data"/>.</param>
        public static Task<VerificationResult> VerifyDetachedAsync(Stream data, string signature, OpenPgpKeyRing keyRing, DateTimeOffset? verificationTime = null, CancellationToken cancellationToken = default)
        {
            return VerifyDetachedAsync(data, ParseSignatures(signature), Keys(keyRing), verificationTime, cancellationToken);
        }

        /// <inheritdoc cref="VerifyDetachedAsync(Stream, string, string, DateTimeOffset?, CancellationToken)"/>
        /// <param name="data">The signed data. Not disposed.</param>
        /// <param name="signature">The detached signature(s), ASCII-armored (.asc) or binary (.sig).</param>
        /// <param name="keyRing">The trusted keys.</param>
        /// <param name="verificationTime">The moment expiration, revocation and future-dated signatures are judged against; the current time when <c>null</c>.</param>
        /// <param name="cancellationToken">Cancels reading <paramref name="data"/>.</param>
        public static Task<VerificationResult> VerifyDetachedAsync(Stream data, ReadOnlyMemory<byte> signature, OpenPgpKeyRing keyRing, DateTimeOffset? verificationTime = null, CancellationToken cancellationToken = default)
        {
            return VerifyDetachedAsync(data, ParseSignatures(signature.Span), Keys(keyRing), verificationTime, cancellationToken);
        }

        private static VerificationResult VerifyClearsign(string clearsignedMessage, ParsedInput<KeyRing> keys, DateTimeOffset? verificationTime)
        {
            DateTimeOffset now = verificationTime ?? DateTimeOffset.UtcNow;

            if (clearsignedMessage is null)
            {
                throw new ArgumentNullException(nameof(clearsignedMessage));
            }

            if (keys.Failed)
            {
                return keys.Failure;
            }

            string signedText;
            byte[] content;
            byte[] signaturePackets;
            try
            {
                ClearsignMessage clearsign = ClearsignParser.Parse(clearsignedMessage);
                signedText = ClearsignCanonicalizer.CanonicalizeText(clearsign.DashEscapedBodyLines);
                content = ClearsignCanonicalizer.Encode(signedText);
                signaturePackets = clearsign.SignatureArmor.Body;
            }
            catch (FailClosedException ex)
            {
                return new VerificationResult(VerificationStatus.MalformedInput, "The clearsigned message is malformed: " + ex.Message);
            }

            using DocumentVerification verification = DocumentVerification.Start(signaturePackets, keys.Value, isClearsign: true);
            verification.Update(content, 0, content.Length);
            return verification.Complete(now, signedText);
        }

        private static VerificationResult VerifyDetached(ReadOnlySpan<byte> data, ParsedInput<byte[]> signatures, ParsedInput<KeyRing> keys, DateTimeOffset? verificationTime)
        {
            DateTimeOffset now = verificationTime ?? DateTimeOffset.UtcNow;

            using DocumentVerification verification = StartDetached(signatures, keys);

            // Fed through one bounded buffer, like the stream overload, rather than copying the
            // whole document (netstandard2.0's hash APIs take arrays, not spans). Nothing is copied
            // at all when the outcome is already decided.
            if (verification.NeedsContent)
            {
                byte[] buffer = ArrayPool<byte>.Shared.Rent(Math.Min(StreamBufferSize, data.Length));
                try
                {
                    int offset = 0;
                    while (offset < data.Length && verification.NeedsContent)
                    {
                        int count = Math.Min(buffer.Length, data.Length - offset);
                        data.Slice(offset, count).CopyTo(buffer);
                        verification.Update(buffer, 0, count);
                        offset += count;
                    }
                }
                finally
                {
                    ArrayPool<byte>.Shared.Return(buffer);
                }
            }

            return verification.Complete(now, signedText: null);
        }

        private static VerificationResult VerifyDetached(Stream data, ParsedInput<byte[]> signatures, ParsedInput<KeyRing> keys, DateTimeOffset? verificationTime)
        {
            DateTimeOffset now = verificationTime ?? DateTimeOffset.UtcNow;

            if (data is null)
            {
                throw new ArgumentNullException(nameof(data));
            }

            using DocumentVerification verification = StartDetached(signatures, keys);
            byte[] buffer = ArrayPool<byte>.Shared.Rent(StreamBufferSize);
            try
            {
                int read;
                while (verification.NeedsContent && (read = data.Read(buffer, 0, buffer.Length)) > 0)
                {
                    verification.Update(buffer, 0, read);
                }
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(buffer);
            }

            return verification.Complete(now, signedText: null);
        }

        private static async Task<VerificationResult> VerifyDetachedAsync(Stream data, ParsedInput<byte[]> signatures, ParsedInput<KeyRing> keys, DateTimeOffset? verificationTime, CancellationToken cancellationToken)
        {
            DateTimeOffset now = verificationTime ?? DateTimeOffset.UtcNow;

            if (data is null)
            {
                throw new ArgumentNullException(nameof(data));
            }

            using DocumentVerification verification = StartDetached(signatures, keys);
            byte[] buffer = ArrayPool<byte>.Shared.Rent(StreamBufferSize);
            try
            {
                int read;
                while (verification.NeedsContent && (read = await data.ReadAsync(buffer, 0, buffer.Length, cancellationToken).ConfigureAwait(false)) > 0)
                {
                    verification.Update(buffer, 0, read);
                }
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(buffer);
            }

            return verification.Complete(now, signedText: null);
        }

        private static ParsedInput<KeyRing> ParseKeys(string publicKeys)
        {
            if (publicKeys is null)
            {
                throw new ArgumentNullException(nameof(publicKeys));
            }

            return OpenPgpKeyRing.TryParse(publicKeys, out OpenPgpKeyRing? keyRing, out string? error) ? Keys(keyRing) : KeysFailure(error);
        }

        private static ParsedInput<KeyRing> ParseKeys(ReadOnlySpan<byte> publicKeys)
        {
            return OpenPgpKeyRing.TryParse(publicKeys, out OpenPgpKeyRing? keyRing, out string? error) ? Keys(keyRing) : KeysFailure(error);
        }

        /// <summary>Key input that didn't parse; the message comes from <see cref="OpenPgpKeyRing.TryParse(ReadOnlySpan{byte}, out OpenPgpKeyRing?, out string?)"/>, so both entry points report it the same way.</summary>
        private static ParsedInput<KeyRing> KeysFailure(string error) =>
            new(new VerificationResult(VerificationStatus.InvalidPublicKey, error));

        private static ParsedInput<byte[]> ParseSignatures(string signature)
        {
            if (signature is null)
            {
                throw new ArgumentNullException(nameof(signature));
            }

            return ParseSignatures(() => PacketInput.Decode(signature, SignatureLabel));
        }

        private static ParsedInput<byte[]> ParseSignatures(ReadOnlySpan<byte> signature)
        {
            byte[] copy = signature.ToArray();
            return ParseSignatures(() => PacketInput.Decode(copy, SignatureLabel));
        }

        private static ParsedInput<KeyRing> Keys(OpenPgpKeyRing keyRing)
        {
            if (keyRing is null)
            {
                throw new ArgumentNullException(nameof(keyRing));
            }

            return new ParsedInput<KeyRing>(keyRing.Inner);
        }

        private static ParsedInput<byte[]> ParseSignatures(Func<byte[]> decode)
        {
            try
            {
                return new ParsedInput<byte[]>(decode());
            }
            catch (FailClosedException ex)
            {
                return new ParsedInput<byte[]>(new VerificationResult(VerificationStatus.MalformedInput, "The signature is malformed: " + ex.Message));
            }
        }

        private static DocumentVerification StartDetached(ParsedInput<byte[]> signatures, ParsedInput<KeyRing> keys)
        {
            if (signatures.Failed)
            {
                return DocumentVerification.Failed(signatures.Failure.Status, signatures.Failure.Message);
            }

            if (keys.Failed)
            {
                return DocumentVerification.Failed(keys.Failure.Status, keys.Failure.Message);
            }

            return DocumentVerification.Start(signatures.Value, keys.Value, isClearsign: false);
        }

        /// <summary>Parsed signature or key input, or the result to report because it couldn't be parsed.</summary>
        private sealed class ParsedInput<T>
            where T : class
        {
            public ParsedInput(T value)
            {
                Value = value;
            }

            public ParsedInput(VerificationResult failure)
            {
                Failure = failure;
                Failed = true;
            }

            /// <summary>Whether parsing failed; exactly one of <see cref="Value"/> and <see cref="Failure"/> is set, and this says which.</summary>
            [MemberNotNullWhen(true, nameof(Failure))]
            [MemberNotNullWhen(false, nameof(Value))]
            public bool Failed { get; }

            public T? Value { get; }

            public VerificationResult? Failure { get; }
        }
    }
}
