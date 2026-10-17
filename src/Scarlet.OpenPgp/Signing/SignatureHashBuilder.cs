using System;
using System.Buffers;
using Scarlet.OpenPgp.Hashing;
using Scarlet.OpenPgp.Packets;

namespace Scarlet.OpenPgp.Signing
{
    /// <summary>
    /// Builds the exact byte sequence a v4/v6 signature hashes (RFC 9580 §5.2.4): the v6 salt, the
    /// signed content, the signature packet's own hashed portion, and a fixed trailer. Isolated on
    /// purpose - a bug here produces verification failures that look exactly like a crypto bug but
    /// aren't, so it gets its own byte-exact test independent of full verification.
    /// </summary>
    internal static class SignatureHashBuilder
    {
        /// <summary>The whole hash input for in-memory content. Used by tests and for small key-signature inputs.</summary>
        public static byte[] BuildDataToHash(byte[] content, SignaturePacket signature)
        {
            byte[] trailer = BuildTrailer(signature);
            var result = new byte[signature.Salt.Length + content.Length + signature.HashedPortion.Length + trailer.Length];
            int offset = 0;
            Append(result, ref offset, signature.Salt);
            Append(result, ref offset, content);
            Append(result, ref offset, signature.HashedPortion);
            Append(result, ref offset, trailer);
            return result;
        }

        /// <summary>The digest of <paramref name="content"/> (hashed as-is, no text canonicalization) under <paramref name="signature"/>.</summary>
        public static byte[] ComputeDigest(byte[] content, SignaturePacket signature, bool isKeySignature = false)
        {
            using SignatureDigest digest = SignatureDigest.Begin(signature, canonicalizeText: false, isKeySignature);
            digest.Update(content, 0, content.Length);
            return digest.Finish();
        }

        /// <summary>The trailer: the signature version, 0xFF, and the hashed portion's length as a 4-octet big-endian number.</summary>
        public static byte[] BuildTrailer(SignaturePacket signature)
        {
            int length = signature.HashedPortion.Length;
            return
            [
                signature.Version,
                (byte)0xFF,
                (byte)(length >> 24),
                (byte)(length >> 16),
                (byte)(length >> 8),
                (byte)length,
            ];
        }

        private static void Append(byte[] target, ref int offset, byte[] source)
        {
            Array.Copy(source, 0, target, offset, source.Length);
            offset += source.Length;
        }
    }

    /// <summary>
    /// An in-progress signature digest that content can be streamed into, so a large document is
    /// read once and never buffered. For text-mode signatures (type 0x01) the content's line
    /// endings are converted to CRLF on the fly (RFC 9580 §5.2.4): a LF not already preceded by CR
    /// becomes CRLF, even across chunk boundaries.
    /// </summary>
    internal sealed class SignatureDigest : IDisposable
    {
        /// <summary>How much input text is canonicalized per hash update (the scratch buffer is twice this).</summary>
        private const int TextSliceSize = 32 * 1024;

        private readonly SignaturePacket _signature;
        private readonly HashContext _hash;
        private readonly bool _canonicalizeText;
        private bool _previousWasCarriageReturn;
        private byte[]? _scratch;

        private SignatureDigest(SignaturePacket signature, HashContext hash, bool canonicalizeText)
        {
            _signature = signature;
            _hash = hash;
            _canonicalizeText = canonicalizeText;
        }

        public SignaturePacket Signature => _signature;

        /// <param name="signature">The signature whose digest to compute.</param>
        /// <param name="canonicalizeText">Convert line endings to CRLF while hashing (text-mode signatures).</param>
        /// <param name="isKeySignature">The signature is a key self-signature, for which SHA-1 is acceptable (see <see cref="HashContext.Create"/>).</param>
        public static SignatureDigest Begin(SignaturePacket signature, bool canonicalizeText, bool isKeySignature = false)
        {
            HashContext hash = HashContext.Create(signature.HashAlgorithm, allowSha1: isKeySignature);
            hash.Update(signature.Salt); // empty for v4; for v6 it goes in before anything else
            return new SignatureDigest(signature, hash, canonicalizeText);
        }

        public void Update(byte[] buffer, int offset, int count)
        {
            if (!_canonicalizeText)
            {
                _hash.Update(buffer, offset, count);
                return;
            }

            // Canonicalize into a scratch buffer and hash it with one update per slice. Hashing each
            // run between line breaks separately cost two hash calls per bare LF - 26x slower on
            // LF-dense input (8 MiB of LFs: 572 ms). Within a slice, each line is found with a
            // (vectorized) search for LF and copied whole, rather than byte by byte. A slice
            // expands at most 2x (every byte a LF).
            _scratch ??= ArrayPool<byte>.Shared.Rent(2 * TextSliceSize);
            var input = new ReadOnlySpan<byte>(buffer, offset, count);
            while (!input.IsEmpty)
            {
                ReadOnlySpan<byte> slice = input.Slice(0, Math.Min(input.Length, TextSliceSize));
                input = input.Slice(slice.Length);
                var output = new Span<byte>(_scratch);
                int written = 0;
                while (true)
                {
                    int lineFeed = slice.IndexOf((byte)'\n');
                    if (lineFeed < 0)
                    {
                        slice.CopyTo(output.Slice(written));
                        written += slice.Length;
                        if (!slice.IsEmpty)
                        {
                            _previousWasCarriageReturn = slice[slice.Length - 1] == (byte)'\r';
                        }

                        break;
                    }

                    bool alreadyCrLf = lineFeed > 0 ? slice[lineFeed - 1] == (byte)'\r' : _previousWasCarriageReturn;
                    slice.Slice(0, lineFeed).CopyTo(output.Slice(written));
                    written += lineFeed;
                    if (!alreadyCrLf)
                    {
                        output[written++] = (byte)'\r';
                    }

                    output[written++] = (byte)'\n';
                    _previousWasCarriageReturn = false;
                    slice = slice.Slice(lineFeed + 1);
                }

                _hash.Update(_scratch, 0, written);
            }
        }

        public byte[] Finish()
        {
            _hash.Update(_signature.HashedPortion);
            _hash.Update(SignatureHashBuilder.BuildTrailer(_signature));
            return _hash.Finish();
        }

        public void Dispose()
        {
            _hash.Dispose();
            if (_scratch is not null)
            {
                ArrayPool<byte>.Shared.Return(_scratch);
                _scratch = null;
            }
        }
    }
}
