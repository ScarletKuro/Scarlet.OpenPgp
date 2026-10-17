using System;
using System.Collections.Generic;
using Scarlet.OpenPgp.Armor;
using Scarlet.OpenPgp.Clearsign;
using Scarlet.OpenPgp.Internal;
using Scarlet.OpenPgp.Packets;
using Scarlet.OpenPgp.Signing;

namespace Scarlet.OpenPgp
{
    /// <summary>
    /// Verifies OpenPGP signatures (RFC 4880 v4, Ed25519 and RSA-PKCS#1 v1.5 only). The caller
    /// supplies exactly the public key they already trust; this type does no key management,
    /// trust-chain evaluation, or revocation checking - see SPEC.md's non-goals.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Every parsing ambiguity, unknown-but-critical subpacket, or malformed input fails closed:
    /// the public methods catch <see cref="FailClosedException"/> at this boundary and turn it
    /// into <c>false</c> rather than letting it escape as an unhandled exception.
    /// </para>
    /// <para>
    /// Time is checked as well as the signature itself: verification fails for a signature past its
    /// own expiration time, a signature older than the key, and a key past the expiration time set
    /// by its most recent valid self-signature.
    /// </para>
    /// </remarks>
    public static class OpenPgpVerifier
    {
        /// <summary>
        /// Verifies a clearsigned message block against an ASCII-armored public key and, on success,
        /// returns the text the signature actually covers.
        /// </summary>
        /// <remarks>
        /// Consume <paramref name="signedText"/>, never <paramref name="clearsignedMessage"/>: lines
        /// in the input differ from the signed text (dash-escaping, trailing whitespace), and the
        /// signature block's own armor headers (e.g. "Comment:") are never signed.
        /// </remarks>
        /// <param name="clearsignedMessage">The complete clearsigned message. Nothing but blank lines may precede its BEGIN line or follow its END line.</param>
        /// <param name="publicKeyArmor">The trusted ASCII-armored public key block.</param>
        /// <param name="signedText">
        /// On success, exactly the signed text: dash-unescaped, trailing spaces and tabs removed,
        /// lines separated by CRLF, with no line break after the last line. Empty on failure.
        /// This is the only part of the message that is authenticated - consume this, never the
        /// original input.
        /// </param>
        public static bool VerifyClearsign(string clearsignedMessage, string publicKeyArmor, out string signedText)
        {
            return VerifyClearsign(clearsignedMessage, publicKeyArmor, DateTimeOffset.UtcNow, out signedText);
        }

        /// <summary>Verifies a detached signature (ASCII-armored) over arbitrary bytes.</summary>
        public static bool VerifyDetached(ReadOnlySpan<byte> data, string signatureArmor, string publicKeyArmor)
        {
            return VerifyDetached(data, signatureArmor, publicKeyArmor, DateTimeOffset.UtcNow);
        }

        /// <summary>The clearsign check against an explicit clock, so tests can pin "now".</summary>
        internal static bool VerifyClearsign(string clearsignedMessage, string publicKeyArmor, DateTimeOffset now, out string signedText)
        {
            signedText = string.Empty;
            try
            {
                ClearsignMessage clearsign = ClearsignParser.Parse(clearsignedMessage);
                SignaturePacket signature = ParseSignaturePacket(clearsign.SignatureArmor.Body);

                if (!signature.IsCanonicalTextDocument)
                {
                    return false;
                }

                // A "Hash" header that doesn't name the signature's actual algorithm means the
                // message isn't what it claims to be - GnuPG rejects this too.
                if (clearsign.HashHeaderAlgorithms.Count > 0 && !Contains(clearsign.HashHeaderAlgorithms, signature.HashAlgorithm))
                {
                    return false;
                }

                string canonicalText = ClearsignCanonicalizer.CanonicalizeText(clearsign.DashEscapedBodyLines);
                byte[] content = ClearsignCanonicalizer.Encode(canonicalText);
                PublicKeyBlock publicKey = PublicKeyBlock.Parse(publicKeyArmor, now);
                if (!VerifySignature(publicKey, signature, content, now))
                {
                    return false;
                }

                signedText = canonicalText;
                return true;
            }
            catch (FailClosedException)
            {
                return false;
            }
        }

        /// <summary>The detached-signature check against an explicit clock, so tests can pin "now".</summary>
        internal static bool VerifyDetached(ReadOnlySpan<byte> data, string signatureArmor, string publicKeyArmor, DateTimeOffset now)
        {
            byte[] content = data.ToArray();
            try
            {
                AsciiArmorBlock signatureBlock = AsciiArmorReader.Read(signatureArmor);
                if (!string.Equals(signatureBlock.Label, "SIGNATURE", StringComparison.Ordinal))
                {
                    return false;
                }

                SignaturePacket signature = ParseSignaturePacket(signatureBlock.Body);
                if (!signature.IsBinaryDocument)
                {
                    return false;
                }

                PublicKeyBlock publicKey = PublicKeyBlock.Parse(publicKeyArmor, now);
                return VerifySignature(publicKey, signature, content, now);
            }
            catch (FailClosedException)
            {
                return false;
            }
        }

        private static SignaturePacket ParseSignaturePacket(byte[] armorBody)
        {
            // A signature armor block (a detached .sig/.asc, or a clearsigned message's trailing
            // block) is exactly one Signature packet by construction - RFC 4880 has no notion of
            // "extra" packets belonging there. Anything other than exactly one Signature-tagged
            // packet is treated as malformed rather than silently picking the first match, since
            // silently ignoring extra/duplicate packets is exactly the kind of parsing ambiguity
            // SPEC.md's fail-closed rule is meant to catch. Contrast with PublicKeyBlock.Parse,
            // which is deliberately permissive because a real public key block legitimately
            // contains several other packet types by design (User ID, self-signatures, subkeys).
            List<Packet> packets = PacketReader.ReadAll(armorBody);
            if (packets.Count != 1 || packets[0].Header.Tag != PacketTag.Signature)
            {
                throw new FailClosedException("Expected exactly one Signature packet in the signature armor block.");
            }

            return SignaturePacket.Parse(packets[0].Body);
        }

        private static bool VerifySignature(PublicKeyBlock publicKey, SignaturePacket signature, byte[] content, DateTimeOffset now)
        {
            DateTimeOffset createdAt = SignatureVerifier.GetCreationTime(signature);

            // A signature can't predate the key that made it.
            if (createdAt < publicKey.PrimaryKey.CreatedAt)
            {
                return false;
            }

            if (!SignatureVerifier.IsUnexpired(signature, now))
            {
                return false;
            }

            // The key must be valid both now and when it made the signature.
            if (publicKey.ExpiresAt.HasValue && (now >= publicKey.ExpiresAt.Value || createdAt >= publicKey.ExpiresAt.Value))
            {
                return false;
            }

            return SignatureVerifier.VerifyCryptographic(publicKey.PrimaryKey, signature, content);
        }

        private static bool Contains<T>(IReadOnlyList<T> list, T value)
        {
            foreach (T item in list)
            {
                if (EqualityComparer<T>.Default.Equals(item, value))
                {
                    return true;
                }
            }

            return false;
        }
    }
}
