using System;
using System.Collections.Generic;
using Scarlet.OpenPgp.Armor;
using Scarlet.OpenPgp.Clearsign;
using Scarlet.OpenPgp.Crypto.Ed25519;
using Scarlet.OpenPgp.Crypto.Rsa;
using Scarlet.OpenPgp.Hashing;
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
    /// Every parsing ambiguity, unknown-but-critical subpacket, or malformed input fails closed:
    /// both public methods catch <see cref="FailClosedException"/> at this boundary and turn it
    /// into <c>false</c> rather than letting it escape as an unhandled exception.
    /// </remarks>
    public static class OpenPgpVerifier
    {
        /// <summary>Verifies a clearsigned message block against an ASCII-armored public key.</summary>
        public static bool VerifyClearsign(string clearsignedMessage, string publicKeyArmor)
        {
            try
            {
                ClearsignMessage clearsign = ClearsignParser.Parse(clearsignedMessage);
                SignaturePacket signature = ParseSignaturePacket(clearsign.SignatureArmor.Body);

                if (!signature.IsCanonicalTextDocument)
                {
                    return false;
                }

                byte[] content = ClearsignCanonicalizer.Canonicalize(clearsign.DashEscapedBodyLines);
                PublicKeyPacket publicKey = ParsePublicKeyPacket(publicKeyArmor);
                return VerifySignature(publicKey, signature, content);
            }
            catch (FailClosedException)
            {
                return false;
            }
        }

        /// <summary>Verifies a detached signature (ASCII-armored) over arbitrary bytes.</summary>
        /// <remarks>
        /// Takes <c>byte[]</c> rather than <see cref="ReadOnlySpan{T}"/> despite SPEC.md's initial
        /// sketch suggesting the latter: <c>ReadOnlySpan&lt;byte&gt;</c> is not part of netstandard2.0's
        /// own reference surface and requires the System.Memory package to use there, which would
        /// violate the zero-external-dependency non-negotiable for this library's primary target.
        /// </remarks>
        public static bool VerifyDetached(byte[] data, string signatureArmor, string publicKeyArmor)
        {
            byte[] content = data;
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

                PublicKeyPacket publicKey = ParsePublicKeyPacket(publicKeyArmor);
                return VerifySignature(publicKey, signature, content);
            }
            catch (FailClosedException)
            {
                return false;
            }
        }

        private static SignaturePacket ParseSignaturePacket(byte[] armorBody)
        {
            List<Packet> packets = PacketReader.ReadAll(armorBody);
            foreach (Packet packet in packets)
            {
                if (packet.Header.Tag == PacketTag.Signature)
                {
                    return SignaturePacket.Parse(packet.Body);
                }
            }

            throw new FailClosedException("No Signature packet found in the signature armor block.");
        }

        private static PublicKeyPacket ParsePublicKeyPacket(string publicKeyArmor)
        {
            AsciiArmorBlock block = AsciiArmorReader.Read(publicKeyArmor);
            List<Packet> packets = PacketReader.ReadAll(block.Body);
            foreach (Packet packet in packets)
            {
                if (packet.Header.Tag == PacketTag.PublicKey)
                {
                    return PublicKeyPacket.Parse(packet.Body);
                }
            }

            throw new FailClosedException("No Public-Key packet found in the public key armor block.");
        }

        private static bool VerifySignature(PublicKeyPacket publicKey, SignaturePacket signature, byte[] content)
        {
            if (publicKey.Algorithm != signature.PublicKeyAlgorithm)
            {
                return false;
            }

            byte[] dataToHash = SignatureHashBuilder.BuildDataToHash(content, signature);
            byte[] digest = OpenPgpHash.ComputeHash(signature.HashAlgorithm, dataToHash);

            switch (publicKey.Algorithm)
            {
                case PublicKeyAlgorithm.RsaEncryptOrSign:
                case PublicKeyAlgorithm.RsaSignOnly:
                    if (publicKey.Rsa is null || signature.RsaSignatureValue is null)
                    {
                        return false;
                    }

                    return RsaPkcs1Verifier.Verify(publicKey.Rsa, signature.HashAlgorithm, digest, signature.RsaSignatureValue.Value);

                case PublicKeyAlgorithm.EdDsaLegacy:
                    if (publicKey.EdDsa is null || signature.EdDsaSignatureValue is null)
                    {
                        return false;
                    }

                    return Ed25519Verifier.Verify(publicKey.EdDsa, digest, signature.EdDsaSignatureValue);

                default:
                    return false;
            }
        }
    }
}
