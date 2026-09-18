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
        public static bool VerifyDetached(ReadOnlySpan<byte> data, string signatureArmor, string publicKeyArmor)
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
            // A signature armor block (a detached .sig/.asc, or a clearsigned message's trailing
            // block) is exactly one Signature packet by construction - RFC 4880 has no notion of
            // "extra" packets belonging there. Anything other than exactly one Signature-tagged
            // packet is treated as malformed rather than silently picking the first match, since
            // silently ignoring extra/duplicate packets is exactly the kind of parsing ambiguity
            // SPEC.md's fail-closed rule is meant to catch. Contrast with ParsePublicKeyPacket
            // below, which is deliberately permissive because a real public key block legitimately
            // contains several other packet types by design (User ID, self-signatures, subkeys).
            List<Packet> packets = PacketReader.ReadAll(armorBody);
            if (packets.Count != 1 || packets[0].Header.Tag != PacketTag.Signature)
            {
                throw new FailClosedException("Expected exactly one Signature packet in the signature armor block.");
            }

            return SignaturePacket.Parse(packets[0].Body);
        }

        private static PublicKeyPacket ParsePublicKeyPacket(string publicKeyArmor)
        {
            // Permissive by design: a real public key block routinely contains a User ID packet,
            // one or more self-signatures, and subkeys with their own binding signatures alongside
            // the primary Public-Key packet we actually need (see the real-world Bun key fixture
            // under TestAssets/bun-release/). We take the first Public-Key packet and ignore the
            // rest, matching how every other OpenPGP implementation reads a "bag of packets" key
            // block for the one primary key packet it cares about.
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

            // The packet's own 2-byte quick-check (RFC 4880 §5.2.3) isn't itself signed material,
            // so it can't be used as a substitute for the real asymmetric check below - but a
            // mismatch here means the packet is inconsistent with the content it claims to cover,
            // which fails closed the same as any other malformed-input case.
            if (signature.LeftHashBytes16[0] != digest[0] || signature.LeftHashBytes16[1] != digest[1])
            {
                return false;
            }

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
