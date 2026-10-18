using System.Security.Cryptography;
using System.Text;
using Scarlet.OpenPgp.Hashing;
using Scarlet.OpenPgp.Packets;
using Scarlet.OpenPgp.Verification;
using Scarlet.OpenPgp.Tests.Packets;

namespace Scarlet.OpenPgp.Tests.Verification
{
    public class SignatureHashBuilderTests
    {
        // draft-koch-eddsa-for-openpgp-04 Appendix A documents the exact bytes hashed when
        // verifying its worked example (signing the literal text "OpenPGP"), plus the resulting
        // SHA-256 digest - an authoritative, independent-of-this-library ground truth for exactly
        // the byte sequence SPEC.md calls out for its own isolated test.
        private static readonly byte[] ExpectedHashInput =
        [
            // "OpenPGP"
            0x4f, 0x70, 0x65, 0x6e, 0x50, 0x47, 0x50,
            // hashed portion: version, type, pubalg, hashalg, 2-byte hashed-subpacket count, hashed-subpacket data
            0x04, 0x00, 0x16, 0x08, 0x00, 0x06, 0x05, 0x02, 0x55, 0xf9, 0x5f, 0x95,
            // trailer: 0x04, 0xFF, 4-byte big-endian length of the hashed portion (12)
            0x04, 0xff, 0x00, 0x00, 0x00, 0x0c,
        ];

        private static readonly byte[] ExpectedDigest =
        [
            0xf6, 0x22, 0x0a, 0x3f, 0x75, 0x78, 0x14, 0xf4, 0xc2, 0x17, 0x6f, 0xfb, 0xb6, 0x8b, 0x00, 0x24,
            0x9c, 0xd4, 0xcc, 0xdc, 0x05, 0x9c, 0x4b, 0x34, 0xad, 0x87, 0x1f, 0x30, 0xb1, 0x74, 0x02, 0x80,
        ];

        private static SignaturePacket ParseSignatureFixture()
        {
            List<Packet> packets = PacketReader.ReadAll(SignaturePacketTests.Ed25519SignaturePacketBytes);
            return SignaturePacket.Parse(packets[0].Body);
        }

        [Fact]
        public void SignatureDigest_WithRealEd25519SignatureFromEddsaDraft_ShouldHashExactlyTheDocumentedByteSequence()
        {
            // Arrange: the draft documents both the bytes hashed and their digest. The digest path
            // verification really uses is checked against the hash of the documented bytes, so any
            // difference in what it feeds the hash - salt, content, hashed portion, trailer - fails.
            SignaturePacket signature = ParseSignatureFixture();
            byte[] content = "OpenPGP"u8.ToArray();

            // Act
            byte[] digest;
            using (SignatureDigest builder = SignatureDigest.Begin(signature, canonicalizeText: false))
            {
                builder.Update(content, 0, content.Length);
                digest = builder.Finish();
            }

            // Assert
            Assert.Equal(SHA256.HashData(ExpectedHashInput), digest);
            Assert.Equal(ExpectedDigest, digest);
        }

        [Fact]
        public void ComputeDigest_DigestPrefix_ShouldMatchTheSignaturePacketsLeftHashBytes()
        {
            // Arrange: the signature packet's own 2-byte quick-check field must equal the first
            // two bytes of the real digest - an internal consistency check independent of the
            // draft's own documented values.
            SignaturePacket signature = ParseSignatureFixture();

            // Act
            byte[] digest = SignatureHashBuilder.ComputeDigest("OpenPGP"u8.ToArray(), signature);

            // Assert
            Assert.Equal(signature.LeftHashBytes16, new[] { digest[0], digest[1] });
        }

        public static TheoryData<string, int> TextModeInputs => new()
        {
            // name, chunk size used to feed the digest (0 = everything in one Update)
            { "mixed", 0 },
            { "mixed", 1 },
            { "mixed", 7 },
            { "all-lf", 0 },
            { "all-lf", 4096 },
            { "cr-lf-across-slice", 0 },
            { "cr-lf-across-slice", 32 * 1024 },
            { "lone-cr-then-lf-next-slice", 0 },
        };

        [Theory]
        [MemberData(nameof(TextModeInputs))]
        public void SignatureDigest_InTextMode_ShouldHashTheSameBytesAsAReferenceCanonicalization(string name, int chunkSize)
        {
            // Arrange: text mode converts each LF not preceded by CR into CRLF. The digest batches
            // that through a 32 KiB slice, so the inputs straddle slices, expand 2x (every byte a
            // LF) and split CR from its LF both within one Update and across Update calls.
            SignaturePacket signature = ParseSignatureFixture();
            byte[] content = BuildTextInput(name);
            byte[] expected = SignatureHashBuilder.ComputeDigest(ReferenceCanonicalize(content), signature);

            // Act
            byte[] actual;
            using (SignatureDigest digest = SignatureDigest.Begin(signature, canonicalizeText: true))
            {
                int step = chunkSize == 0 ? content.Length : chunkSize;
                for (int offset = 0; offset < content.Length; offset += step)
                {
                    digest.Update(content, offset, Math.Min(step, content.Length - offset));
                }

                actual = digest.Finish();
            }

            // Assert
            Assert.Equal(expected, actual);
        }

        private static byte[] BuildTextInput(string name)
        {
            const int slice = 32 * 1024;
            switch (name)
            {
                case "mixed":
                    return Encoding.ASCII.GetBytes("a\nb\r\nc\rd\n\n\r\r\n\r\ne\n");
                case "all-lf":
                    return Enumerable.Repeat((byte)'\n', (2 * slice) + 3).ToArray();
                case "cr-lf-across-slice":
                    {
                        byte[] text = Enumerable.Repeat((byte)'x', (2 * slice) + 10).ToArray();
                        text[slice - 1] = (byte)'\r';
                        text[slice] = (byte)'\n'; // already CRLF: must not gain a second CR
                        text[(2 * slice) - 1] = (byte)'\n';
                        return text;
                    }

                case "lone-cr-then-lf-next-slice":
                    {
                        byte[] text = Enumerable.Repeat((byte)'x', slice + 10).ToArray();
                        text[slice - 2] = (byte)'\r';
                        text[slice] = (byte)'\n'; // CR not directly before it: becomes CRLF
                        return text;
                    }

                default:
                    throw new ArgumentOutOfRangeException(nameof(name), name, null);
            }
        }

        private static byte[] ReferenceCanonicalize(byte[] text)
        {
            var result = new List<byte>(text.Length * 2);
            for (int i = 0; i < text.Length; i++)
            {
                if (text[i] == (byte)'\n' && (i == 0 || text[i - 1] != (byte)'\r'))
                {
                    result.Add((byte)'\r');
                }

                result.Add(text[i]);
            }

            return result.ToArray();
        }
    }
}
