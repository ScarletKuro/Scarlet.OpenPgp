using Scarlet.OpenPgp.Packets;

namespace Scarlet.OpenPgp.Signing
{
    /// <summary>
    /// Builds the exact byte sequence a v4 signature hashes (RFC 4880 §5.2.4): the signed content,
    /// followed by the signature packet's own hashed-subpacket region, followed by a fixed trailer.
    /// Isolated on purpose - a bug here produces verification failures that look exactly like a
    /// crypto bug but aren't, so it gets its own byte-exact test independent of full verification.
    /// </summary>
    internal static class SignatureHashBuilder
    {
        public static byte[] BuildDataToHash(byte[] content, SignaturePacket signature)
        {
            byte[] hashedPortion = BuildHashedPortion(signature);
            byte[] trailer = BuildTrailer(hashedPortion.Length);

            var result = new byte[content.Length + hashedPortion.Length + trailer.Length];
            System.Array.Copy(content, 0, result, 0, content.Length);
            System.Array.Copy(hashedPortion, 0, result, content.Length, hashedPortion.Length);
            System.Array.Copy(trailer, 0, result, content.Length + hashedPortion.Length, trailer.Length);
            return result;
        }

        private static byte[] BuildHashedPortion(SignaturePacket signature)
        {
            byte[] hashedSubpacketData = signature.HashedSubpacketData;
            var portion = new byte[6 + hashedSubpacketData.Length];
            portion[0] = signature.Version;
            portion[1] = signature.SignatureTypeRaw;
            portion[2] = (byte)signature.PublicKeyAlgorithm;
            portion[3] = (byte)signature.HashAlgorithm;
            portion[4] = (byte)(hashedSubpacketData.Length >> 8);
            portion[5] = (byte)hashedSubpacketData.Length;
            System.Array.Copy(hashedSubpacketData, 0, portion, 6, hashedSubpacketData.Length);
            return portion;
        }

        private static byte[] BuildTrailer(int hashedPortionLength)
        {
            return new[]
            {
                (byte)0x04,
                (byte)0xFF,
                (byte)(hashedPortionLength >> 24),
                (byte)(hashedPortionLength >> 16),
                (byte)(hashedPortionLength >> 8),
                (byte)hashedPortionLength,
            };
        }
    }
}
