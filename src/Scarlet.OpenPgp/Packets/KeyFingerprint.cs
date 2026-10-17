using System.Security.Cryptography;

namespace Scarlet.OpenPgp.Packets
{
    /// <summary>
    /// A v4 public key fingerprint (RFC 4880 §12.2): SHA-1 over 0x99, the packet body's 2-byte
    /// big-endian length, and the packet body itself. The low-order 64 bits (last 8 bytes) double
    /// as the classic "key ID" used by Issuer subpackets.
    /// </summary>
    internal sealed class KeyFingerprint
    {
        private KeyFingerprint(byte[] bytes)
        {
            Bytes = bytes;
        }

        public byte[] Bytes { get; }

        /// <summary>The low-order 64 bits of the fingerprint, as used by the classic Issuer (type 16) subpacket.</summary>
        public byte[] KeyId
        {
            get
            {
                var keyId = new byte[8];
                System.Array.Copy(Bytes, Bytes.Length - 8, keyId, 0, 8);
                return keyId;
            }
        }

        public static KeyFingerprint ComputeV4(byte[] publicKeyPacketBody)
        {
            var hashInput = new byte[3 + publicKeyPacketBody.Length];
            hashInput[0] = 0x99;
            hashInput[1] = (byte)(publicKeyPacketBody.Length >> 8);
            hashInput[2] = (byte)publicKeyPacketBody.Length;
            System.Array.Copy(publicKeyPacketBody, 0, hashInput, 3, publicKeyPacketBody.Length);

            using (var sha1 = SHA1.Create())
            {
                return new KeyFingerprint(sha1.ComputeHash(hashInput));
            }
        }

        public bool Matches(byte[] other)
        {
            if (other.Length != Bytes.Length)
            {
                return false;
            }

            int diff = 0;
            for (int i = 0; i < Bytes.Length; i++)
            {
                diff |= Bytes[i] ^ other[i];
            }

            return diff == 0;
        }
    }
}
