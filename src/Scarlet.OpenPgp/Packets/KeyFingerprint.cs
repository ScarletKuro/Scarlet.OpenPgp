using System;
using System.Security.Cryptography;
using System.Text;
using Scarlet.OpenPgp.Internal;

namespace Scarlet.OpenPgp.Packets
{
    /// <summary>
    /// A key fingerprint (RFC 9580 §5.5.4). Version 4: SHA-1 over 0x99, the packet body's 2-octet
    /// length, and the body; the key ID is the low-order 64 bits. Version 6: SHA2-256 over 0x9B, a
    /// 4-octet length, and the body; the key ID is the high-order 64 bits.
    /// </summary>
    internal sealed class KeyFingerprint
    {
        // Racing threads compute the same string; publishing a reference is atomic.
        private string? _hex;
        private string? _keyIdHex;

        private KeyFingerprint(byte version, byte[] bytes, byte[] keyId)
        {
            Version = version;
            Bytes = bytes;
            KeyId = keyId;
        }

        /// <summary>The key version this fingerprint belongs to (4 or 6); also the version octet of an Issuer Fingerprint subpacket naming it.</summary>
        public byte Version { get; }

        public byte[] Bytes { get; }

        /// <summary>The 8-octet key ID, as used by the Issuer Key ID (type 16) subpacket.</summary>
        public byte[] KeyId { get; }

        public static KeyFingerprint Compute(byte version, byte[] publicKeyPacketBody)
        {
            switch (version)
            {
                case 4:
                    return ComputeV4(publicKeyPacketBody);
                case 6:
                    return ComputeV6(publicKeyPacketBody);
                default:
                    throw new FailClosedException("Unsupported key version " + version + ".");
            }
        }

        private static KeyFingerprint ComputeV4(byte[] publicKeyPacketBody)
        {
            byte[] hashInput = KeyHashPrefix.Build(4, publicKeyPacketBody);

            // A v4 fingerprint *is* SHA-1 by definition (RFC 9580 §5.5.4.2); it identifies a key,
            // it doesn't authenticate anything.
#pragma warning disable CA5350 // Do Not Use Weak Cryptographic Algorithms
            using var sha1 = SHA1.Create();
#pragma warning restore CA5350
            byte[] fingerprint = sha1.ComputeHash(hashInput);
            var keyId = new byte[8];
            System.Array.Copy(fingerprint, fingerprint.Length - 8, keyId, 0, 8);
            return new KeyFingerprint(4, fingerprint, keyId);
        }

        private static KeyFingerprint ComputeV6(byte[] publicKeyPacketBody)
        {
            byte[] hashInput = KeyHashPrefix.Build(6, publicKeyPacketBody);
            using var sha256 = SHA256.Create();
            byte[] fingerprint = sha256.ComputeHash(hashInput);
            var keyId = new byte[8];
            System.Array.Copy(fingerprint, 0, keyId, 0, 8);
            return new KeyFingerprint(6, fingerprint, keyId);
        }

        public bool Matches(ReadOnlySpan<byte> other) => FixedTimeEquals(Bytes, other);

        public bool MatchesKeyId(ReadOnlySpan<byte> keyId) => FixedTimeEquals(KeyId, keyId);

        /// <summary>The key ID in uppercase hexadecimal; computed once.</summary>
        public string KeyIdHex => _keyIdHex ??= ToHex(KeyId);

        /// <summary>Uppercase hexadecimal, the form GnuPG and most tooling print; computed once.</summary>
        public override string ToString() => _hex ??= ToHex(Bytes);

        private static string ToHex(byte[] bytes)
        {
            var builder = new StringBuilder(bytes.Length * 2);
            foreach (byte b in bytes)
            {
                builder.Append(b.ToString("X2", System.Globalization.CultureInfo.InvariantCulture));
            }

            return builder.ToString();
        }

        private static bool FixedTimeEquals(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b)
        {
            if (a.Length != b.Length)
            {
                return false;
            }

            int diff = 0;
            for (int i = 0; i < a.Length; i++)
            {
                diff |= a[i] ^ b[i];
            }

            return diff == 0;
        }
    }

    /// <summary>
    /// The framing a key packet body gets whenever it is hashed - for its fingerprint and inside key
    /// signatures (RFC 9580 §5.2.4, §5.5.4): 0x99 and a 2-octet length for v4, 0x9B and a 4-octet
    /// length for v6.
    /// </summary>
    internal static class KeyHashPrefix
    {
        public static byte[] Build(byte keyVersion, byte[] publicKeyPacketBody)
        {
            int length = publicKeyPacketBody.Length;
            byte[] result;
            int offset;
            if (keyVersion == 6)
            {
                result = new byte[5 + length];
                result[0] = 0x9B;
                result[1] = (byte)(length >> 24);
                result[2] = (byte)(length >> 16);
                result[3] = (byte)(length >> 8);
                result[4] = (byte)length;
                offset = 5;
            }
            else
            {
                if (length > 0xFFFF)
                {
                    throw new FailClosedException("A v4 key packet body cannot exceed 65535 octets.");
                }

                result = new byte[3 + length];
                result[0] = 0x99;
                result[1] = (byte)(length >> 8);
                result[2] = (byte)length;
                offset = 3;
            }

            System.Array.Copy(publicKeyPacketBody, 0, result, offset, length);
            return result;
        }
    }
}
