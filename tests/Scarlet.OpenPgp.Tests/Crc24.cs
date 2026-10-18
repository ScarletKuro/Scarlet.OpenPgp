namespace Scarlet.OpenPgp.Tests
{
    /// <summary>
    /// The CRC24 checksum of OpenPGP ASCII armor (RFC 4880 §6.1), for tests that build armor the way
    /// other implementations write it. The library itself doesn't check it: RFC 9580 §6.1 makes it
    /// optional, and it was never a security control - the signature is.
    /// </summary>
    internal static class Crc24
    {
        private const int Init = 0x00B704CE;
        private const int Poly = 0x01864CFB;
        private const int Mask = 0x00FFFFFF;

        public static int Compute(byte[] data)
        {
            int crc = Init;
            foreach (byte b in data)
            {
                crc ^= b << 16;
                for (int bit = 0; bit < 8; bit++)
                {
                    crc <<= 1;
                    if ((crc & 0x01000000) != 0)
                    {
                        crc ^= Poly;
                    }
                }
            }

            return crc & Mask;
        }
    }
}
