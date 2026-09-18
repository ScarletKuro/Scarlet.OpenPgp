namespace Scarlet.OpenPgp.Armor
{
    /// <summary>
    /// The CRC24 checksum used by OpenPGP ASCII armor (RFC 4880 §6.1) to detect transmission
    /// corruption in the base64-encoded body. This is not a security control - it exists to catch
    /// accidental mangling, not tampering - but a mismatch must still fail closed like any other
    /// malformed input.
    /// </summary>
    internal static class Crc24
    {
        private const int Init = 0x00B704CE;
        private const int Poly = 0x01864CFB;
        private const int Mask = 0x00FFFFFF;

        public static int Compute(byte[] data)
        {
            int crc = Init;
            for (int i = 0; i < data.Length; i++)
            {
                crc ^= data[i] << 16;
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
