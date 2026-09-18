using System.Numerics;
using Scarlet.OpenPgp.Internal;

namespace Scarlet.OpenPgp.Packets
{
    /// <summary>
    /// OpenPGP "multiprecision integer" encoding (RFC 4880 §3.2): a 2-byte big-endian bit-count
    /// prefix followed by ceil(bits/8) big-endian, unsigned magnitude bytes.
    /// </summary>
    /// <remarks>
    /// The tricky part is entirely on the .NET side: <see cref="BigInteger"/>'s byte-array
    /// constructor and <see cref="BigInteger.ToByteArray()"/> are little-endian and two's-complement,
    /// while MPIs are big-endian and unsigned. Getting the byte-order reversal and sign guard byte
    /// wrong silently produces a *negative* BigInteger whenever the magnitude's high bit happens to
    /// be set - which then poisons every downstream RSA/key computation without an obvious symptom.
    /// </remarks>
    internal static class Mpi
    {
        /// <summary>Reads one MPI starting at <paramref name="offset"/>. Returns the value and the number of bytes consumed (including the 2-byte length prefix).</summary>
        public static (BigInteger Value, int BytesConsumed) ReadFrom(byte[] data, int offset)
        {
            if (offset < 0 || offset + 2 > data.Length)
            {
                throw new FailClosedException("Unexpected end of input while reading an MPI length prefix.");
            }

            int bitLength = (data[offset] << 8) | data[offset + 1];
            int byteLength = (bitLength + 7) / 8;

            if (offset + 2 + byteLength > data.Length)
            {
                throw new FailClosedException("Unexpected end of input while reading an MPI body (truncated).");
            }

            var magnitude = new byte[byteLength];
            System.Array.Copy(data, offset + 2, magnitude, 0, byteLength);

            return (ToUnsignedBigInteger(magnitude), 2 + byteLength);
        }

        /// <summary>Interprets a big-endian byte sequence as an unsigned magnitude.</summary>
        public static BigInteger ToUnsignedBigInteger(byte[] bigEndianMagnitude)
        {
            // +1 guard byte (always zero) at the most-significant end so BigInteger's little-endian,
            // two's-complement constructor never mistakes a set high bit for a negative sign.
            var littleEndian = new byte[bigEndianMagnitude.Length + 1];
            for (int i = 0; i < bigEndianMagnitude.Length; i++)
            {
                littleEndian[i] = bigEndianMagnitude[bigEndianMagnitude.Length - 1 - i];
            }

            return new BigInteger(littleEndian);
        }

        /// <summary>
        /// Renders a non-negative <see cref="BigInteger"/> as a fixed-length, big-endian, unsigned
        /// byte sequence (left-padded with zeros). Throws if the value does not fit in that length.
        /// </summary>
        public static byte[] ToFixedLengthUnsignedBytes(BigInteger value, int length)
        {
            byte[] littleEndian = value.ToByteArray(); // little-endian, may include a trailing 0x00 sign guard
            var result = new byte[length];

            int copyLength = System.Math.Min(littleEndian.Length, length);
            for (int i = 0; i < copyLength; i++)
            {
                result[length - 1 - i] = littleEndian[i];
            }

            for (int i = length; i < littleEndian.Length; i++)
            {
                if (littleEndian[i] != 0)
                {
                    throw new FailClosedException("Value does not fit in the requested fixed-length byte encoding.");
                }
            }

            return result;
        }
    }
}
