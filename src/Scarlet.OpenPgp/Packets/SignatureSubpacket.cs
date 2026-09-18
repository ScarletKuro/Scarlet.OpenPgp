namespace Scarlet.OpenPgp.Packets
{
    /// <summary>A single parsed signature subpacket (RFC 4880 §5.2.3.1).</summary>
    internal sealed class SignatureSubpacket
    {
        public SignatureSubpacket(byte rawType, bool critical, byte[] data)
        {
            RawType = rawType;
            Critical = critical;
            Data = data;
        }

        public byte RawType { get; }

        public bool Critical { get; }

        public byte[] Data { get; }

        public bool Is(SignatureSubpacketType type) => RawType == (byte)type;
    }
}
