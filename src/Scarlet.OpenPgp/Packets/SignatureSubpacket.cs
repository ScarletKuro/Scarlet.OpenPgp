namespace Scarlet.OpenPgp.Packets
{
    /// <summary>A single parsed signature subpacket (RFC 9580 §5.2.3.7).</summary>
    internal sealed class SignatureSubpacket(byte rawType, bool critical, byte[] data)
    {
        public byte RawType { get; } = rawType;

        public bool Critical { get; } = critical;

        public byte[] Data { get; } = data;

        public bool Is(SignatureSubpacketType type) => RawType == (byte)type;
    }
}
