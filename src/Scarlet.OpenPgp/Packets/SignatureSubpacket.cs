using System;

namespace Scarlet.OpenPgp.Packets
{
    /// <summary>
    /// A single signature subpacket (RFC 9580 §5.2.3.7): a view into the signature body it was read
    /// from, so reading one copies nothing.
    /// </summary>
    internal readonly struct SignatureSubpacket(byte[] buffer, int dataOffset, int dataLength, byte rawType, bool critical)
    {
        private readonly byte[] _buffer = buffer;
        private readonly int _dataOffset = dataOffset;
        private readonly int _dataLength = dataLength;

        public byte RawType { get; } = rawType;

        public bool Critical { get; } = critical;

        public ReadOnlySpan<byte> Data => new(_buffer, _dataOffset, _dataLength);

        public bool Is(SignatureSubpacketType type) => RawType == (byte)type;
    }
}
