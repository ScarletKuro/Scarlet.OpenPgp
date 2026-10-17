namespace Scarlet.OpenPgp.Packets
{
    /// <summary>A parsed packet: its tag and the fully-assembled body (partial-body chunks already concatenated).</summary>
    internal readonly struct PacketHeader(PacketTag tag, byte rawTag)
    {
        public PacketTag Tag { get; } = tag;

        /// <summary>The raw numeric tag, kept even when it doesn't map to a known <see cref="PacketTag"/> value.</summary>
        public byte RawTag { get; } = rawTag;
    }
}
