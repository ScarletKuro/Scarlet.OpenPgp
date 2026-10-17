using System.Collections.Generic;
using Scarlet.OpenPgp.Internal;
using Scarlet.OpenPgp.Packets;

namespace Scarlet.OpenPgp.Tests.Packets
{
    public class PacketReaderTests
    {
        [Fact]
        public void ReadAll_WithOldFormatOneByteLength_ShouldParseTagAndBody()
        {
            // Arrange: old-format tag 6 (public key), 1-byte length = 3, body {0x01,0x02,0x03}.
            byte[] data = { 0x98, 0x03, 0x01, 0x02, 0x03 };

            // Act
            List<Packet> packets = PacketReader.ReadAll(data);

            // Assert
            Assert.Single(packets);
            Assert.Equal(PacketTag.PublicKey, packets[0].Header.Tag);
            Assert.Equal(new byte[] { 0x01, 0x02, 0x03 }, packets[0].Body);
        }

        [Fact]
        public void ReadAll_WithNewFormatOneByteLength_ShouldParseTagAndBody()
        {
            // Arrange: new-format tag 2 (signature), 1-byte length = 5.
            byte[] data = { 0xC2, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05 };

            // Act
            List<Packet> packets = PacketReader.ReadAll(data);

            // Assert
            Assert.Single(packets);
            Assert.Equal(PacketTag.Signature, packets[0].Header.Tag);
            Assert.Equal(new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05 }, packets[0].Body);
        }

        [Fact]
        public void ReadAll_WithNewFormatTwoByteLength_ShouldParseTagAndBody()
        {
            // Arrange: new-format tag 2, 2-byte length encoding for 193 (first=192 -> (0<<8)+1+192=193).
            var data = new List<byte> { 0xC2, 192, 1 };
            for (int i = 0; i < 193; i++)
            {
                data.Add((byte)i);
            }

            // Act
            List<Packet> packets = PacketReader.ReadAll(data.ToArray());

            // Assert
            Assert.Single(packets);
            Assert.Equal(193, packets[0].Body.Length);
        }

        [Fact]
        public void ReadAll_WithPartialBodyLength_ShouldConcatenateChunksIntoOneBody()
        {
            // Arrange: new-format tag 8 (Compressed Data, one of the few tags allowed partial
            // lengths), a partial chunk of the minimum 512 bytes (0xE9 -> 1<<9), then a final
            // non-partial chunk of length 2.
            var data = new List<byte> { 0xC8, 0xE9 };
            data.AddRange(System.Linq.Enumerable.Repeat((byte)0xAA, 512));
            data.AddRange(new byte[] { 0x02, 0xBB, 0xCC });

            // Act
            List<Packet> packets = PacketReader.ReadAll(data.ToArray());

            // Assert
            Assert.Single(packets);
            Assert.Equal(514, packets[0].Body.Length);
            Assert.Equal(new byte[] { 0xBB, 0xCC }, packets[0].Body[512..]);
        }

        [Fact]
        public void ReadAll_WithPartialBodyLengthOnASignaturePacket_ShouldFailClosed()
        {
            // Arrange: RFC 4880 §4.2.2.4 only allows partial lengths on data packets.
            var data = new List<byte> { 0xC2, 0xE9 };
            data.AddRange(System.Linq.Enumerable.Repeat((byte)0xAA, 512));
            data.AddRange(new byte[] { 0x01, 0xBB });

            // Act & Assert
            Assert.Throws<FailClosedException>(() => PacketReader.ReadAll(data.ToArray()));
        }

        [Fact]
        public void ReadAll_WithFirstPartialChunkShorterThan512Bytes_ShouldFailClosed()
        {
            // Arrange: tag 8, partial chunk of length 1 (0xE0 -> 1<<0), then a final chunk.
            byte[] data = { 0xC8, 0xE0, 0xAA, 0x02, 0xBB, 0xCC };

            // Act & Assert
            Assert.Throws<FailClosedException>(() => PacketReader.ReadAll(data));
        }

        [Fact]
        public void ReadAll_WithMultiplePackets_ShouldReturnThemInOrder()
        {
            // Arrange: old-format tag 6 length 1, then new-format tag 2 length 1.
            byte[] data = { 0x98, 0x01, 0xAA, 0xC2, 0x01, 0xBB };

            // Act
            List<Packet> packets = PacketReader.ReadAll(data);

            // Assert
            Assert.Equal(2, packets.Count);
            Assert.Equal(PacketTag.PublicKey, packets[0].Header.Tag);
            Assert.Equal(PacketTag.Signature, packets[1].Header.Tag);
        }

        [Fact]
        public void ReadAll_WithUnknownTag_ShouldStillReturnItRatherThanThrow()
        {
            // Arrange: new-format tag 63 (unassigned/experimental), length 1.
            byte[] data = { 0xFF, 0x01, 0xAA };

            // Act
            List<Packet> packets = PacketReader.ReadAll(data);

            // Assert
            Assert.Equal(63, packets[0].Header.RawTag);
        }

        [Fact]
        public void ReadAll_WithLengthExceedingRemainingData_ShouldFailClosed()
        {
            // Arrange: old-format tag 6 claims a 1-byte length of 5, but only 2 bytes follow.
            byte[] data = { 0x98, 0x05, 0x01, 0x02 };

            // Act & Assert
            Assert.Throws<FailClosedException>(() => PacketReader.ReadAll(data));
        }

        [Fact]
        public void ReadAll_WithOversizedFourByteLengthCausingIntOverflow_ShouldFailClosedNotThrowUnhandled()
        {
            // Arrange: old-format tag 6, 4-byte length = 0x7FFFFFFF. Naively checking
            // "position + length > data.Length" in 32-bit int arithmetic overflows (position=5
            // plus 0x7FFFFFFF wraps negative), which would previously bypass the truncation check
            // and crash inside MemoryStream.Write instead of failing closed.
            byte[] data = { 0x9A, 0x7F, 0xFF, 0xFF, 0xFF };

            // Act & Assert
            Assert.Throws<FailClosedException>(() => PacketReader.ReadAll(data));
        }

        [Fact]
        public void ReadAll_WithTruncatedHeader_ShouldFailClosed()
        {
            // Arrange: a tag byte announcing a length octet that never arrives.
            byte[] data = { 0xC2 };

            // Act & Assert
            Assert.Throws<FailClosedException>(() => PacketReader.ReadAll(data));
        }

        [Fact]
        public void ReadAll_WithHighBitNotSetOnTagByte_ShouldFailClosed()
        {
            // Arrange
            byte[] data = { 0x02 };

            // Act & Assert
            Assert.Throws<FailClosedException>(() => PacketReader.ReadAll(data));
        }
    }
}
