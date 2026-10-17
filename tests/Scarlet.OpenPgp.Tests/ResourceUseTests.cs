using System.Diagnostics;
using Scarlet.OpenPgp.Packets;

namespace Scarlet.OpenPgp.Tests
{
    /// <summary>
    /// Regressions for work and memory a hostile or merely large input could force. Allocations are
    /// measured on the current thread (deterministic for this synchronous code); the one timing
    /// bound is far above the fixed behavior and far below the old one.
    /// </summary>
    public class ResourceUseTests
    {
        private const string Folder = "TestAssets/gnupg-generated/v4-eddsa-ed25519-legacy/";
        private const int MiB = 1024 * 1024;

        private static readonly DateTimeOffset Now = new DateTimeOffset(2026, 10, 17, 0, 0, 0, TimeSpan.Zero);

        private static long AllocatedBy(Action action)
        {
            action(); // warm up JIT and statics outside the measurement
            long before = GC.GetAllocatedBytesForCurrentThread();
            action();
            return GC.GetAllocatedBytesForCurrentThread() - before;
        }

        [Fact]
        public void SignatureInput_WithTensOfThousandsOfDistinctPackets_ShouldBeRejectedWithoutQuadraticWork()
        {
            // Arrange: 64,000 distinct tiny "signature" packets (375 KB). Deduplicating all of them
            // before checking the 32-signature limit took 8 seconds.
            var input = new List<byte>();
            for (int i = 0; i < 64000; i++)
            {
                input.AddRange([0xC2, 0x04, (byte)(i >> 24), (byte)(i >> 16), (byte)(i >> 8), (byte)i]);
            }

            OpenPgpKeyRing keyRing = OpenPgpKeyRing.Parse(File.ReadAllBytes(Folder + "public-key.gpg"));
            byte[] signatures = input.ToArray();

            // Act
            var stopwatch = Stopwatch.StartNew();
            VerificationResult result = OpenPgpVerifier.VerifyDetached("data"u8, signatures, keyRing, Now);
            stopwatch.Stop();

            // Assert
            Assert.Equal(VerificationStatus.MalformedInput, result.Status);
            Assert.True(stopwatch.Elapsed < TimeSpan.FromSeconds(2), "Took " + stopwatch.Elapsed);
        }

        [Fact]
        public void InMemoryData_ShouldNotBeCopiedWhole()
        {
            // Arrange: 16 MiB of data; the span overload used to copy all of it first.
            byte[] data = new byte[16 * MiB];
            byte[] signature = File.ReadAllBytes(Folder + "data.txt.sig");
            OpenPgpKeyRing keyRing = OpenPgpKeyRing.Parse(File.ReadAllBytes(Folder + "public-key.gpg"));

            // Act
            long allocated = AllocatedBy(() => OpenPgpVerifier.VerifyDetached(data, signature, keyRing, Now));

            // Assert: a bounded hashing buffer, not a copy of the document.
            Assert.True(allocated < 1 * MiB, "Allocated " + allocated + " bytes.");
        }

        [Fact]
        public void InMemoryData_WhenTheOutcomeIsAlreadyKnown_ShouldNotBeRead()
        {
            // Arrange: a signature by a key that isn't supplied - no hashing is needed at all.
            byte[] data = new byte[16 * MiB];
            byte[] otherSignersSignature = File.ReadAllBytes("TestAssets/gnupg-generated/v4-ecdsa-nistp256/data.txt.sig");
            OpenPgpKeyRing keyRing = OpenPgpKeyRing.Parse(File.ReadAllBytes(Folder + "public-key.gpg"));

            // Act
            VerificationResult result = OpenPgpVerifier.VerifyDetached(data, otherSignersSignature, keyRing, Now);
            long allocated = AllocatedBy(() => OpenPgpVerifier.VerifyDetached(data, otherSignersSignature, keyRing, Now));

            // Assert
            Assert.Equal(VerificationStatus.NoMatchingKey, result.Status);
            Assert.True(allocated < 256 * 1024, "Allocated " + allocated + " bytes.");
        }

        [Fact]
        public void PacketReader_ShouldCopyEachBodyOnceAndSkipIgnoredBodies()
        {
            // Arrange: a 16 MiB Padding packet (ignored by every consumer) and a 16 MiB Literal Data
            // packet. Bodies used to be copied into a growing MemoryStream and then copied again.
            int length = 16 * MiB;
            byte[] header(PacketTag tag) => [(byte)(0xC0 | (byte)tag), 0xFF, (byte)(length >> 24), (byte)(length >> 16), (byte)(length >> 8), (byte)length];
            byte[] padding = [.. header(PacketTag.Padding), .. new byte[length]];
            byte[] literal = [.. header(PacketTag.LiteralData), .. new byte[length]];

            // Act
            long paddingAllocated = AllocatedBy(() => PacketReader.ReadAll(padding));
            long literalAllocated = AllocatedBy(() => PacketReader.ReadAll(literal));

            // Assert
            Assert.Empty(PacketReader.ReadAll(padding)[0].Body);
            Assert.Equal(length, PacketReader.ReadAll(literal)[0].Body.Length);
            Assert.True(paddingAllocated < 64 * 1024, "Padding allocated " + paddingAllocated + " bytes.");
            Assert.True(literalAllocated < length + (1 * MiB), "Literal allocated " + literalAllocated + " bytes.");
        }
    }
}
