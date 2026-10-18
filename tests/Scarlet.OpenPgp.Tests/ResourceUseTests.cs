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

        [Theory]
        [InlineData(0xD5, 0x00)] // empty Padding packets: ignored, so they used to pile up unchecked
        [InlineData(0xC2, 0x00)] // identical empty "signature" packets: deduplicated, but each still materialized
        public void SignatureInput_OfAMillionTinyPackets_ShouldNotAmplifyMemory(byte tag, byte length)
        {
            // Arrange: 1 MiB of 2-byte packets. Reading every packet before looking at any made this
            // allocate 69 MiB of packet objects.
            ReadOnlySpan<byte> packet = [tag, length];
            byte[] input = new byte[MiB];
            for (int i = 0; i < input.Length; i += packet.Length)
            {
                packet.CopyTo(input.AsSpan(i));
            }

            var keyRing = OpenPgpKeyRing.Parse(File.ReadAllBytes(Folder + "public-key.gpg"));
            byte[] data = File.ReadAllBytes(Folder + "data.txt");
            VerificationResult? result = null;

            // Act
            long allocated = AllocatedBy(() => result = OpenPgpVerifier.VerifyDetached(data, input, keyRing, Now));

            // Assert
            Assert.NotNull(result);
            Assert.False(result.IsValid);
            // The input is copied once (the span overload owns its own copy); nothing else may scale with it.
            Assert.True(allocated < input.Length + (256 * 1024), "Allocated " + allocated + " bytes for a " + input.Length + "-byte input.");
        }

        [Fact]
        public void KeyInput_WithThousandsOfIdenticalCertificateCopies_ShouldMergeInLinearMemory()
        {
            // Arrange: the same certificate 4,000 times (under 1 MB). Folding each copy into the
            // growing merged certificate allocated about 1 GB.
            byte[] certificate = File.ReadAllBytes(Folder + "public-key.gpg");
            byte[] keys = [.. Enumerable.Repeat(certificate, 4000).SelectMany(b => b)];
            OpenPgpKeyRing? keyRing = null;

            // Act
            long allocated = AllocatedBy(() => keyRing = OpenPgpKeyRing.Parse(keys));

            // Assert
            Assert.NotNull(keyRing);
            Assert.Single(keyRing.Certificates);
            Assert.True(allocated < 32L * keys.Length, "Allocated " + allocated + " bytes for a " + keys.Length + "-byte input.");
        }

        [Fact]
        public void KeyInput_WithThousandsOfSlightlyDifferentCopies_ShouldExhaustOneSharedCheckBudget()
        {
            // Arrange: each copy gets its own extra User ID, so none is an exact repeat; every copy's
            // self-signatures would be checked again. The copies share one budget, so they can't
            // multiply what one certificate is allowed.
            byte[] certificate = File.ReadAllBytes(Folder + "public-key.gpg");
            // This certificate has one self-signature, so 5,000 copies need 5,000 checks - over the 4,096 budget.
            byte[] keys = [.. Enumerable.Range(0, 5000).SelectMany(i => (byte[])[.. certificate, 0xCD, 0x04, .. BitConverter.GetBytes(i)])];
            string? error = null;

            // Act
            long allocated = AllocatedBy(() => OpenPgpKeyRing.TryParse(keys, out _, out error));

            // Assert
            Assert.Contains("signature checks", error, StringComparison.Ordinal);
            Assert.True(allocated < 32L * keys.Length, "Allocated " + allocated + " bytes for a " + keys.Length + "-byte input.");
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
            Assert.Empty(PacketReader.ReadAll(padding)); // ignored packets are dropped entirely
            Assert.Equal(length, PacketReader.ReadAll(literal)[0].Body.Length);
            Assert.True(paddingAllocated < 64 * 1024, "Padding allocated " + paddingAllocated + " bytes.");
            Assert.True(literalAllocated < length + (1 * MiB), "Literal allocated " + literalAllocated + " bytes.");
        }
    }
}
