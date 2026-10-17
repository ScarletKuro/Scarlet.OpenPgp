using BenchmarkDotNet.Attributes;
using Scarlet.OpenPgp.Armor;
using Scarlet.OpenPgp.Crypto.Ed448;
using Scarlet.OpenPgp.Hashing;
using Scarlet.OpenPgp.Packets;

namespace Scarlet.OpenPgp.Benchmarks
{
    /// <summary>Hash throughput over 1 MiB, for the in-library hashes against the platform's SHA-256.</summary>
    [MemoryDiagnoser]
    public class HashBenchmarks
    {
        private readonly byte[] _data = new byte[1024 * 1024];

        [Params("Sha256", "Sha224", "Sha3_256", "Sha3_512")]
        public string Algorithm { get; set; } = "";

        [GlobalSetup]
        public void Setup() => new Random(42).NextBytes(_data);

        [Benchmark]
        public byte[] Hash()
        {
            using HashContext hash = HashContext.Create(Enum.Parse<HashAlgorithmId>(Algorithm));
            hash.Update(_data);
            return hash.Finish();
        }
    }

    /// <summary>Ed448 has no GnuPG fixture (GnuPG only emits it in v5 keys), so it's timed directly on an RFC 8032 vector.</summary>
    [MemoryDiagnoser]
    public class Ed448Benchmarks
    {
        private static readonly byte[] PublicKey = Convert.FromHexString(
            "43ba28f430cdff456ae531545f7ecd0ac834a55d9358c0372bfa0c6c6798c0866aea01eb00742802b8438ea4cb82169c235160627b4c3a9480");

        private static readonly byte[] Message = [0x03];

        private static readonly byte[] Signature = Convert.FromHexString(
            "26b8f91727bd62897af15e41eb43c377efb9c610d48f2335cb0bd0087810f4352541b143c4b981b7e18f62de8ccdf633fc1bf037ab7cd779805e0dbcc0aae1cb" +
            "cee1afb2e027df36bc04dcecbf154336c19f0af7e0a6472905e799f1953d2a0ff3348ab21aa4adafd1d234441cf807c03a00");

        [Benchmark]
        public bool Verify() => Ed448Verifier.Verify(PublicKey, Message, Signature);
    }

    /// <summary>Decoding input: ASCII armor (base64) and packet framing.</summary>
    [MemoryDiagnoser]
    public class DecodeBenchmarks
    {
        private string _armoredKeys = "";
        private byte[] _binaryKeys = [];

        [GlobalSetup]
        public void Setup()
        {
            _armoredKeys = Assets.Text("real-world/debian-trixie-release/archive-key-13.asc");
            _binaryKeys = Assets.Bytes("real-world/debian-trixie-release/debian-keyring.gpg");
        }

        [Benchmark]
        public byte[] DearmorKeys() => PacketInput.Decode(_armoredKeys, "PUBLIC KEY BLOCK");

        [Benchmark]
        public int ReadPackets() => PacketReader.ReadAll(_binaryKeys).Count;
    }

    /// <summary>A 1 MiB text-mode body with LF line endings (the canonicalizing path). The signature is over other data, so it fails - after hashing everything.</summary>
    [MemoryDiagnoser]
    public class TextModeBenchmarks
    {
        private byte[] _data = [];
        private byte[] _signature = [];
        private OpenPgpKeyRing _keyRing = null!;

        [GlobalSetup]
        public void Setup()
        {
            const string folder = "gnupg-generated/v4-textmode/";
            _signature = Assets.Bytes(folder + "data-lf.txt.textmode.sig");
            _keyRing = OpenPgpKeyRing.Parse(Assets.Bytes(folder + "public-key.gpg"));
            byte[] line = "The quick brown fox jumps over the lazy dog, again and again and again.\n"u8.ToArray();
            _data = new byte[1024 * 1024 / line.Length * line.Length];
            for (int i = 0; i < _data.Length; i += line.Length)
            {
                line.CopyTo(_data, i);
            }
        }

        [Benchmark]
        public VerificationResult Verify() => OpenPgpVerifier.VerifyDetached(_data, _signature, _keyRing, Assets.AssembledOn);
    }
}
