using BenchmarkDotNet.Attributes;

namespace Scarlet.OpenPgp.Benchmarks
{
    /// <summary>One detached verification per algorithm, against a key ring parsed once (the steady state).</summary>
    [MemoryDiagnoser]
    public class VerifyBenchmarks
    {
        private byte[] _data = [];
        private byte[] _signature = [];
        private OpenPgpKeyRing _keyRing = null!;

        [Params(
            "v4-rsa3072",
            "v4-dsa3072",
            "v4-ecdsa-nistp256",
            "v4-ecdsa-nistp521",
            "v4-ecdsa-brainpoolp512r1",
            "v4-eddsa-ed25519-legacy")]
        public string Fixture { get; set; } = "";

        [GlobalSetup]
        public void Setup()
        {
            string folder = "gnupg-generated/" + Fixture + "/";
            _data = Assets.Bytes(folder + "data.txt");
            _signature = Assets.Bytes(folder + "data.txt.sig");
            _keyRing = OpenPgpKeyRing.Parse(Assets.Bytes(folder + "public-key.gpg"));
            VerificationResult result = Verify();
            if (!result.IsValid)
            {
                throw new InvalidOperationException(Fixture + ": " + result);
            }
        }

        [Benchmark]
        public VerificationResult Verify() => OpenPgpVerifier.VerifyDetached(_data, _signature, _keyRing, Assets.AssembledOn);
    }

    /// <summary>Parsing keys, which checks every self-signature: the cost of loading a key file.</summary>
    [MemoryDiagnoser]
    public class KeyRingBenchmarks
    {
        private byte[] _debianKeyring = [];
        private byte[] _ed25519Key = [];
        private byte[] _rsaArmored = [];

        [GlobalSetup]
        public void Setup()
        {
            _debianKeyring = Assets.Bytes("real-world/debian-trixie-release/debian-keyring.gpg");
            _ed25519Key = Assets.Bytes("gnupg-generated/v4-eddsa-ed25519-legacy/public-key.gpg");
            _rsaArmored = Assets.Bytes("gnupg-generated/v4-rsa3072/public-key.asc");
        }

        [Benchmark]
        public OpenPgpKeyRing DebianKeyring() => OpenPgpKeyRing.Parse(_debianKeyring);

        [Benchmark]
        public OpenPgpKeyRing Ed25519Key() => OpenPgpKeyRing.Parse(_ed25519Key);

        [Benchmark]
        public OpenPgpKeyRing RsaArmored() => OpenPgpKeyRing.Parse(_rsaArmored);
    }

    /// <summary>End-to-end real-world cases: apt's InRelease (clearsigned, 140 KB) and Release.gpg (detached).</summary>
    [MemoryDiagnoser]
    public class RealWorldBenchmarks
    {
        private string _inRelease = "";
        private byte[] _release = [];
        private byte[] _releaseSignature = [];
        private OpenPgpKeyRing _keyRing = null!;

        [GlobalSetup]
        public void Setup()
        {
            const string folder = "real-world/debian-trixie-release/";
            _inRelease = Assets.Text(folder + "InRelease");
            _release = Assets.Bytes(folder + "Release");
            _releaseSignature = Assets.Bytes(folder + "Release.gpg");
            _keyRing = OpenPgpKeyRing.Parse(Assets.Bytes(folder + "debian-keyring.gpg"));
            if (!InRelease().IsValid || !ReleaseGpg().IsValid)
            {
                throw new InvalidOperationException("Debian fixtures don't verify.");
            }
        }

        [Benchmark]
        public VerificationResult InRelease() => OpenPgpVerifier.VerifyClearsign(_inRelease, _keyRing, Assets.AssembledOn);

        [Benchmark]
        public VerificationResult ReleaseGpg() => OpenPgpVerifier.VerifyDetached(_release, _releaseSignature, _keyRing, Assets.AssembledOn);
    }
}
