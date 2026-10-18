using System.Diagnostics;
using System.Text;
using Scarlet.OpenPgp.Armor;
using Scarlet.OpenPgp.Clearsign;
using Scarlet.OpenPgp.Internal;
using Scarlet.OpenPgp.Packets;

namespace Scarlet.OpenPgp.Tests.Fuzzing
{
    /// <summary>
    /// Deterministic mutation fuzzing of every parser that sees attacker-controlled input, seeded
    /// from the real fixtures. The invariants: internal parsers fail only with
    /// <see cref="FailClosedException"/>; the public API never throws and never takes pathologically
    /// long; and altered signed data never verifies. Set SCARLET_FUZZ_ITERATIONS to run longer (the
    /// default keeps the suite fast); SCARLET_FUZZ_SEED picks a different deterministic sequence.
    /// The coverage-guided counterpart is the libFuzzer harness under fuzz/.
    /// </summary>
    public class MutationFuzzTests
    {
        private static readonly int Iterations = ReadEnvironment("SCARLET_FUZZ_ITERATIONS", 300);

        private static readonly int Seed = ReadEnvironment("SCARLET_FUZZ_SEED", 9580);

        private static readonly TimeSpan SlowCallLimit = TimeSpan.FromSeconds(10);

        private static readonly DateTimeOffset Now = new DateTimeOffset(2026, 10, 17, 0, 0, 0, TimeSpan.Zero);

        /// <summary>
        /// A per-test seed from <see cref="Seed"/> and the test's inputs, via 32-bit FNV-1a. Unlike
        /// string.GetHashCode (randomized per process in modern .NET), this is the same in every
        /// process, so a given SCARLET_FUZZ_SEED replays exactly the same mutations.
        /// </summary>
        private static int StableSeed(params string[] parts)
        {
            unchecked
            {
                uint hash = 2166136261u ^ (uint)Seed;
                foreach (char c in string.Join("|", parts))
                {
                    hash = (hash ^ c) * 16777619u;
                }

                return (int)hash;
            }
        }

        private static int ReadEnvironment(string name, int fallback) =>
            int.TryParse(Environment.GetEnvironmentVariable(name), out int value) && value > 0 ? value : fallback;

        private static byte[] Asset(string path) => File.ReadAllBytes(Path.Combine("TestAssets", path));

        /// <summary>Detached signature fixtures (binary packets) with their data and key, chosen to be fast to verify.</summary>
        public static TheoryData<string, string, string> DetachedSeeds => new TheoryData<string, string, string>
        {
            { "gnupg-generated/v4-eddsa-ed25519-legacy", "data.txt.sig", "public-key.gpg" },
            { "gnupg-generated/v4-ecdsa-nistp256", "data.txt.sig", "public-key.gpg" },
            { "gnupg-generated/v4-signing-subkey", "data.txt.sig", "public-key.gpg" },
            { "gnupg-generated/v4-multi-signer", "data.txt.sig", "keyring-a-only.gpg" },
            { "gnupg-generated/v4-revoked-subkey-soft", "data.txt.before-revocation.sig", "public-key.gpg" },
            { "gnupg-generated/v4-expired-signature", "data.txt.expires-2099.sig", "public-key.gpg" },
            { "gnupg-generated/v4-textmode", "data-lf.txt.textmode.sig", "public-key.gpg" },
        };

        [Theory]
        [MemberData(nameof(DetachedSeeds))]
        public void PublicApi_WithMutatedSignaturePackets_ShouldNeverThrowOrHang(string folder, string signatureFile, string keyFile)
        {
            byte[] data = Asset(folder + "/" + DataFileFor(folder));
            byte[] signature = Asset(folder + "/" + signatureFile);
            byte[] keys = Asset(folder + "/" + keyFile);
            var mutator = new Mutator(StableSeed(folder, signatureFile, "signature"));

            for (int i = 0; i < Iterations; i++)
            {
                byte[] mutated = mutator.Mutate(signature);
                Run(() => OpenPgpVerifier.VerifyDetached(data, mutated, keys, Now), mutated);
            }
        }

        [Theory]
        [MemberData(nameof(DetachedSeeds))]
        public void PublicApi_WithMutatedKeyPackets_ShouldNeverThrowOrHang(string folder, string signatureFile, string keyFile)
        {
            byte[] data = Asset(folder + "/" + DataFileFor(folder));
            byte[] signature = Asset(folder + "/" + signatureFile);
            byte[] keys = Asset(folder + "/" + keyFile);
            var mutator = new Mutator(StableSeed(folder, keyFile, "keys"));

            for (int i = 0; i < Iterations; i++)
            {
                byte[] mutated = mutator.Mutate(keys);
                Run(() => OpenPgpVerifier.VerifyDetached(data, signature, mutated, Now), mutated);
            }
        }

        [Theory]
        [MemberData(nameof(DetachedSeeds))]
        public void PublicApi_WithMutatedData_ShouldNeverVerify(string folder, string signatureFile, string keyFile)
        {
            byte[] data = Asset(folder + "/" + DataFileFor(folder));
            byte[] signature = Asset(folder + "/" + signatureFile);
            byte[] keys = Asset(folder + "/" + keyFile);
            var mutator = new Mutator(StableSeed(folder, signatureFile, "data"));
            bool textMode = signatureFile.Contains("textmode", StringComparison.Ordinal);

            // Baseline: the unaltered data must verify, or "altered data never verifies" proves nothing.
            VerificationResult baseline = OpenPgpVerifier.VerifyDetached(data, signature, keys, Now);
            Assert.True(baseline.IsValid, baseline.ToString());

            for (int i = 0; i < Math.Max(1, Iterations / 3); i++)
            {
                byte[] mutated = mutator.Mutate(data);
                if (mutated.AsSpan().SequenceEqual(data) || (textMode && SameText(mutated, data)))
                {
                    continue; // not actually a change (text mode treats LF and CRLF alike)
                }

                VerificationResult result = Run(() => OpenPgpVerifier.VerifyDetached(mutated, signature, keys, Now), mutated);
                Assert.False(result.IsValid, "Altered data verified: " + Convert.ToBase64String(mutated));
            }
        }

        [Theory]
        [InlineData("gnupg-generated/v4-eddsa-ed25519-legacy/data.txt.clearsign.asc", "gnupg-generated/v4-eddsa-ed25519-legacy/public-key.gpg")]
        [InlineData("gnupg-generated/v4-multi-signer/data.txt.clearsign.asc", "gnupg-generated/v4-multi-signer/keyring-a-only.gpg")]
        [InlineData("rfc9580/a6-cleartext-signed.asc", "rfc9580/a3-v6-certificate.gpg")]
        [InlineData("bun-release/SHASUMS256.txt.asc", "bun-release/bun-public-key.asc")]
        public void PublicApi_WithMutatedClearsignedText_ShouldNeverThrowOrVerifyAlteredText(string messageFile, string keyFile)
        {
            string message = Encoding.UTF8.GetString(Asset(messageFile));
            byte[] keys = Asset(keyFile);
            string? originalSignedText = OpenPgpVerifier.VerifyClearsign(message, keys, Now).SignedText;
            Assert.NotNull(originalSignedText);
            var mutator = new Mutator(StableSeed(messageFile, "clearsign"));

            for (int i = 0; i < Iterations; i++)
            {
                string mutated = mutator.MutateText(message);
                VerificationResult result = Run(() => OpenPgpVerifier.VerifyClearsign(mutated, keys, Now), Encoding.UTF8.GetBytes(mutated));

                // Whatever the mutation, a valid result may only ever vouch for the original text.
                if (result.IsValid)
                {
                    Assert.Equal(originalSignedText, result.SignedText);
                }
            }
        }

        [Theory]
        [InlineData("real-world/gnupg-npth-multisig/gnupg-signature-keys.gpg")]
        [InlineData("real-world/nodejs-clearsign-rsa/SHASUMS256.txt.sig")]
        [InlineData("real-world/debian-trixie-release/archive-key-13-only.gpg")]
        [InlineData("rfc9580/a3-v6-certificate.gpg")]
        [InlineData("gnupg-generated/v4-dsa2048/public-key.gpg")]
        [InlineData("gnupg-generated/v4-ecdsa-brainpoolp384r1/public-key.gpg")]
        [InlineData("gnupg-generated/v4-revoked-key-hard/public-key.gpg")]
        public void Parsers_WithMutatedPackets_ShouldOnlyFailClosed(string seedFile)
        {
            byte[] seed = Asset(seedFile);
            var mutator = new Mutator(StableSeed(seedFile, "packets"));

            for (int i = 0; i < Iterations * 3; i++)
            {
                byte[] mutated = mutator.Mutate(seed);
                ExpectOnlyFailClosed(mutated, () =>
                {
                    foreach (Packet packet in PacketReader.ReadAll(mutated))
                    {
                        if (packet.Header.Tag == PacketTag.Signature)
                        {
                            ExpectOnlyFailClosed(mutated, () => ConsumeSignature(SignaturePacket.Parse(packet.Body)));
                        }
                        else if (packet.Header.Tag == PacketTag.PublicKey || packet.Header.Tag == PacketTag.PublicSubkey)
                        {
                            ExpectOnlyFailClosed(mutated, () => PublicKeyPacket.Parse(packet.Body));
                        }
                    }
                });
            }
        }

        [Theory]
        [InlineData("real-world/tor-browser-subkey/sha256sums-signed-build.txt.asc")]
        [InlineData("real-world/gnupg-npth-multisig/gnupg-signature-keys.asc")]
        [InlineData("real-world/debian-trixie-release/InRelease")]
        [InlineData("rfc9580/a6-cleartext-signed.asc")]
        public void ArmorAndClearsignParsers_WithMutatedText_ShouldOnlyFailClosed(string seedFile)
        {
            string seed = Encoding.UTF8.GetString(Asset(seedFile));
            var mutator = new Mutator(StableSeed(seedFile, "text"));

            for (int i = 0; i < Iterations; i++)
            {
                string mutated = mutator.MutateText(seed);
                byte[] bytes = Encoding.UTF8.GetBytes(mutated);
                ExpectOnlyFailClosed(bytes, () => AsciiArmorReader.ReadAll(mutated));
                ExpectOnlyFailClosed(bytes, () => PacketInput.Decode(bytes, "SIGNATURE"));
                ExpectOnlyFailClosed(bytes, () =>
                {
                    ClearsignMessage message = ClearsignParser.Parse(mutated);
                    ClearsignCanonicalizer.Encode(ClearsignCanonicalizer.CanonicalizeText(message.DashEscapedBodyLines));
                });
            }
        }

        private static void ConsumeSignature(SignaturePacket signature)
        {
            // Touch every lazily-evaluated accessor - each may parse further.
            _ = signature.EmbeddedSignatures.ToList();
            ExpectOnlyFailClosed(signature.Body, () => _ = signature.KeyFlags);
            ExpectOnlyFailClosed(signature.Body, () => _ = signature.RevocationReason);
            ExpectOnlyFailClosed(signature.Body, () => signature.TryGetHashedTime(SignatureSubpacketType.SignatureCreationTime, out _));
        }

        private static string DataFileFor(string folder) => folder.EndsWith("v4-textmode", StringComparison.Ordinal) ? "data-lf.txt" : "data.txt";

        private static bool SameText(byte[] a, byte[] b) =>
            Encoding.Latin1.GetString(a).Replace("\r\n", "\n") == Encoding.Latin1.GetString(b).Replace("\r\n", "\n");

        private static VerificationResult Run(Func<VerificationResult> call, byte[] input)
        {
            var stopwatch = Stopwatch.StartNew();
            VerificationResult result;
            try
            {
                result = call();
            }
            catch (Exception ex)
            {
                throw new Xunit.Sdk.XunitException("The public API threw " + ex.GetType().Name + " (" + ex.Message + ") for input (SCARLET_FUZZ_SEED=" + Seed + "): " + Convert.ToBase64String(input), ex);
            }

            Assert.True(stopwatch.Elapsed < SlowCallLimit, "Pathologically slow (" + stopwatch.Elapsed + ") for input: " + Convert.ToBase64String(input));
            Assert.NotNull(result);
            return result;
        }

        private static void ExpectOnlyFailClosed(byte[] input, Action action)
        {
            try
            {
                action();
            }
            catch (FailClosedException)
            {
                // the one allowed failure mode
            }
            catch (Exception ex)
            {
                throw new Xunit.Sdk.XunitException("A parser threw " + ex.GetType().Name + " (" + ex.Message + ") instead of failing closed, for input (SCARLET_FUZZ_SEED=" + Seed + "): " + Convert.ToBase64String(input), ex);
            }
        }

        /// <summary>Byte- and text-level mutations biased toward what breaks binary parsers: length fields, boundary values, truncation, splicing.</summary>
        private sealed class Mutator
        {
            private static readonly byte[] InterestingBytes = [0x00, 0x01, 0x7F, 0x80, 0xBF, 0xC0, 0xDF, 0xE0, 0xFE, 0xFF];

            private static readonly string[] InterestingText =
            [
                "\n", "\r", "\r\n", "-", "- ", " ", "\t", "=", ":", "-----BEGIN PGP SIGNATURE-----", "-----END PGP SIGNATURE-----",
                "-----BEGIN PGP SIGNED MESSAGE-----", "Hash: SHA256", "﻿", "\uD800", "é", "A", "//", "==",
            ];

            private readonly Random _random;

            public Mutator(int seed)
            {
                _random = new Random(seed);
            }

            public byte[] Mutate(byte[] input)
            {
                var bytes = new List<byte>(input);
                int count = 1 + _random.Next(4);
                for (int i = 0; i < count; i++)
                {
                    MutateOnce(bytes);
                }

                return bytes.ToArray();
            }

            public string MutateText(string input)
            {
                var builder = new StringBuilder(input);
                int count = 1 + _random.Next(3);
                for (int i = 0; i < count; i++)
                {
                    int position = _random.Next(builder.Length + 1);
                    switch (_random.Next(4))
                    {
                        case 0:
                            builder.Insert(position, InterestingText[_random.Next(InterestingText.Length)]);
                            break;
                        case 1:
                            if (builder.Length > 0)
                            {
                                builder.Remove(Math.Min(position, builder.Length - 1), Math.Min(1 + _random.Next(8), builder.Length - Math.Min(position, builder.Length - 1)));
                            }

                            break;
                        case 2:
                            if (position < builder.Length)
                            {
                                builder[position] = (char)(' ' + _random.Next(95));
                            }

                            break;
                        default:
                            builder.Length = Math.Min(builder.Length, position);
                            break;
                    }
                }

                return builder.ToString();
            }

            private void MutateOnce(List<byte> bytes)
            {
                if (bytes.Count == 0)
                {
                    bytes.Add((byte)_random.Next(256));
                    return;
                }

                int position = _random.Next(bytes.Count);
                switch (_random.Next(9))
                {
                    case 0: // flip a bit
                        bytes[position] ^= (byte)(1 << _random.Next(8));
                        break;
                    case 1: // random byte
                        bytes[position] = (byte)_random.Next(256);
                        break;
                    case 2: // boundary byte (length octets, tags, MPI headers)
                        bytes[position] = InterestingBytes[_random.Next(InterestingBytes.Length)];
                        break;
                    case 3: // big-endian 16/32-bit boundary values over a length field
                        uint value = new uint[] { 0, 1, 0x7F, 0xFF, 0x100, 0x7FFF, 0xFFFF, 0x7FFFFFFF, 0xFFFFFFFF }[_random.Next(9)];
                        int width = _random.Next(2) == 0 ? 2 : 4;
                        for (int i = 0; i < width && position + i < bytes.Count; i++)
                        {
                            bytes[position + i] = (byte)(value >> (8 * (width - 1 - i)));
                        }

                        break;
                    case 4: // insert random bytes
                        var inserted = new byte[1 + _random.Next(8)];
                        _random.NextBytes(inserted);
                        bytes.InsertRange(position, inserted);
                        break;
                    case 5: // delete a range
                        bytes.RemoveRange(position, Math.Min(1 + _random.Next(16), bytes.Count - position));
                        break;
                    case 6: // duplicate a range (repeated packets/subpackets)
                        int length = Math.Min(1 + _random.Next(64), bytes.Count - position);
                        bytes.InsertRange(_random.Next(bytes.Count + 1), bytes.GetRange(position, length));
                        break;
                    case 7: // truncate
                        bytes.RemoveRange(position, bytes.Count - position);
                        break;
                    default: // swap two bytes
                        int other = _random.Next(bytes.Count);
                        (bytes[position], bytes[other]) = (bytes[other], bytes[position]);
                        break;
                }
            }
        }
    }
}
