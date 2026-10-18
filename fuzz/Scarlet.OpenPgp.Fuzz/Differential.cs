using System.Numerics;
using System.Text.Json;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Scarlet.OpenPgp.Crypto.Ecdsa;
using Scarlet.OpenPgp.Crypto.Ed25519;
using Scarlet.OpenPgp.Crypto.Ed448;
using Scarlet.OpenPgp.Crypto.Rsa;
using Scarlet.OpenPgp.Hashing;
using Scarlet.OpenPgp.Packets;
using BcBigInteger = Org.BouncyCastle.Math.BigInteger;
using BcEd25519 = Org.BouncyCastle.Math.EC.Rfc8032.Ed25519;
using BcEd448 = Org.BouncyCastle.Math.EC.Rfc8032.Ed448;

namespace Scarlet.OpenPgp.Fuzz;

/// <summary>
/// Differential targets: the same (key, signature, message) goes to this library's verifier and to
/// BouncyCastle's, and any disagreement is a crash. The fuzzer mutates valid triples (seeded from
/// Wycheproof's valid vectors), so it explores exactly the near-valid inputs where a verifier that
/// accepts a forgery - or rejects a genuine signature - differs from an independent one.
/// </summary>
/// <remarks>
/// Deliberate differences are excluded rather than reported: this library rejects small-order
/// EdDSA public keys and non-uncompressed ECDSA points (BouncyCastle may accept both), and for RSA
/// only "accepted here, rejected by BouncyCastle" is a failure, because BouncyCastle also accepts a
/// DigestInfo encoded without its NULL parameter, which this library refuses.
/// </remarks>
internal static class Differential
{
    private const int Ed25519KeyLength = 32;
    private const int Ed25519SignatureLength = 64;
    private const int Ed448KeyLength = 57;
    private const int Ed448SignatureLength = 114;
    private const int P256PointLength = 65;
    private const int P256ScalarLength = 32;

    private static readonly X9ECParameters P256 = ECNamedCurveTable.GetByName("P-256");
    private static readonly ECDomainParameters P256Domain = new(P256);
    private static readonly Lazy<(BigInteger N, BigInteger E)> RsaKey = new(LoadRsaKey);

    public static void Ed25519(ReadOnlySpan<byte> input)
    {
        if (input.Length < Ed25519KeyLength + Ed25519SignatureLength)
        {
            return;
        }

        byte[] publicKey = input[..Ed25519KeyLength].ToArray();
        byte[] signature = input.Slice(Ed25519KeyLength, Ed25519SignatureLength).ToArray();
        byte[] message = input[(Ed25519KeyLength + Ed25519SignatureLength)..].ToArray();

        bool ours = Ed25519Verifier.Verify(new Ed25519PublicKey(publicKey), message, signature);
        bool theirs = BcEd25519.Verify(signature, 0, publicKey, 0, message, 0, message.Length);
        if (ours != theirs && !(theirs && IsSmallOrderEd25519(publicKey)))
        {
            Fail("Ed25519", ours, theirs);
        }
    }

    public static void Ed448(ReadOnlySpan<byte> input)
    {
        if (input.Length < Ed448KeyLength + Ed448SignatureLength)
        {
            return;
        }

        byte[] publicKey = input[..Ed448KeyLength].ToArray();
        byte[] signature = input.Slice(Ed448KeyLength, Ed448SignatureLength).ToArray();
        byte[] message = input[(Ed448KeyLength + Ed448SignatureLength)..].ToArray();

        bool ours = Ed448Verifier.Verify(publicKey, message, signature);
        bool theirs = BcEd448.Verify(signature, 0, publicKey, 0, [], message, 0, message.Length);
        if (ours != theirs && !(theirs && IsSmallOrderEd448(publicKey)))
        {
            Fail("Ed448", ours, theirs);
        }
    }

    /// <summary>Input: an SEC 1 point (65 octets), r and s (32 each), then the digest.</summary>
    public static void EcdsaP256(ReadOnlySpan<byte> input)
    {
        int digestStart = P256PointLength + (2 * P256ScalarLength);
        if (input.Length <= digestStart)
        {
            return;
        }

        byte[] point = input[..P256PointLength].ToArray();
        byte[] r = input.Slice(P256PointLength, P256ScalarLength).ToArray();
        byte[] s = input.Slice(P256PointLength + P256ScalarLength, P256ScalarLength).ToArray();
        byte[] digest = input[digestStart..].ToArray();

        bool ours = EcdsaVerifier.Verify(EcCurve.NistP256, point, digest, Mpi.ToUnsignedBigInteger(r), Mpi.ToUnsignedBigInteger(s));
        bool theirs;
        try
        {
            var signer = new ECDsaSigner();
            signer.Init(false, new ECPublicKeyParameters(P256.Curve.DecodePoint(point), P256Domain));
            theirs = signer.VerifySignature(digest, new BcBigInteger(1, r), new BcBigInteger(1, s));
        }
        catch (Exception ex) when (ex is ArgumentException or FormatException)
        {
            theirs = false; // BouncyCastle refuses the point: a bad encoding, or not on the curve
        }

        if (ours != theirs && !(theirs && point[0] != 0x04))
        {
            Fail("ECDSA P-256", ours, theirs);
        }
    }

    /// <summary>Input: a 256-octet signature under a fixed 2048-bit Wycheproof key, then the message (SHA-256).</summary>
    public static void Rsa2048(ReadOnlySpan<byte> input)
    {
        (BigInteger n, BigInteger e) = RsaKey.Value;
        var key = new RsaPublicKey(n, e);
        if (input.Length < key.ModulusByteLength)
        {
            return;
        }

        byte[] signature = input[..key.ModulusByteLength].ToArray();
        byte[] message = input[key.ModulusByteLength..].ToArray();

        bool ours = RsaPkcs1Verifier.Verify(key, HashAlgorithmId.Sha256, Sha256(message), Mpi.ToUnsignedBigInteger(signature));
        bool theirs;
        try
        {
            var signer = new RsaDigestSigner(new Sha256Digest());
            signer.Init(false, new RsaKeyParameters(false, ToBouncyCastle(n), ToBouncyCastle(e)));
            signer.BlockUpdate(message, 0, message.Length);
            theirs = signer.VerifySignature(signature);
        }
        catch (Org.BouncyCastle.Crypto.DataLengthException)
        {
            theirs = false; // signature value not below the modulus
        }

        if (ours && !theirs)
        {
            Fail("RSA 2048", ours, theirs);
        }
    }

    /// <summary>Writes Wycheproof's valid vectors for <paramref name="target"/> as seed inputs into <paramref name="directory"/>.</summary>
    public static int WriteSeeds(string target, string directory)
    {
        Directory.CreateDirectory(directory);
        int count = 0;
        foreach ((byte[] seed, int id) in Seeds(target))
        {
            File.WriteAllBytes(Path.Combine(directory, target + "-" + id), seed);
            count++;
        }

        return count;
    }

    private static IEnumerable<(byte[] Seed, int Id)> Seeds(string target)
    {
        string file = target switch
        {
            "ed25519" => "ed25519_test.json",
            "ed448" => "ed448_test.json",
            "ecdsa-p256" => "ecdsa_secp256r1_sha256_p1363_test.json",
            "rsa2048" => "rsa_signature_2048_sha256_test.json",
            _ => throw new ArgumentOutOfRangeException(nameof(target), target, null),
        };

        using JsonDocument document = JsonDocument.Parse(File.ReadAllBytes(Path.Combine(AppContext.BaseDirectory, "Seeds", "wycheproof", file)));
        var seeds = new List<(byte[], int)>();
        foreach (JsonElement group in document.RootElement.GetProperty("testGroups").EnumerateArray())
        {
            foreach (JsonElement test in group.GetProperty("tests").EnumerateArray())
            {
                if (test.GetProperty("result").GetString() != "valid")
                {
                    continue;
                }

                byte[] message = Hex(test.GetProperty("msg"));
                byte[] signature = Hex(test.GetProperty("sig"));
                byte[]? seed = target switch
                {
                    "ed25519" or "ed448" => [.. Hex(group.GetProperty("publicKey").GetProperty("pk")), .. signature, .. message],
                    "ecdsa-p256" => [.. Hex(group.GetProperty("publicKey").GetProperty("uncompressed")), .. signature, .. Sha256(message)],
                    "rsa2048" when Hex(group.GetProperty("publicKey").GetProperty("modulus")).AsSpan().TrimStart((byte)0).SequenceEqual(ToUnsignedBytes(RsaKey.Value.N)) => [.. signature, .. message],
                    _ => null,
                };

                if (seed is not null)
                {
                    seeds.Add((seed, test.GetProperty("tcId").GetInt32()));
                }
            }
        }

        return seeds;
    }

    private static (BigInteger N, BigInteger E) LoadRsaKey()
    {
        using JsonDocument document = JsonDocument.Parse(File.ReadAllBytes(Path.Combine(AppContext.BaseDirectory, "Seeds", "wycheproof", "rsa_signature_2048_sha256_test.json")));
        JsonElement publicKey = document.RootElement.GetProperty("testGroups")[0].GetProperty("publicKey");
        return (Mpi.ToUnsignedBigInteger(Hex(publicKey.GetProperty("modulus"))), Mpi.ToUnsignedBigInteger(Hex(publicKey.GetProperty("publicExponent"))));
    }

    private static bool IsSmallOrderEd25519(byte[] publicKey) =>
        PointDecoder.TryDecode(publicKey, out EdwardsPoint a) && a.Double().Double().Double().Equals(EdwardsPoint.Identity);

    private static bool IsSmallOrderEd448(byte[] publicKey) =>
        Ed448PointDecoder.TryDecode(publicKey, out Ed448Point a) && a.Double().Double().Equals(Ed448Point.Identity);

    private static byte[] Sha256(byte[] message) => System.Security.Cryptography.SHA256.HashData(message);

    private static byte[] Hex(JsonElement element) => Convert.FromHexString(element.GetString() ?? "");

    private static BcBigInteger ToBouncyCastle(BigInteger value) => new(1, ToUnsignedBytes(value));

    private static byte[] ToUnsignedBytes(BigInteger value) => value.ToByteArray(isUnsigned: true, isBigEndian: true);

    private static void Fail(string algorithm, bool ours, bool theirs) =>
        throw new InvalidOperationException(algorithm + ": this library " + (ours ? "accepted" : "rejected") + " a signature BouncyCastle " + (theirs ? "accepted" : "rejected") + ".");
}
