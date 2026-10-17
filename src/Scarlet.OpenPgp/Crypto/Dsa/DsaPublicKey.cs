using System.Numerics;
using Scarlet.OpenPgp.Hashing;
using Scarlet.OpenPgp.Internal;

namespace Scarlet.OpenPgp.Crypto.Dsa
{
    /// <summary>
    /// A DSA public key - domain parameters (p, q, g) plus the public value y - as parsed from an
    /// OpenPGP algorithm-17 key packet (RFC 9580 §5.5.5.2).
    /// </summary>
    /// <remarks>
    /// <para>
    /// The constructor rejects anything outside the FIPS 186-4 §4.2 parameter sizes this library
    /// is willing to trust: L ≥ 2048 and N ∈ {224, 256}. In particular the classic DSA-1024/160
    /// keys (L = 1024, N = 160, "DSA-1024 with SHA-1") are refused outright. Their 1024-bit
    /// discrete-log group is within reach of well-resourced attackers, NIST disallowed them for
    /// signature generation after 2013 (SP 800-131A), and a 160-bit q caps the scheme at roughly
    /// 80-bit security no matter how strong the hash. RFC 9580 §9.1 also deprecates DSA entirely.
    /// </para>
    /// <para>
    /// The remaining checks are the cheap structural ones from FIPS 186-4 Appendix A.1.1/A.2.2
    /// and SP 800-89 §5.3.1 (partial public-key validation): q | p - 1, and both g and y lie in
    /// (1, p) and in the order-q subgroup (x^q ≡ 1 mod p). Rejecting y outside that subgroup or
    /// y = 1 matters: with y = 1, v = g^u1 mod p mod q and anyone can forge. p and q are not
    /// primality-tested: that would be expensive, and parameters are chosen by the key owner, who
    /// can only weaken their own signatures - the subgroup checks are what rule out degenerate
    /// values that would let a third party forge.
    /// </para>
    /// </remarks>
    internal sealed class DsaPublicKey : VerificationKey
    {
        /// <summary>The smallest prime modulus accepted (L in FIPS 186-4 §4.2).</summary>
        public const int MinimumPBitLength = 2048;

        /// <summary>The largest prime modulus accepted. FIPS 186-4 tops out at 3072 bits; this leaves headroom while keeping a verification's modular exponentiations bounded.</summary>
        public const int MaximumPBitLength = 16384;

        public DsaPublicKey(BigInteger p, BigInteger q, BigInteger g, BigInteger y)
        {
            P = p;
            Q = q;
            G = g;
            Y = y;

            PBitLength = BigIntegerMath.BitLength(p);
            // Sizes outside the policy are "unsupported" (e.g. legacy DSA-1024 keys); impossible
            // values are malformed. A key ring skips the former and rejects the latter.
            if (p.IsEven)
            {
                throw new FailClosedException("DSA prime p must be odd.");
            }

            if (PBitLength < MinimumPBitLength || PBitLength > MaximumPBitLength)
            {
                throw FailClosedException.Unsupported("DSA prime p must be between " + MinimumPBitLength + " and " + MaximumPBitLength + " bits.");
            }

            QBitLength = BigIntegerMath.BitLength(q);
            if (QBitLength != 224 && QBitLength != 256)
            {
                throw FailClosedException.Unsupported("DSA subgroup order q must be 224 or 256 bits (FIPS 186-4 §4.2); got " + QBitLength + " bits.");
            }

            if (!BigInteger.Remainder(p - 1, q).IsZero)
            {
                throw new FailClosedException("DSA subgroup order q does not divide p - 1.");
            }

            if (g <= 1 || g >= p || !BigInteger.ModPow(g, q, p).IsOne)
            {
                throw new FailClosedException("DSA generator g must satisfy 1 < g < p and g^q mod p = 1.");
            }

            if (y <= 1 || y >= p || !BigInteger.ModPow(y, q, p).IsOne)
            {
                throw new FailClosedException("DSA public value y must satisfy 1 < y < p and y^q mod p = 1.");
            }
        }

        /// <summary>The prime modulus p.</summary>
        public BigInteger P { get; }

        /// <summary>The subgroup order q, a divisor of p - 1.</summary>
        public BigInteger Q { get; }

        /// <summary>The subgroup generator g, of order q.</summary>
        public BigInteger G { get; }

        /// <summary>The public value y = g^x mod p.</summary>
        public BigInteger Y { get; }

        /// <summary>L = bitlen(p).</summary>
        public int PBitLength { get; }

        /// <summary>N = bitlen(q): 224 or 256.</summary>
        public int QBitLength { get; }

        public override string Description => "DSA " + PBitLength.ToString(System.Globalization.CultureInfo.InvariantCulture);

        /// <summary>RFC 9580 §5.2.3.2: a digest at least as long as q.</summary>
        public override int MinimumHashBits => QBitLength;

        public override bool Verify(HashAlgorithmId hashAlgorithm, byte[] digest, SignatureValue signature) =>
            signature is RsSignatureValue rs && DsaVerifier.Verify(this, digest, rs.R, rs.S);
    }
}
