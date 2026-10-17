using System.Numerics;

namespace Scarlet.OpenPgp.Crypto
{
    /// <summary>The algorithm-specific value of a signature (RFC 9580 §5.2.3.2-5), as parsed from a signature packet.</summary>
    internal abstract class SignatureValue
    {
    }

    /// <summary>An RSA signature: the integer s = m^d mod n.</summary>
    internal sealed class RsaSignatureValue(BigInteger value) : SignatureValue
    {
        public BigInteger Value { get; } = value;
    }

    /// <summary>A DSA or ECDSA signature: the integer pair (r, s).</summary>
    internal sealed class RsSignatureValue(BigInteger r, BigInteger s) : SignatureValue
    {
        public BigInteger R { get; } = r;

        public BigInteger S { get; } = s;
    }

    /// <summary>An EdDSA signature in its native encoding, R || S: 64 octets for Ed25519, 114 for Ed448.</summary>
    internal sealed class EdDsaSignatureValue(byte[] value) : SignatureValue
    {
        public byte[] Value { get; } = value;
    }
}
