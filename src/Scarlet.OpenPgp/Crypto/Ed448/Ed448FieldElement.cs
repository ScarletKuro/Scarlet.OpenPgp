using System.Numerics;

namespace Scarlet.OpenPgp.Crypto.Ed448
{
    /// <summary>
    /// An element of the finite field GF(p) where p = 2^448 - 2^224 - 1 (RFC 8032 §5.2), backed by
    /// <see cref="BigInteger"/>. Same correctness-over-speed rationale as the Ed25519 field element:
    /// this verify-only library has no secret key material, so constant-time arithmetic buys nothing.
    /// </summary>
    internal readonly struct Ed448FieldElement : System.IEquatable<Ed448FieldElement>
    {
        public static readonly BigInteger P = BigInteger.Pow(2, 448) - BigInteger.Pow(2, 224) - 1;

        public static readonly Ed448FieldElement Zero = new Ed448FieldElement(BigInteger.Zero);
        public static readonly Ed448FieldElement One = new Ed448FieldElement(BigInteger.One);

        public Ed448FieldElement(BigInteger value)
        {
            Value = Mod(value);
        }

        public BigInteger Value { get; }

        public static Ed448FieldElement operator +(Ed448FieldElement a, Ed448FieldElement b) => new Ed448FieldElement(a.Value + b.Value);

        public static Ed448FieldElement operator -(Ed448FieldElement a, Ed448FieldElement b) => new Ed448FieldElement(a.Value - b.Value);

        public static Ed448FieldElement operator -(Ed448FieldElement a) => new Ed448FieldElement(-a.Value);

        public static Ed448FieldElement operator *(Ed448FieldElement a, Ed448FieldElement b) => new Ed448FieldElement(a.Value * b.Value);

        public static bool operator ==(Ed448FieldElement a, Ed448FieldElement b) => a.Value == b.Value;

        public static bool operator !=(Ed448FieldElement a, Ed448FieldElement b) => a.Value != b.Value;

        public bool IsZero => Value.IsZero;

        public bool IsOdd => !Value.IsEven;

        public Ed448FieldElement Square() => this * this;

        public Ed448FieldElement Pow(BigInteger exponent) => new Ed448FieldElement(BigInteger.ModPow(Value, exponent, P));

        /// <summary>Multiplicative inverse mod p via Fermat's little theorem, as RFC 8032 §5.2.1 recommends: x^-1 = x^(p-2) mod p.</summary>
        public Ed448FieldElement Invert() => Pow(P - 2);

        public bool Equals(Ed448FieldElement other) => this == other;

        public override bool Equals(object? obj) => obj is Ed448FieldElement other && Equals(other);

        public override int GetHashCode() => Value.GetHashCode();

        public override string ToString() => Value.ToString(System.Globalization.CultureInfo.InvariantCulture);

        private static BigInteger Mod(BigInteger value)
        {
            BigInteger result = value % P;
            return result.Sign < 0 ? result + P : result;
        }
    }
}
