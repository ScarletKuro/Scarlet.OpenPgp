using System.Numerics;

namespace Scarlet.OpenPgp.Crypto.Ed25519
{
    /// <summary>
    /// An element of the finite field GF(p) where p = 2^255 - 19, backed by <see cref="BigInteger"/>.
    /// Correctness over speed, per SPEC.md's explicit non-goal of optimized/constant-time arithmetic -
    /// there is no secret key material anywhere in this verify-only library, so the usual
    /// side-channel concerns that motivate fixed-width/constant-time field arithmetic don't apply.
    /// </summary>
    internal readonly struct FieldElement : System.IEquatable<FieldElement>
    {
        public static readonly BigInteger P = BigInteger.Pow(2, 255) - 19;

        public static readonly FieldElement Zero = new FieldElement(BigInteger.Zero);
        public static readonly FieldElement One = new FieldElement(BigInteger.One);

        public FieldElement(BigInteger value)
        {
            Value = Mod(value);
        }

        public BigInteger Value { get; }

        public static FieldElement operator +(FieldElement a, FieldElement b) => new FieldElement(a.Value + b.Value);

        public static FieldElement operator -(FieldElement a, FieldElement b) => new FieldElement(a.Value - b.Value);

        public static FieldElement operator -(FieldElement a) => new FieldElement(-a.Value);

        public static FieldElement operator *(FieldElement a, FieldElement b) => new FieldElement(a.Value * b.Value);

        public static bool operator ==(FieldElement a, FieldElement b) => a.Value == b.Value;

        public static bool operator !=(FieldElement a, FieldElement b) => a.Value != b.Value;

        public bool IsZero => Value.IsZero;

        public bool IsOdd => !Value.IsEven;

        public FieldElement Pow(BigInteger exponent) => new FieldElement(BigInteger.ModPow(Value, exponent, P));

        /// <summary>Multiplicative inverse mod p, via Fermat's little theorem (p is prime): a^(p-2) = a^-1 mod p.</summary>
        public FieldElement Invert() => Pow(P - 2);

        public bool Equals(FieldElement other) => this == other;

        public override bool Equals(object? obj) => obj is FieldElement other && Equals(other);

        public override int GetHashCode() => Value.GetHashCode();

        public override string ToString() => Value.ToString(System.Globalization.CultureInfo.InvariantCulture);

        private static BigInteger Mod(BigInteger value)
        {
            BigInteger result = value % P;
            return result.Sign < 0 ? result + P : result;
        }
    }
}
