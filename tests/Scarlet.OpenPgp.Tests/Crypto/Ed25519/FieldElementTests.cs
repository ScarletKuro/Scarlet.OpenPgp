using System.Numerics;
using Scarlet.OpenPgp.Crypto.Ed25519;

namespace Scarlet.OpenPgp.Tests.Crypto.Ed25519
{
    public class FieldElementTests
    {
        [Fact]
        public void Constructor_WithNegativeValue_ShouldNormalizeIntoRange()
        {
            // Arrange
            var element = new FieldElement(-5);

            // Act & Assert
            Assert.True(element.Value >= BigInteger.Zero && element.Value < FieldElement.P);
            Assert.Equal(FieldElement.P - 5, element.Value);
        }

        [Fact]
        public void Addition_OfAValueAndItsNegation_ShouldBeZero()
        {
            // Arrange
            var a = new FieldElement(12345);

            // Act
            FieldElement result = a + (-a);

            // Assert
            Assert.True(result.IsZero);
        }

        [Fact]
        public void Invert_MultipliedByOriginal_ShouldBeOne()
        {
            // Arrange
            var a = new FieldElement(98765);

            // Act
            FieldElement result = a * a.Invert();

            // Assert
            Assert.Equal(FieldElement.One, result);
        }

        [Fact]
        public void Multiplication_IsDistributiveOverAddition()
        {
            // Arrange
            var a = new FieldElement(7);
            var b = new FieldElement(11);
            var c = new FieldElement(13);

            // Act
            FieldElement left = a * (b + c);
            FieldElement right = (a * b) + (a * c);

            // Assert
            Assert.Equal(left, right);
        }

        [Fact]
        public void Pow_WithExponentP_MinusOne_ShouldBeOneForNonZeroElement_FermatsLittleTheorem()
        {
            // Arrange
            var a = new FieldElement(42);

            // Act
            FieldElement result = a.Pow(FieldElement.P - 1);

            // Assert
            Assert.Equal(FieldElement.One, result);
        }

        [Fact]
        public void Arithmetic_OnEdgeAndRandomValues_ShouldMatchBigIntegerModP()
        {
            // Arrange: the limb arithmetic against plain BigInteger arithmetic mod p, on the values
            // where carries and the final reduction are most likely to go wrong (0, 1, p - 1, values
            // with every limb at its maximum, 2^255 - 1 >= p) plus seeded random ones.
            BigInteger p = FieldElement.P;
            var values = new List<BigInteger>
            {
                0, 1, 2, 19, 38, p - 1, p - 2, p - 19, p + 1, (BigInteger.One << 255) - 1,
                (BigInteger.One << 254) - 1, BigInteger.One << 254, (BigInteger.One << 16) - 1, BigInteger.One << 16,
            };
            var random = new Random(25519);
            var bytes = new byte[33];
            for (int i = 0; i < 200; i++)
            {
                random.NextBytes(bytes);
                bytes[32] = 0;
                values.Add(new BigInteger(bytes));
            }

            // Act & Assert
            for (int i = 0; i < values.Count; i++)
            {
                BigInteger x = values[i];
                BigInteger y = values[(i * 7 + 3) % values.Count];
                var a = new FieldElement(x);
                var b = new FieldElement(y);
                Assert.Equal(Mod(x), a.Value);
                Assert.Equal(Mod(x + y), (a + b).Value);
                Assert.Equal(Mod(x - y), (a - b).Value);
                Assert.Equal(Mod(-x), (-a).Value);
                Assert.Equal(Mod(x * y), (a * b).Value);
                Assert.Equal(Mod(x * x), a.Square().Value);
                Assert.Equal(Mod(x).IsZero, a.IsZero);
                Assert.Equal(!Mod(x).IsEven, a.IsOdd);
                Assert.Equal(Mod(x) == Mod(y), a == b);
                if (!Mod(x).IsZero)
                {
                    Assert.Equal(BigInteger.One, (a * a.Invert()).Value);
                }

                // Long chains without a reduction in between: sums and differences of products.
                FieldElement chained = (a * b) - (b * b) + (a * a) - (a + b) - (a + b);
                Assert.Equal(Mod((x * y) - (y * y) + (x * x) - (2 * (x + y))), chained.Value);
            }

            static BigInteger Mod(BigInteger value)
            {
                BigInteger r = value % FieldElement.P;
                return r.Sign < 0 ? r + FieldElement.P : r;
            }
        }
    }
}
