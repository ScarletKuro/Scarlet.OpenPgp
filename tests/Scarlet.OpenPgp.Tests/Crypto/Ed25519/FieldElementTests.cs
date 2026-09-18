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
    }
}
