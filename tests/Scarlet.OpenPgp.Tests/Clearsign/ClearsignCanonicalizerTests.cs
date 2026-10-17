using System.Text;
using Scarlet.OpenPgp.Clearsign;

namespace Scarlet.OpenPgp.Tests.Clearsign
{
    public class ClearsignCanonicalizerTests
    {
        [Fact]
        public void Canonicalize_WithDashEscapedLine_ShouldUnescapeIt()
        {
            // Arrange: the original line was "-foo"; on the wire it becomes "- -foo".
            string[] lines = { "- -foo" };

            // Act
            byte[] result = ClearsignCanonicalizer.Canonicalize(lines);

            // Assert
            Assert.Equal("-foo", Encoding.UTF8.GetString(result));
        }

        [Fact]
        public void Canonicalize_WithTrailingSpacesAndTabs_ShouldStripThem()
        {
            // Arrange
            string[] lines = { "hello   ", "world\t\t" };

            // Act
            byte[] result = ClearsignCanonicalizer.Canonicalize(lines);

            // Assert
            Assert.Equal("hello\r\nworld", Encoding.UTF8.GetString(result));
        }

        [Fact]
        public void Canonicalize_WithMultipleLines_ShouldJoinWithCrlfWithoutATrailingCrlf()
        {
            // Arrange: confirmed empirically against a real production signature (Bun's
            // SHASUMS256.txt.asc, whose own source file has no trailing newline) - the hash only
            // matches when no CRLF is appended after the final line.
            string[] lines = { "line one", "line two" };

            // Act
            byte[] result = ClearsignCanonicalizer.Canonicalize(lines);

            // Assert
            Assert.Equal("line one\r\nline two", Encoding.UTF8.GetString(result));
        }

        [Fact]
        public void Canonicalize_WithLineNotStartingWithDash_ShouldLeaveItUnchangedBesidesWhitespace()
        {
            // Arrange
            string[] lines = { "no dash here " };

            // Act
            byte[] result = ClearsignCanonicalizer.Canonicalize(lines);

            // Assert
            Assert.Equal("no dash here", Encoding.UTF8.GetString(result));
        }

        [Fact]
        public void Canonicalize_UnescapesBeforeStrippingWhitespace_ForALineThatWasJustADash()
        {
            // Arrange: original line was "-" (with a trailing space), escaped wire form is "- - ".
            string[] lines = { "- - " };

            // Act
            byte[] result = ClearsignCanonicalizer.Canonicalize(lines);

            // Assert: unescape "- - " -> "- " (dash, space), then strip trailing whitespace -> "-".
            Assert.Equal("-", Encoding.UTF8.GetString(result));
        }

        [Fact]
        public void Canonicalize_WithEmptyLines_ShouldPreserveThemAsEmpty()
        {
            // Arrange
            string[] lines = { "first", "", "third" };

            // Act
            byte[] result = ClearsignCanonicalizer.Canonicalize(lines);

            // Assert
            Assert.Equal("first\r\n\r\nthird", Encoding.UTF8.GetString(result));
        }

        [Fact]
        public void Canonicalize_WithSingleLine_ShouldNotAddAnyCrlf()
        {
            // Arrange
            string[] lines = { "only line" };

            // Act
            byte[] result = ClearsignCanonicalizer.Canonicalize(lines);

            // Assert
            Assert.Equal("only line", Encoding.UTF8.GetString(result));
        }

        [Fact]
        public void Canonicalize_WithAnUnpairedSurrogate_ShouldFailClosed()
        {
            // Arrange: lenient UTF-8 encoding would map this to U+FFFD's bytes, letting a different
            // string produce the same signed bytes as text that really contains U+FFFD.
            string[] lines = { "bad \uD800 surrogate" };

            // Act & Assert
            Assert.Throws<Scarlet.OpenPgp.Internal.FailClosedException>(() => ClearsignCanonicalizer.Canonicalize(lines));
        }
    }
}
