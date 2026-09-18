using System.Text;

namespace Scarlet.OpenPgp.Clearsign
{
    /// <summary>
    /// Canonicalizes clearsigned message text before hashing (RFC 4880 §7.1, §5.2.1): each line is
    /// dash-unescaped (a leading "- " marks a line that originally started with "-", added purely to
    /// keep it from being mistaken for the signature armor boundary), then has its trailing
    /// whitespace stripped, then the lines are rejoined with CRLF *between* them only - no trailing
    /// CRLF after the final line. The wire format always shows a line break before
    /// "-----BEGIN PGP SIGNATURE-----" (the armor boundary must start its own line), but that break
    /// is a framing artifact, not signed content: confirmed empirically against a real production
    /// signature (Bun's SHASUMS256.txt.asc) whose own source file has no trailing newline, and whose
    /// hash only matches when no CRLF is added after the last line.
    /// </summary>
    internal static class ClearsignCanonicalizer
    {
        public static byte[] Canonicalize(string[] dashEscapedLines)
        {
            var builder = new StringBuilder();
            for (int i = 0; i < dashEscapedLines.Length; i++)
            {
                if (i > 0)
                {
                    builder.Append("\r\n");
                }

                string line = dashEscapedLines[i];
                string unescaped = line.StartsWith("- ") ? line.Substring(2) : line;
                string trimmed = unescaped.TrimEnd(' ', '\t');
                builder.Append(trimmed);
            }

            return Encoding.UTF8.GetBytes(builder.ToString());
        }
    }
}
