using Scarlet.OpenPgp.Armor;

namespace Scarlet.OpenPgp.Clearsign
{
    /// <summary>The three logical parts of a parsed clearsigned message (RFC 4880 §7).</summary>
    internal sealed class ClearsignMessage
    {
        public ClearsignMessage(string[] dashEscapedBodyLines, AsciiArmorBlock signatureArmor)
        {
            DashEscapedBodyLines = dashEscapedBodyLines;
            SignatureArmor = signatureArmor;
        }

        /// <summary>The signed text's lines, exactly as they appear on the wire (still dash-escaped, trailing whitespace not yet stripped). Feed to <see cref="ClearsignCanonicalizer"/> before hashing.</summary>
        public string[] DashEscapedBodyLines { get; }

        /// <summary>The decoded, CRC24-verified "-----BEGIN PGP SIGNATURE-----" armor block.</summary>
        public AsciiArmorBlock SignatureArmor { get; }
    }
}
