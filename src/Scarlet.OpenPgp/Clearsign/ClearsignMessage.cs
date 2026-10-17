using System.Collections.Generic;
using Scarlet.OpenPgp.Armor;
using Scarlet.OpenPgp.Hashing;

namespace Scarlet.OpenPgp.Clearsign
{
    /// <summary>The three logical parts of a parsed clearsigned message (RFC 4880 §7).</summary>
    internal sealed class ClearsignMessage
    {
        public ClearsignMessage(string[] dashEscapedBodyLines, IReadOnlyList<HashAlgorithmId> hashHeaderAlgorithms, AsciiArmorBlock signatureArmor)
        {
            DashEscapedBodyLines = dashEscapedBodyLines;
            HashHeaderAlgorithms = hashHeaderAlgorithms;
            SignatureArmor = signatureArmor;
        }

        /// <summary>The signed text's lines, exactly as they appear on the wire (still dash-escaped, trailing whitespace not yet stripped). Feed to <see cref="ClearsignCanonicalizer"/> before hashing.</summary>
        public string[] DashEscapedBodyLines { get; }

        /// <summary>The algorithms named by the message's "Hash" armor headers, in order. Empty when the message has none.</summary>
        public IReadOnlyList<HashAlgorithmId> HashHeaderAlgorithms { get; }

        /// <summary>The decoded, CRC24-verified "-----BEGIN PGP SIGNATURE-----" armor block.</summary>
        public AsciiArmorBlock SignatureArmor { get; }
    }
}
