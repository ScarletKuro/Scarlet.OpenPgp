using System.Collections.Generic;

namespace Scarlet.OpenPgp.Armor
{
    /// <summary>
    /// A single decoded ASCII armor block (RFC 9580 §6.2): the label from the BEGIN/END lines, the
    /// armor headers (e.g. "Version", "Hash"), and the base64-decoded body bytes.
    /// </summary>
    internal sealed class AsciiArmorBlock(string label, IReadOnlyList<KeyValuePair<string, string>> headers, byte[] body)
    {
        /// <summary>The text between "BEGIN PGP " and "-----", e.g. "SIGNATURE" or "PUBLIC KEY BLOCK".</summary>
        public string Label { get; } = label;

        /// <summary>
        /// Armor headers in source order. A list rather than a dictionary because clearsign blocks
        /// can legally repeat the "Hash" header (one per hash algorithm the signer offers).
        /// </summary>
        public IReadOnlyList<KeyValuePair<string, string>> Headers { get; } = headers;

        public byte[] Body { get; } = body;
    }
}
