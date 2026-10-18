using System;
using System.Collections.Generic;

namespace Scarlet.OpenPgp.Internal
{
    /// <summary>Compares byte arrays by content, for sets and dictionaries keyed by packet bytes or digests.</summary>
    internal sealed class ByteArrayComparer : IEqualityComparer<byte[]>
    {
        public static readonly ByteArrayComparer Instance = new();

        private ByteArrayComparer()
        {
        }

        public bool Equals(byte[]? x, byte[]? y) =>
            ReferenceEquals(x, y) || (x is not null && y is not null && x.AsSpan().SequenceEqual(y));

        /// <summary>FNV-1a over the content. Not collision-resistant, which is fine: equality is still decided by <see cref="Equals(byte[], byte[])"/>.</summary>
        public int GetHashCode(byte[] obj)
        {
            unchecked
            {
                uint hash = 2166136261;
                foreach (byte b in obj)
                {
                    hash = (hash ^ b) * 16777619;
                }

                return (int)hash;
            }
        }
    }
}
