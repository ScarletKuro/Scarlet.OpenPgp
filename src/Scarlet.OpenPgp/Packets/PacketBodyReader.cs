using System;
using System.Numerics;
using Scarlet.OpenPgp.Internal;

namespace Scarlet.OpenPgp.Packets
{
    /// <summary>
    /// A forward-only cursor over a packet body. Every read is bounds-checked and fails closed with
    /// a message naming what was being read, so a truncated or lying length field never reads
    /// past the body.
    /// </summary>
    internal struct PacketBodyReader(byte[] body)
    {
        private readonly byte[] _body = body;

        /// <summary>How far into the body the cursor is.</summary>
        public int Offset { get; private set; }

        public readonly bool IsAtEnd => Offset == _body.Length;

        public byte ReadByte(string what) => ReadBytes(1, what)[0];

        public byte[] ReadBytes(int length, string what)
        {
            if (length < 0 || (long)Offset + length > _body.Length)
            {
                throw new FailClosedException("Unexpected end of input while reading the " + what + ".");
            }

            byte[] result = _body.AsSpan(Offset, length).ToArray();
            Offset += length;
            return result;
        }

        /// <summary>A big-endian unsigned number of <paramref name="size"/> octets (at most 4).</summary>
        public long ReadBigEndian(int size, string what)
        {
            long value = 0;
            foreach (byte b in ReadBytes(size, what))
            {
                value = (value << 8) | b;
            }

            return value;
        }

        /// <summary>A region preceded by its <paramref name="lengthFieldSize"/>-octet big-endian length.</summary>
        public byte[] ReadLengthPrefixed(int lengthFieldSize, string what)
        {
            long length = ReadBigEndian(lengthFieldSize, what + " length");
            if (Offset + length > _body.Length)
            {
                throw new FailClosedException("Unexpected end of input while reading the " + what + " (truncated).");
            }

            return ReadBytes((int)length, what);
        }

        /// <summary>
        /// One MPI (RFC 9580 §3.2). Real integers (RSA, DSA and ECDSA values) are read with
        /// <paramref name="requireCanonical"/>, so the same value can't be re-encoded another way;
        /// see <see cref="Mpi.ReadFrom"/> for why EdDSA's MPI-wrapped byte strings must not be.
        /// </summary>
        public BigInteger ReadMpi(bool requireCanonical) => ReadMpi(requireCanonical, out _);

        /// <param name="requireCanonical">Reject a non-canonical encoding.</param>
        /// <param name="encodedLength">The MPI's length on the wire, including its 2-octet prefix.</param>
        public BigInteger ReadMpi(bool requireCanonical, out int encodedLength)
        {
            (BigInteger value, int consumed) = Mpi.ReadFrom(_body, Offset, requireCanonical);
            Offset += consumed;
            encodedLength = consumed;
            return value;
        }

        /// <summary>A curve OID: a length octet (0 and 0xFF are reserved) and that many OID content octets (RFC 9580 §5.5.5.4).</summary>
        public byte[] ReadCurveOid()
        {
            int length = ReadByte("curve OID length");
            if (length == 0 || length == 0xFF)
            {
                throw new FailClosedException("Curve OID length " + length + " is reserved.");
            }

            return ReadBytes(length, "curve OID");
        }

        /// <summary>Fails closed unless the whole body has been consumed.</summary>
        public readonly void ExpectEnd(string what)
        {
            if (!IsAtEnd)
            {
                throw new FailClosedException(what + " has unexpected trailing data.");
            }
        }
    }
}
