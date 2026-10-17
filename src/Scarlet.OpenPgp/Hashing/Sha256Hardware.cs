using System;
using System.Buffers.Binary;
#if NET
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.Arm;
#endif

namespace Scarlet.OpenPgp.Hashing
{
    /// <summary>
    /// The SHA-256 compression function on the ARMv8 SHA-256 instructions (SHA256H, SHA256H2,
    /// SHA256SU0, SHA256SU1), for <see cref="Sha224"/>. .NET exposes these on ARM64 only - there is
    /// no x86 SHA-NI equivalent - and not at all on netstandard2.0, where <see cref="IsSupported"/>
    /// is always false and the portable implementation is used.
    /// </summary>
    internal static class Sha256Hardware
    {
#if NET
        /// <summary>Round constants grouped four to a vector, one vector per four rounds.</summary>
        private static readonly Vector128<uint>[] RoundConstants = CreateRoundConstants();

        public static bool IsSupported => Sha256.IsSupported;

        /// <summary>Compresses <paramref name="blocks"/> 64-byte blocks of <paramref name="data"/> into <paramref name="state"/> (eight words, a..h).</summary>
        public static void Compress(uint[] state, byte[] data, int offset, int blocks)
        {
            Vector128<uint> abcd = Vector128.Create(state[0], state[1], state[2], state[3]);
            Vector128<uint> efgh = Vector128.Create(state[4], state[5], state[6], state[7]);
            Span<Vector128<uint>> message = stackalloc Vector128<uint>[4];

            for (int block = 0; block < blocks; block++)
            {
                ReadOnlySpan<byte> input = data.AsSpan(offset + (block * 64), 64);
                for (int i = 0; i < 4; i++)
                {
                    message[i] = Vector128.Create(
                        BinaryPrimitives.ReadUInt32BigEndian(input.Slice(16 * i)),
                        BinaryPrimitives.ReadUInt32BigEndian(input.Slice((16 * i) + 4)),
                        BinaryPrimitives.ReadUInt32BigEndian(input.Slice((16 * i) + 8)),
                        BinaryPrimitives.ReadUInt32BigEndian(input.Slice((16 * i) + 12)));
                }

                Vector128<uint> abcdSaved = abcd;
                Vector128<uint> efghSaved = efgh;

                // Sixteen groups of four rounds. message[g % 4] holds W[4g..4g+3]; once used, it is
                // replaced by W[4g+16..4g+19] = SU1(SU0(W[4g..], W[4g+4..]), W[4g+8..], W[4g+12..])
                // (FIPS 180-4 §6.2.2 step 1), needed by the groups four further on.
                for (int group = 0; group < 16; group++)
                {
                    Vector128<uint> wk = message[group & 3] + RoundConstants[group];
                    if (group < 12)
                    {
                        message[group & 3] = Sha256.ScheduleUpdate1(
                            Sha256.ScheduleUpdate0(message[group & 3], message[(group + 1) & 3]),
                            message[(group + 2) & 3],
                            message[(group + 3) & 3]);
                    }

                    Vector128<uint> abcdBefore = abcd;
                    abcd = Sha256.HashUpdate1(abcd, efgh, wk);
                    efgh = Sha256.HashUpdate2(efgh, abcdBefore, wk);
                }

                abcd += abcdSaved;
                efgh += efghSaved;
            }

            for (int i = 0; i < 4; i++)
            {
                state[i] = abcd.GetElement(i);
                state[i + 4] = efgh.GetElement(i);
            }
        }

        private static Vector128<uint>[] CreateRoundConstants()
        {
            uint[] k = Sha224.K;
            var constants = new Vector128<uint>[16];
            for (int group = 0; group < 16; group++)
            {
                constants[group] = Vector128.Create(k[4 * group], k[(4 * group) + 1], k[(4 * group) + 2], k[(4 * group) + 3]);
            }

            return constants;
        }
#else
        public static bool IsSupported => false;

        public static void Compress(uint[] state, byte[] data, int offset, int blocks) =>
            throw new PlatformNotSupportedException();
#endif
    }
}
