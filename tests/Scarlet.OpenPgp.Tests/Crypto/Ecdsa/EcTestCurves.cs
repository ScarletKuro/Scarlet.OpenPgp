using System.Numerics;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto.Parameters;
using Scarlet.OpenPgp.Crypto.Ecdsa;
using Scarlet.OpenPgp.Packets;
using BcBigInteger = Org.BouncyCastle.Math.BigInteger;

namespace Scarlet.OpenPgp.Tests.Crypto.Ecdsa
{
    /// <summary>Shared helpers mapping this library's curves to BouncyCastle's reference definitions (test-only).</summary>
    internal static class EcTestCurves
    {
        public static EcCurve Get(string bouncyCastleName)
        {
            switch (bouncyCastleName)
            {
                case "P-256":
                    return EcCurve.NistP256;
                case "P-384":
                    return EcCurve.NistP384;
                case "P-521":
                    return EcCurve.NistP521;
                case "brainpoolP256r1":
                    return EcCurve.BrainpoolP256r1;
                case "brainpoolP384r1":
                    return EcCurve.BrainpoolP384r1;
                case "brainpoolP512r1":
                    return EcCurve.BrainpoolP512r1;
                default:
                    throw new System.ArgumentOutOfRangeException(nameof(bouncyCastleName), bouncyCastleName, null);
            }
        }

        public static X9ECParameters GetReference(string bouncyCastleName) => ECNamedCurveTable.GetByName(bouncyCastleName);

        public static ECDomainParameters GetReferenceDomain(string bouncyCastleName)
        {
            X9ECParameters x9 = GetReference(bouncyCastleName);
            return new ECDomainParameters(x9.Curve, x9.G, x9.N, x9.H, x9.GetSeed());
        }

        public static BigInteger ToNumerics(BcBigInteger value) => Mpi.ToUnsignedBigInteger(value.ToByteArrayUnsigned());

        public static BcBigInteger ToBouncyCastle(BigInteger value) => new BcBigInteger(1, value.ToByteArray(isUnsigned: true, isBigEndian: true));
    }
}
