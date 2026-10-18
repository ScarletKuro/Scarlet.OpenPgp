using System.Numerics;
using BenchmarkDotNet.Attributes;
using Scarlet.OpenPgp.Crypto.Ed25519;

namespace Scarlet.OpenPgp.Benchmarks
{
    /// <summary>Ed25519 field and point primitives, to see where a verification's time goes.</summary>
    public class Ed25519FieldBenchmarks
    {
        private readonly FieldElement _a = new FieldElement(BigInteger.Parse("12345678901234567890123456789012345678901234567890123456789", System.Globalization.CultureInfo.InvariantCulture));
        private readonly FieldElement _b = new FieldElement(BigInteger.Parse("98765432109876543210987654321098765432109876543210987654321", System.Globalization.CultureInfo.InvariantCulture));
        private readonly EdwardsPoint _p = EdwardsPoint.B.Double();
        private readonly EdwardsPoint _other = EdwardsPoint.B.Double().Double().Add(EdwardsPoint.B);
        // Sinks: each benchmark stores its result here so the JIT can't drop the work as unused.
        // (Returning it isn't possible - the types are internal, and benchmark methods are public.)
        // ReSharper disable NotAccessedField.Local
        private FieldElement _r;
        private EdwardsPoint _q;
        // ReSharper restore NotAccessedField.Local

        [Benchmark]
        public void Multiply() => _r = _a * _b;

        [Benchmark]
        public void Square() => _r = _a.Square();

        [Benchmark]
        public void Add() => _r = _a + _b;

        [Benchmark]
        public bool AreEqual() => _a == _b;

        [Benchmark]
        public void PointAdd() => _q = _p.Add(_other);

        [Benchmark]
        public void PointDouble() => _q = _p.Double();
    }
}
