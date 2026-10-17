using BenchmarkDotNet.Running;

namespace Scarlet.OpenPgp.Benchmarks
{
    internal static class Program
    {
        // dotnet run -c Release -- --filter '*'            every benchmark
        // dotnet run -c Release -- --filter '*Verify*'     one class
        private static void Main(string[] args) => BenchmarkSwitcher.FromAssembly(typeof(Program).Assembly).Run(args);
    }

    internal static class Assets
    {
        /// <summary>When the test fixtures were assembled; every fixture signature is valid at this time.</summary>
        public static readonly DateTimeOffset AssembledOn = new DateTimeOffset(2026, 10, 17, 0, 0, 0, TimeSpan.Zero);

        public static byte[] Bytes(string path) => File.ReadAllBytes(Path.Combine(AppContext.BaseDirectory, "TestAssets", path));

        public static string Text(string path) => File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "TestAssets", path));
    }
}
