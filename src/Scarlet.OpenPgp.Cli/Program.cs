using System.Diagnostics.CodeAnalysis;

namespace Scarlet.OpenPgp.Cli
{
    [ExcludeFromCodeCoverage]
    internal static class Program
    {
        private static int Main(string[] args)
        {
            var application = new OpenPgpCliApplication(System.Console.Out, System.Console.Error);
            return application.Run(args);
        }
    }
}
