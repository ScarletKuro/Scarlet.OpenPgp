using System.Diagnostics.CodeAnalysis;

namespace Scarlet.OpenPgp.Cli;

[ExcludeFromCodeCoverage]
internal static class Program
{
    private static int Main(string[] args)
    {
        using Stream stdout = Console.OpenStandardOutput();
        var application = new OpenPgpCliApplication(stdout, Console.Error);
        return application.Run(args);
    }
}