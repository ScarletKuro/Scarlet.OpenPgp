using System.Text;
using Scarlet.OpenPgp.Armor;
using Scarlet.OpenPgp.Cli;

namespace Scarlet.OpenPgp.Tests.Cli
{
    public class OpenPgpCliApplicationTests : IDisposable
    {
        private readonly string _workDir;
        private readonly StringWriter _stdout = new StringWriter();
        private readonly StringWriter _stderr = new StringWriter();

        private static readonly byte[] Ed25519PublicKeyPacketBytes =
        [
            0x98, 0x33, 0x04, 0x53, 0xf3, 0x5f, 0x0b, 0x16, 0x09, 0x2b, 0x06, 0x01, 0x04, 0x01, 0xda, 0x47,
            0x0f, 0x01, 0x01, 0x07, 0x40, 0x3f, 0x09, 0x89, 0x94, 0xbd, 0xd9, 0x16, 0xed, 0x40, 0x53, 0x19,
            0x79, 0x34, 0xe4, 0xa8, 0x7c, 0x80, 0x73, 0x3a, 0x12, 0x80, 0xd6, 0x2f, 0x80, 0x10, 0x99, 0x2e,
            0x43, 0xee, 0x3b, 0x24, 0x06,
        ];

        private static readonly byte[] Ed25519SignaturePacketBytes =
        [
            0x88, 0x5e, 0x04, 0x00, 0x16, 0x08, 0x00, 0x06, 0x05, 0x02, 0x55, 0xf9, 0x5f, 0x95, 0x00, 0x0a,
            0x09, 0x10, 0x8c, 0xfd, 0xe1, 0x21, 0x97, 0x96, 0x5a, 0x9a, 0xf6, 0x22, 0x01, 0x00, 0x56, 0xf9,
            0x0c, 0xca, 0x98, 0xe2, 0x10, 0x26, 0x37, 0xbd, 0x98, 0x3f, 0xdb, 0x16, 0xc1, 0x31, 0xdf, 0xd2,
            0x7e, 0xd8, 0x2b, 0xf4, 0xdd, 0xe5, 0x60, 0x6e, 0x0d, 0x75, 0x6a, 0xed, 0x33, 0x66, 0x01, 0x00,
            0xd0, 0x9c, 0x4f, 0xa1, 0x15, 0x27, 0xf0, 0x38, 0xe0, 0xf5, 0x7f, 0x22, 0x01, 0xd8, 0x2f, 0x2e,
            0xa2, 0xc9, 0x03, 0x32, 0x65, 0xfa, 0x6c, 0xeb, 0x48, 0x9e, 0x85, 0x4b, 0xae, 0x61, 0xb4, 0x04,
        ];

        public OpenPgpCliApplicationTests()
        {
            _workDir = Path.Combine(Path.GetTempPath(), "scarlet-openpgp-cli-tests-" + Guid.NewGuid());
            Directory.CreateDirectory(_workDir);
        }

        public void Dispose()
        {
            try
            {
                Directory.Delete(_workDir, recursive: true);
            }
            catch (IOException)
            {
                // Best-effort cleanup.
            }
        }

        private static string Armor(string label, byte[] body)
        {
            int crc = Crc24.Compute(body);
            byte[] crcBytes = [(byte)(crc >> 16), (byte)(crc >> 8), (byte)crc];
            return "-----BEGIN PGP " + label + "-----\n\n"
                   + Convert.ToBase64String(body) + "\n"
                   + "=" + Convert.ToBase64String(crcBytes) + "\n"
                   + "-----END PGP " + label + "-----\n";
        }

        private string WriteFile(string name, string content)
        {
            string path = Path.Combine(_workDir, name);
            File.WriteAllText(path, content);
            return path;
        }

        private string WriteFile(string name, byte[] content)
        {
            string path = Path.Combine(_workDir, name);
            File.WriteAllBytes(path, content);
            return path;
        }

        private OpenPgpCliApplication CreateApplication() => new OpenPgpCliApplication(_stdout, _stderr);

        [Fact]
        public void Run_WithValidDetachedSignature_ShouldReturnSuccessAndKeepStdoutClean()
        {
            // Arrange
            string keyPath = WriteFile("key.asc", Armor("PUBLIC KEY BLOCK", Ed25519PublicKeyPacketBytes));
            string sigPath = WriteFile("sig.asc", Armor("SIGNATURE", Ed25519SignaturePacketBytes));
            string dataPath = WriteFile("data.txt", "OpenPGP"u8.ToArray());

            // Act
            int exitCode = CreateApplication().Run(["verify", "--key", keyPath, "--signature", sigPath, "--data", dataPath]);

            // Assert
            Assert.Equal(ExitCodes.Success, exitCode);
            Assert.Equal(string.Empty, _stdout.ToString());
            Assert.Contains("verified", _stderr.ToString());
        }

        [Fact]
        public void Run_WithTamperedData_ShouldReturnVerificationFailed()
        {
            // Arrange
            string keyPath = WriteFile("key.asc", Armor("PUBLIC KEY BLOCK", Ed25519PublicKeyPacketBytes));
            string sigPath = WriteFile("sig.asc", Armor("SIGNATURE", Ed25519SignaturePacketBytes));
            string dataPath = WriteFile("data.txt", "tampered"u8.ToArray());

            // Act
            int exitCode = CreateApplication().Run(["verify", "--key", keyPath, "--signature", sigPath, "--data", dataPath]);

            // Assert
            Assert.Equal(ExitCodes.VerificationFailed, exitCode);
        }

        [Fact]
        public void Run_WithMissingRequiredFlag_ShouldReturnUsageError()
        {
            // Act
            int exitCode = CreateApplication().Run(["verify", "--key", "somekey.asc"]);

            // Assert
            Assert.Equal(ExitCodes.UsageError, exitCode);
            Assert.Contains("Scarlet.OpenPgp:", _stderr.ToString());
        }

        [Fact]
        public void Run_WithUnknownCommand_ShouldReturnUsageError()
        {
            // Act
            int exitCode = CreateApplication().Run(["sign", "--key", "x"]);

            // Assert
            Assert.Equal(ExitCodes.UsageError, exitCode);
        }

        [Fact]
        public void Run_WithNonExistentKeyFile_ShouldReturnInputError()
        {
            // Arrange
            string sigPath = WriteFile("sig.asc", Armor("SIGNATURE", Ed25519SignaturePacketBytes));
            string dataPath = WriteFile("data.txt", "OpenPGP"u8.ToArray());
            string missingKeyPath = Path.Combine(_workDir, "does-not-exist.asc");

            // Act
            int exitCode = CreateApplication().Run(["verify", "--key", missingKeyPath, "--signature", sigPath, "--data", dataPath]);

            // Assert
            Assert.Equal(ExitCodes.InputError, exitCode);
        }

        [Fact]
        public void Run_WithAKeyPathThrowingAnUnexpectedExceptionType_ShouldReturnUnexpectedErrorNotCrash()
        {
            // Arrange: an embedded NUL character makes File.ReadAllText throw ArgumentException,
            // which is neither IOException nor UnauthorizedAccessException - this must still be
            // caught by the top-level safety net rather than escaping as a raw crash.
            string sigPath = WriteFile("sig.asc", Armor("SIGNATURE", Ed25519SignaturePacketBytes));
            string dataPath = WriteFile("data.txt", "OpenPGP"u8.ToArray());
            string invalidKeyPath = Path.Combine(_workDir, "key\0withnul.asc");

            // Act
            int exitCode = CreateApplication().Run(["verify", "--key", invalidKeyPath, "--signature", sigPath, "--data", dataPath]);

            // Assert
            Assert.Equal(ExitCodes.UnexpectedError, exitCode);
            Assert.Contains("Scarlet.OpenPgp:", _stderr.ToString());
        }

        [Fact]
        public void Run_WithHelpFlag_ShouldPrintUsageAndReturnSuccess()
        {
            // Act
            int exitCode = CreateApplication().Run(["--help"]);

            // Assert
            Assert.Equal(ExitCodes.Success, exitCode);
            Assert.Contains("Usage:", _stderr.ToString());
        }

        [Fact]
        public void Run_WithNoDataFlag_ShouldTreatSignaturePathAsAClearsignedMessage()
        {
            // Arrange: build a minimal clearsign message whose signature is the real Ed25519
            // detached signature over "OpenPGP" - it isn't a canonical-text-type signature, so
            // verification should correctly fail (not crash) via the clearsign path.
            string keyPath = WriteFile("key.asc", Armor("PUBLIC KEY BLOCK", Ed25519PublicKeyPacketBytes));
            string clearsignMessage = "-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA256\n\nOpenPGP\n"
                                       + Armor("SIGNATURE", Ed25519SignaturePacketBytes);
            string sigPath = WriteFile("message.asc", clearsignMessage);

            // Act
            int exitCode = CreateApplication().Run(["verify", "--key", keyPath, "--signature", sigPath]);

            // Assert
            Assert.Equal(ExitCodes.VerificationFailed, exitCode);
        }

        private const string BunAssets = "TestAssets/bun-release/";

        [Fact]
        public void Run_WithOutputToStdout_ShouldWriteExactlyTheSignedText()
        {
            // Act
            int exitCode = CreateApplication().Run(
            [
                "verify", "--key", BunAssets + "bun-public-key.asc", "--signature", BunAssets + "SHASUMS256.txt.asc", "--output", "-",
            ]);

            // Assert
            Assert.Equal(ExitCodes.Success, exitCode);
            string expected = File.ReadAllText(BunAssets + "SHASUMS256.txt").Replace("\r\n", "\n");
            Assert.Equal(expected, _stdout.ToString().Replace("\r\n", "\n"));
        }

        [Fact]
        public void Run_WithOutputToAFile_ShouldWriteTheSignedTextOnlyOnSuccess()
        {
            // Arrange
            string outputPath = Path.Combine(_workDir, "signed.txt");
            string tamperedPath = WriteFile("tampered.asc", "unsigned line\n" + File.ReadAllText(BunAssets + "SHASUMS256.txt.asc"));
            string tamperedOutputPath = Path.Combine(_workDir, "tampered-signed.txt");

            // Act
            int exitCode = CreateApplication().Run(
            [
                "verify", "--key", BunAssets + "bun-public-key.asc", "--signature", BunAssets + "SHASUMS256.txt.asc", "--output", outputPath,
            ]);
            int tamperedExitCode = CreateApplication().Run(
            [
                "verify", "--key", BunAssets + "bun-public-key.asc", "--signature", tamperedPath, "--output", tamperedOutputPath,
            ]);

            // Assert
            Assert.Equal(ExitCodes.Success, exitCode);
            Assert.Equal(
                File.ReadAllText(BunAssets + "SHASUMS256.txt").Replace("\r\n", "\n"),
                File.ReadAllText(outputPath).Replace("\r\n", "\n"));
            Assert.Equal(ExitCodes.InputError, tamperedExitCode); // unsigned text around the block makes the message malformed
            Assert.False(File.Exists(tamperedOutputPath));
        }

        [Fact]
        public void Run_WithOutputAndData_ShouldReturnUsageError()
        {
            // Act
            int exitCode = CreateApplication().Run(["verify", "--key", "k", "--signature", "s", "--data", "d", "--output", "-"]);

            // Assert
            Assert.Equal(ExitCodes.UsageError, exitCode);
        }

        [Fact]
        public void Run_WithSignatureFileThatIsNotValidUtf8_ShouldReturnInputError()
        {
            // Arrange: invalid UTF-8 would otherwise be decoded to U+FFFD and could match signed
            // text that really contains U+FFFD.
            string keyPath = WriteFile("key.asc", Armor("PUBLIC KEY BLOCK", Ed25519PublicKeyPacketBytes));
            string sigPath = WriteFile("message.asc", [0x2D, 0x2D, 0xFF, 0xFE, 0x80, 0x0A]);

            // Act
            int exitCode = CreateApplication().Run(["verify", "--key", keyPath, "--signature", sigPath]);

            // Assert
            Assert.Equal(ExitCodes.InputError, exitCode);
        }
    }
}
