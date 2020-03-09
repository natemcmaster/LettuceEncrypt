#nullable enable
using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using McMaster.AspNetCore.LetsEncrypt;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace LetsEncrypt.UnitTests
{
    using static TestUtils;

    public class FileSystemCertificateRepoTests
    {
        [Theory]
        [InlineData(null)]
        [InlineData("")]
        public async Task ItCanSaveCertsWithoutPassword(string? password)
        {
            var dir = new DirectoryInfo(Path.Combine(AppContext.BaseDirectory, Path.GetRandomFileName()));
            var repo = new FileSystemCertificateRepository(dir, password);
            var cert = CreateTestCert("localhost");
            var expectedFile = Path.Combine(dir.FullName, "certs", cert.Thumbprint + ".pfx");
            await repo.SaveAsync(cert, default);

            Assert.NotNull(new X509Certificate2(expectedFile));
        }

        [Fact]
        public async Task ItCreatesCertOnDiskAsync()
        {
            var dir = new DirectoryInfo(Path.Combine(AppContext.BaseDirectory, Path.GetRandomFileName()));
            Assert.False(dir.Exists, "Directory should not exist yet created");

            var repo = new FileSystemCertificateRepository(dir, "testpassword");
            var cert = CreateTestCert("localhost");
            var expectedFile = Path.Combine(dir.FullName, "certs", cert.Thumbprint + ".pfx");

            await repo.SaveAsync(cert, default);

            dir.Refresh();
            Assert.True(dir.Exists, "Directory was created");
            Assert.True(File.Exists(expectedFile), "Cert exists");
        }

        [Fact]
        public void DIConfiguresRepo()
        {
            var dir = new DirectoryInfo(Path.Combine(AppContext.BaseDirectory, Path.GetRandomFileName()));
            var services = new ServiceCollection()
                .AddLogging()
                .AddLetsEncrypt()
                .PersistDataToDirectory(dir, "testpassword")
                .Services
                .BuildServiceProvider(validateScopes: true);

            Assert.Single(
                services.GetServices<ICertificateRepository>()
                .OfType<FileSystemCertificateRepository>());
        }
    }
}
