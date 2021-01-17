// Copyright (c) Nate McMaster.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

#nullable enable
using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using LettuceEncrypt.Internal;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Hosting.Internal;
using Xunit;
#if NETCOREAPP2_1
using IHostEnvironment = Microsoft.Extensions.Hosting.IHostingEnvironment;

#endif

namespace LettuceEncrypt.UnitTests
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
        public async Task ItCreatesDirectory()
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

        [Theory]
        [InlineData(null)]
        [InlineData("testpassword")]
        public async Task ItRoundTripsCert(string? password)
        {
            var dir = new DirectoryInfo(Path.Combine(AppContext.BaseDirectory, Path.GetRandomFileName()));

            var repo = new FileSystemCertificateRepository(dir, password);
            var writeCert = CreateTestCert("localhost");

            await repo.SaveAsync(writeCert, default);

            var certs = await repo.GetCertificatesAsync(default);
            var readCert = Assert.Single(certs);
            Assert.NotSame(writeCert, readCert);
            Assert.Equal(writeCert, readCert);
        }

        [Fact]
        public void DIConfiguresRepo()
        {
            var dir = new DirectoryInfo(Path.Combine(AppContext.BaseDirectory, Path.GetRandomFileName()));
            var services = new ServiceCollection()
                .AddSingleton<IHostEnvironment, HostingEnvironment>()
                .AddLogging()
                .AddLettuceEncrypt()
                .PersistDataToDirectory(dir, "testpassword")
                .Services
                .BuildServiceProvider(validateScopes: true);

            Assert.Single(
                services.GetServices<ICertificateRepository>()
                    .OfType<FileSystemCertificateRepository>());
        }

        [Fact]
        public void MultipleCallsToDIWithSameInfoDoesNotDuplicate()
        {
            var dir = new DirectoryInfo(Path.Combine(AppContext.BaseDirectory, Path.GetRandomFileName()));

            var provider = new ServiceCollection()
                .AddSingleton<IHostEnvironment, HostingEnvironment>()
                .AddLogging()
                .AddLettuceEncrypt()
                .PersistDataToDirectory(dir, "")
                .PersistDataToDirectory(dir, "")
                .Services
                .BuildServiceProvider(validateScopes: true);


            Assert.Single(provider.GetServices<ICertificateRepository>().OfType<FileSystemCertificateRepository>());
            Assert.Single(provider.GetServices<ICertificateSource>().OfType<FileSystemCertificateRepository>());
        }

        [Fact]
        public void MultipleCallsToDIWithDirerentDirectory()
        {
            var dir1 = new DirectoryInfo(Path.Combine(AppContext.BaseDirectory, Path.GetRandomFileName()));
            var dir2 = new DirectoryInfo(Path.Combine(AppContext.BaseDirectory, Path.GetRandomFileName()));

            var provider = new ServiceCollection()
                .AddSingleton<IHostEnvironment, HostingEnvironment>()
                .AddLogging()
                .AddLettuceEncrypt()
                .PersistDataToDirectory(dir1, "")
                .PersistDataToDirectory(dir2, "")
                .Services
                .BuildServiceProvider(validateScopes: true);


            Assert.Equal(2,
                provider.GetServices<ICertificateRepository>().OfType<FileSystemCertificateRepository>().Count());
            Assert.Equal(2,
                provider.GetServices<ICertificateSource>().OfType<FileSystemCertificateRepository>().Count());
        }

        [Fact]
        public void ThrowsIfMultipleCallsDIWithDifferentPassword()
        {
            var dir = new DirectoryInfo(Path.Combine(AppContext.BaseDirectory, Path.GetRandomFileName()));

            var provider = new ServiceCollection()
                .AddSingleton<IHostEnvironment, HostingEnvironment>()
                .AddLogging()
                .AddLettuceEncrypt()
                .PersistDataToDirectory(dir, "one");

            Assert.Throws<ArgumentException>(() => provider.PersistDataToDirectory(dir, "two"));
        }
    }
}
