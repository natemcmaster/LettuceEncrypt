// Copyright (c) Nate McMaster.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Azure.Security.KeyVault.Certificates;
using Azure.Security.KeyVault.Secrets;
using LettuceEncrypt.Azure.Internal;
using LettuceEncrypt.UnitTests;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Hosting.Internal;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Moq;
using Xunit;

#if NETCOREAPP2_1
using IHostEnvironment = Microsoft.Extensions.Hosting.IHostingEnvironment;
#endif

namespace LettuceEncrypt.Azure.UnitTests
{
    public class AzureKeyVaultTests
    {
        private static void DefaultConfigure(AzureKeyVaultLettuceEncryptOptions options)
        {
            options.AzureKeyVaultEndpoint = "http://something";
        }

        [Fact]
        public void SourceAndRepositorySameInstance()
        {
            var provider = new ServiceCollection()
                .AddSingleton<IHostEnvironment, HostingEnvironment>()
                .AddLogging()
                .AddLettuceEncrypt()
                .PersistCertificatesToAzureKeyVault(DefaultConfigure)
                .Services
                .BuildServiceProvider(validateScopes: true);


            var repository = provider.GetServices<ICertificateRepository>().OfType<AzureKeyVaultCertificateRepository>()
                .First();
            var source = provider.GetServices<ICertificateSource>().OfType<AzureKeyVaultCertificateRepository>()
                .First();

            Assert.Same(source, repository);
        }

        [Fact]
        public void MultipleCallsToPersistCertificatesToAzureKeyVaultDoesNotDuplicateServices()
        {
            var provider = new ServiceCollection()
                .AddSingleton<IHostEnvironment, HostingEnvironment>()
                .AddLogging()
                .AddLettuceEncrypt()
                .PersistCertificatesToAzureKeyVault(DefaultConfigure)
                .PersistCertificatesToAzureKeyVault(DefaultConfigure)
                .PersistCertificatesToAzureKeyVault(DefaultConfigure)
                .Services
                .BuildServiceProvider(validateScopes: true);


            Assert.Single(provider.GetServices<ICertificateRepository>().OfType<AzureKeyVaultCertificateRepository>());
            Assert.Single(provider.GetServices<ICertificateSource>().OfType<AzureKeyVaultCertificateRepository>());
        }

        [Fact]
        public async Task ImportCertificateChecksDuplicate()
        {
            const string Domain1 = "github.com";
            const string Domain2 = "azure.com";

            var certClient = new Mock<CertificateClient>();
            var certClientFactory = new Mock<ICertificateClientFactory>();
            certClientFactory.Setup(c => c.Create()).Returns(certClient.Object);
            var options = Options.Create(new LettuceEncryptOptions());

            options.Value.DomainNames = new[] { Domain1, Domain2 };

            var repository = new AzureKeyVaultCertificateRepository(
                certClientFactory.Object,
                Mock.Of<ISecretClientFactory>(),
                options,
                NullLogger<AzureKeyVaultCertificateRepository>.Instance);
            foreach (var domain in options.Value.DomainNames)
            {
                var certificateToSave = TestUtils.CreateTestCert(domain);
                await repository.SaveAsync(certificateToSave, CancellationToken.None);
            }

            certClient.Verify(t => t.GetCertificateAsync(AzureKeyVaultCertificateRepository.NormalizeHostName(Domain1),
                CancellationToken.None));
            certClient.Verify(t => t.GetCertificateAsync(AzureKeyVaultCertificateRepository.NormalizeHostName(Domain2),
                CancellationToken.None));
        }

        [Fact]
        public async Task GetCertificateLooksForDomainsAsync()
        {
            const string Domain1 = "github.com";
            const string Domain2 = "azure.com";

            var secretClient = new Mock<SecretClient>();
            var secretClientFactory = new Mock<ISecretClientFactory>();
            secretClientFactory.Setup(c => c.Create()).Returns(secretClient.Object);
            var options = Options.Create(new LettuceEncryptOptions());

            options.Value.DomainNames = new[] { Domain1, Domain2 };

            var repository = new AzureKeyVaultCertificateRepository(
                Mock.Of<ICertificateClientFactory>(),
                secretClientFactory.Object, options,
                NullLogger<AzureKeyVaultCertificateRepository>.Instance);

            var certificates = await repository.GetCertificatesAsync(CancellationToken.None);

            Assert.Empty(certificates);

            secretClient.Verify(t => t.GetSecretAsync(AzureKeyVaultCertificateRepository.NormalizeHostName(Domain1),
                null, CancellationToken.None));
            secretClient.Verify(t => t.GetSecretAsync(AzureKeyVaultCertificateRepository.NormalizeHostName(Domain2),
                null, CancellationToken.None));
        }
    }
}
