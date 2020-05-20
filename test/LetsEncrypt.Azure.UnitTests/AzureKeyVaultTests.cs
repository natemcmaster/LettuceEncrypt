using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Azure.Security.KeyVault.Certificates;
using Azure.Security.KeyVault.Secrets;
using McMaster.AspNetCore.LetsEncrypt;
using LetsEncrypt.UnitTests;
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

namespace LetsEncrypt.Azure.UnitTests
{
    public class AzureKeyVaultTests
    {
        private static void DefaultConfigure(AzureKeyVaultCertificateRepositoryOptions options)
        {
            options.AzureKeyVaultEndpoint = "http://something";
        }

        [Fact]
        public void SourceAndRepositorySameInstance()
        {
            var provider = new ServiceCollection()
                .AddSingleton<IHostEnvironment, HostingEnvironment>()
                .AddLogging()
                .AddLetsEncrypt()
                .PersistCertificatesToAzureKeyVault(DefaultConfigure)
                .Services
                .BuildServiceProvider(validateScopes: true);


            var repository = provider.GetServices<ICertificateRepository>().OfType<AzureKeyVaultCertificateRepository>().First();
            var source = provider.GetServices<ICertificateSource>().OfType<AzureKeyVaultCertificateRepository>().First();

            Assert.Same(source, repository);
        }

        [Fact]
        public void MultipleCallsToPersistCertificatesToAzureKeyVaultDoesNotDuplicateServices()
        {
            var provider = new ServiceCollection()
                .AddSingleton<IHostEnvironment, HostingEnvironment>()
                .AddLogging()
                .AddLetsEncrypt()
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

            var certclient = new Mock<CertificateClient>();
            var secretclient = new Mock<SecretClient>();
            var options = Options.Create(new LetsEncryptOptions());

            options.Value.DomainNames = new[] { Domain1, Domain2 }; 
            
            var repository = new AzureKeyVaultCertificateRepository(certclient.Object, secretclient.Object, options, NullLogger<AzureKeyVaultCertificateRepository>.Instance);
            foreach(var domain in options.Value.DomainNames)
            {
                var certificateToSave = TestUtils.CreateTestCert(domain);
                await repository.SaveAsync(certificateToSave, CancellationToken.None);
            }

            certclient.Verify(t => t.GetCertificateAsync(AzureKeyVaultCertificateRepository.NormalizeHostName(Domain1), CancellationToken.None));
            certclient.Verify(t => t.GetCertificateAsync(AzureKeyVaultCertificateRepository.NormalizeHostName(Domain2), CancellationToken.None));

        }

        [Fact]
        public async Task GetCertificateLooksForDomainsAsync()
        {
            const string Domain1 = "github.com";
            const string Domain2 = "azure.com";

            var certclient = new Mock<CertificateClient>();
            var secretclient = new Mock<SecretClient>();
            var options = Options.Create(new LetsEncryptOptions());

            options.Value.DomainNames = new[] { Domain1, Domain2 };

            var repository = new AzureKeyVaultCertificateRepository(certclient.Object, secretclient.Object, options, NullLogger<AzureKeyVaultCertificateRepository>.Instance);

            var certificates = await repository.GetCertificatesAsync(CancellationToken.None);

            Assert.Empty(certificates);

            secretclient.Verify(t => t.GetSecretAsync(AzureKeyVaultCertificateRepository.NormalizeHostName(Domain1), null, CancellationToken.None));
            secretclient.Verify(t => t.GetSecretAsync(AzureKeyVaultCertificateRepository.NormalizeHostName(Domain2), null, CancellationToken.None));
        }
    }
}
