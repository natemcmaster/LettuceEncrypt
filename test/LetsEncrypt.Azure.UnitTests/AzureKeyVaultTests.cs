using Azure.Security.KeyVault.Certificates;
using McMaster.AspNetCore.LetsEncrypt;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Hosting.Internal;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Moq;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Xunit;

#if NETCOREAPP2_1
using IHostEnvironment = Microsoft.Extensions.Hosting.IHostingEnvironment;
#endif

namespace LetsEncrypt.Azure.UnitTests
{
    public class AzureKeyVaultTests
    {
        [Fact]
        public void InterfacesRegistered()
        {
            var services = new ServiceCollection();

            var provider = services
                .AddSingleton<IHostEnvironment, HostingEnvironment>()
                .AddLogging()
                .AddLetsEncrypt()
                .AddKeyVaultCertificateRepository(options =>
                {
                    options.AzureKeyVaultEndpoint = "http://something";
                })
                .Services.BuildServiceProvider();


            Assert.Single(provider.GetServices<ICertificateRepository>().OfType<AzureKeyVaultCertificateRepository>());
            Assert.Single(provider.GetServices<ICertificateSource>().OfType<AzureKeyVaultCertificateRepository>());
        }

        [Fact]
        public async Task GetCertificateLooksForDomainsAsync()
        {
            const string Domain1 = "https://github.com";
            const string Domain2 = "https://azure.com";

            var client = new Mock<CertificateClient>();
            var logger = new Mock<ILogger<AzureKeyVaultCertificateRepository>>();
            var options = new Mock<IOptions<LetsEncryptOptions>>();

            options.Setup(o => o.Value).Returns(new LetsEncryptOptions
            {
                DomainNames = new[] { Domain1, Domain2 }
            });

            var repository = new AzureKeyVaultCertificateRepository(client.Object, options.Object, logger.Object);

            var certificates = await repository.GetCertificatesAsync(CancellationToken.None);

            Assert.Empty(certificates);

            client.Verify(t => t.GetCertificateAsync(AzureKeyVaultCertificateRepository.NormalizeHostName(Domain1), CancellationToken.None));
            client.Verify(t => t.GetCertificateAsync(AzureKeyVaultCertificateRepository.NormalizeHostName(Domain2), CancellationToken.None));
        }
    }
}

