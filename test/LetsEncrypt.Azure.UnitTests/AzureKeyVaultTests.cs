using System;
using System.Linq;
using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using Azure.Security.KeyVault.Certificates;
using Azure.Security.KeyVault.Secrets;
using McMaster.AspNetCore.LetsEncrypt;
using Microsoft.Extensions.DependencyInjection;
//using Microsoft.Extensions.Diagnostics.HealthChecks;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Hosting.Internal;
using Microsoft.Extensions.Logging;
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
        private X509Certificate2 BuildSelfSignedServerCertificate(string certificateHost)
        {
            var CN = certificateHost.Replace("https://", ""); // Sanitize from certificate common name, dns name and friendly name

            var sanBuilder = new SubjectAlternativeNameBuilder();
            sanBuilder.AddIpAddress(IPAddress.Loopback);
            sanBuilder.AddIpAddress(IPAddress.IPv6Loopback);
            sanBuilder.AddDnsName(CN);
            sanBuilder.AddDnsName($"www.{CN}");

            var distinguishedName = new X500DistinguishedName($"CN={CN}");

            using var rsa = RSA.Create(2048);

            var request = new CertificateRequest(distinguishedName, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

            var certificate = request.CreateSelfSigned(new DateTimeOffset(DateTime.UtcNow.AddDays(-1)), new DateTimeOffset(DateTime.UtcNow.AddDays(1)));
            var exportedCertficiate = new X509Certificate2(certificate.Export(X509ContentType.Pfx, "p@ssw0rd"), "p@ssw0rd", X509KeyStorageFlags.Exportable);
            return exportedCertficiate;
        }

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
            var logger = new Mock<ILogger<AzureKeyVaultCertificateRepository>>();
            var options = Options.Create(new LetsEncryptOptions
            {
                DomainNames = new[] { Domain1, Domain2 }
            });

            var repository = new AzureKeyVaultCertificateRepository(certclient.Object, secretclient.Object, options.Object, logger.Object);
            foreach(var domain in options.Object.Value.DomainNames)
            {
                var certificateToSave = BuildSelfSignedServerCertificate(domain);
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
            var logger = new Mock<ILogger<AzureKeyVaultCertificateRepository>>();
            var options = new Mock<IOptions<LetsEncryptOptions>>();

            options.Setup(o => o.Value).Returns(new LetsEncryptOptions
            {
                DomainNames = new[] { Domain1, Domain2 }
            });

            var repository = new AzureKeyVaultCertificateRepository(certclient.Object, secretclient.Object, options.Object, logger.Object);

            var certificates = await repository.GetCertificatesAsync(CancellationToken.None);

            Assert.Empty(certificates);

            secretclient.Verify(t => t.GetSecretAsync(AzureKeyVaultCertificateRepository.NormalizeHostName(Domain1), null, CancellationToken.None));
            secretclient.Verify(t => t.GetSecretAsync(AzureKeyVaultCertificateRepository.NormalizeHostName(Domain2), null, CancellationToken.None));
        }
    }
}
