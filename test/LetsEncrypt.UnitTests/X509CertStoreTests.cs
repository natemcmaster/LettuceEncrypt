using System;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using McMaster.AspNetCore.LetsEncrypt;
using McMaster.AspNetCore.LetsEncrypt.Internal;
using McMaster.Extensions.Xunit;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Xunit;
using Xunit.Abstractions;

namespace LetsEncrypt.UnitTests
{
    using static TestUtils;

    public class X509CertStoreTests : IDisposable
    {
        private readonly ITestOutputHelper _output;
        private readonly LetsEncryptOptions _options;
        private readonly X509CertStore _certStore;

        public X509CertStoreTests(ITestOutputHelper output)
        {
            _output = output;
            _options = new LetsEncryptOptions();
            _certStore = new X509CertStore(Options.Create(_options), NullLogger<X509CertStore>.Instance)
            {
                AllowInvalidCerts = true
            };
        }

        public void Dispose()
        {
            _certStore.Dispose();
        }

        [Fact]
        public async Task ItFindsCertByCommonNameAsync()
        {
            var commonName = "x509store.read.letsencrypt.test.natemcmaster.com";
            _options.DomainNames = new[] { commonName };
            using var x509store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
            x509store.Open(OpenFlags.ReadWrite);
            var testCert = CreateTestCert(commonName);
            x509store.Add(testCert);

            _output.WriteLine($"Adding cert {testCert.Thumbprint} to My/CurrentUser");

            try
            {
                var certs = await _certStore.GetCertificatesAsync(default);
                var foundCert = Assert.Single(certs);
                Assert.NotNull(foundCert);
                Assert.Equal(testCert, foundCert);
            }
            finally
            {

                x509store.Remove(testCert);
            }
        }

        [SkippableFact]
        [SkipOnOS(OS.Windows)] // Flaky on Windows for unclear reasons.
        public async Task ItSavesCertificates()
        {
            var commonName = "x509store.save.letsencrypt.test.natemcmaster.com";
            var testCert = CreateTestCert(commonName);
            using var x509store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
            x509store.Open(OpenFlags.ReadWrite);

            try
            {
                await _certStore.SaveAsync(testCert, default);

                var certificates = x509store.Certificates.Find(
                    X509FindType.FindByThumbprint,
                    testCert.Thumbprint,
                    validOnly: false);

                _output.WriteLine($"Searching for cert {testCert.Thumbprint} to My/CurrentUser");

                var foundCert = Assert.Single(certificates);

                Assert.NotNull(foundCert);
                Assert.Equal(testCert, foundCert);
            }
            finally
            {
                x509store.Remove(testCert);
            }
        }

        [Fact]
        public async Task ItReturnsEmptyWhenCantFindCertAsync()
        {
            var commonName = "notfound.letsencrypt.test.natemcmaster.com";
            _options.DomainNames = new[] { commonName };
            var certs = await _certStore.GetCertificatesAsync(default);
            Assert.Empty(certs);
        }

        [Fact]
        public void ItFindsCertTheCertWithLongestLifespan()
        {
            var commonName = "x509store-ttl.letsencrypt.test.natemcmaster.com";
            using var x509store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
            x509store.Open(OpenFlags.ReadWrite);
            var testCert0 = CreateTestCert(commonName, DateTimeOffset.Now.AddMinutes(2));
            var testCert1 = CreateTestCert(commonName, DateTimeOffset.Now.AddHours(1));
            var testCert2 = CreateTestCert(commonName, DateTimeOffset.Now.AddHours(2));
            x509store.Add(testCert2);
            x509store.Add(testCert1);
            x509store.Add(testCert0);
            try
            {
                var foundCert = _certStore.GetCertificate(commonName);
                Assert.NotNull(foundCert);
                Assert.Equal(testCert2, foundCert);
            }
            finally
            {
                x509store.Remove(testCert0);
                x509store.Remove(testCert1);
                x509store.Remove(testCert2);
            }
        }
    }
}
