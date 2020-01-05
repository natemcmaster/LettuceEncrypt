using McMaster.AspNetCore.LetsEncrypt.Internal;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using System;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using Xunit;
using Xunit.Abstractions;

namespace LetsEncrypt.UnitTests
{
    using static TestUtils;

    public class X509CertStoreTests
    {
        private readonly ITestOutputHelper _output;

        public X509CertStoreTests(ITestOutputHelper output)
        {
            _output = output;
        }

        [Fact]
        public void ItFindsCertByCommonName()
        {
            var commonName = "x509store.read.letsencrypt.test.natemcmaster.com";
            using var x509store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
            x509store.Open(OpenFlags.ReadWrite);
            var testCert = CreateTestCert(commonName);
            x509store.Add(testCert);

            _output.WriteLine($"Adding cert {testCert.Thumbprint} to My/CurrentUser");

            try
            {
                using var certStore = new X509CertStore(NullLogger<X509CertStore>.Instance)
                {
                    AllowInvalidCerts = true
                };
                var foundCert = certStore.GetCertificate(commonName);
                Assert.NotNull(foundCert);
                Assert.Equal(testCert, foundCert);
            }
            finally
            {

                x509store.Remove(testCert);
            }
        }

        [Fact]
        public async Task ItSavesCertifiates()
        {
            var commonName = "x509store.save.letsencrypt.test.natemcmaster.com";
            var testCert = CreateTestCert(commonName);
            using var x509store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
            x509store.Open(OpenFlags.ReadWrite);

            try
            {
                using var certStore = new X509CertStore(NullLogger<X509CertStore>.Instance)
                {
                    AllowInvalidCerts = true
                };
                await certStore.SaveAsync(testCert, default);

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
        public void ItReturnsNullWhenCantFindCert()
        {
            var commonName = "notfound.letsencrypt.test.natemcmaster.com";
            using var certStore = new X509CertStore(Mock.Of<ILogger<X509CertStore>>())
            {
                AllowInvalidCerts = true
            };
            var foundCert = certStore.GetCertificate(commonName);
            Assert.Null(foundCert);
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
                using var certStore = new X509CertStore(Mock.Of<ILogger<X509CertStore>>())
                {
                    AllowInvalidCerts = true
                };
                var foundCert = certStore.GetCertificate(commonName);
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
