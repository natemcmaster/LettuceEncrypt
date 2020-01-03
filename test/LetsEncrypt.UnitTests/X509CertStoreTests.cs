using McMaster.AspNetCore.LetsEncrypt.Internal;
using Microsoft.Extensions.Logging;
using Moq;
using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Xunit;

namespace LetsEncrypt.UnitTests
{
    public class X509CertStoreTests
    {
        [Fact]
        public void ItFindsCertByCommonName()
        {
            var commonName = "x509store.letsencrypt.test.natemcmaster.com";
            using var x509store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
            x509store.Open(OpenFlags.ReadWrite);
            var testCert = CreateTestCert(commonName);
            x509store.Add(testCert);
            try
            {
                var logger = new Mock<ILogger<X509CertStore>>();
                logger.Setup(l => l.IsEnabled(It.IsAny<LogLevel>())).Returns(true);
                using var certStore = new X509CertStore(logger.Object)
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

        private X509Certificate2 CreateTestCert(string commonName, DateTimeOffset? expires = null)
        {
            expires ??= DateTimeOffset.Now.AddMinutes(2);
            var key = RSA.Create(2048);
            var csr = new CertificateRequest(
                "CN=" + commonName,
                key,
                HashAlgorithmName.SHA512,
                RSASignaturePadding.Pkcs1);
            return csr.CreateSelfSigned(DateTimeOffset.Now.AddMinutes(-1), expires.Value);
        }
    }
}
