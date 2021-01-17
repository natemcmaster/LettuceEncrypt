// Copyright (c) Nate McMaster.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using LettuceEncrypt.Internal;
using McMaster.Extensions.Xunit;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Xunit;
using Xunit.Abstractions;

namespace LettuceEncrypt.UnitTests
{
    using static TestUtils;

    public class X509CertStoreTests : IDisposable
    {
        private readonly ITestOutputHelper _output;
        private readonly LettuceEncryptOptions _options;
        private readonly X509CertStore _certStore;

        public X509CertStoreTests(ITestOutputHelper output)
        {
            _output = output;
            _options = new LettuceEncryptOptions();
            _certStore = new X509CertStore(Options.Create(_options), NullLogger<X509CertStore>.Instance)
            {
                AllowInvalidCerts = true
            };
        }

        public void Dispose()
        {
            _certStore.Dispose();
        }

        [SkippableFact]
        [SkipOnWindowsCIBuild(SkipReason =
            "On Windows in CI, adding certs to store doesn't work for unclear reasons.")]
        public async Task ItFindsCertByCommonNameAsync()
        {
            var commonName = "x509store.read.test.natemcmaster.com";
            _options.DomainNames = new[] { commonName };
            using var x509Store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
            x509Store.Open(OpenFlags.ReadWrite);
            var testCert = CreateTestCert(commonName);
            x509Store.Add(testCert);

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
                x509Store.Remove(testCert);
            }
        }

        [SkippableFact]
        [SkipOnWindowsCIBuild(SkipReason =
            "On Windows in CI, adding certs to store doesn't work for unclear reasons.")]
        public async Task ItSavesCertificates()
        {
            var commonName = "x509store.save.test.natemcmaster.com";
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
            var commonName = "notfound.test.natemcmaster.com";
            _options.DomainNames = new[] { commonName };
            var certs = await _certStore.GetCertificatesAsync(default);
            Assert.Empty(certs);
        }
    }
}
