// Copyright (c) Nate McMaster.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using LettuceEncrypt.Internal;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Moq;
using Xunit;

namespace LettuceEncrypt.UnitTests
{
    public class StartupCertificateLoaderTests
    {
        [Fact]
        public async Task ItLoadsAllCertsIntoSelector()
        {
            var testCert = new X509Certificate2();
            IEnumerable<X509Certificate2> certs = new[] { testCert };

            var selector = new Mock<CertificateSelector>(
                Options.Create(new LettuceEncryptOptions()),
                NullLogger<CertificateSelector>.Instance);

            selector
                .Setup(s => s.Add(testCert))
                .Verifiable();

            var source1 = CreateCertSource(certs);
            var source2 = CreateCertSource(certs);

            var startupLoader = new StartupCertificateLoader(
                new[] { source1.Object, source2.Object },
                selector.Object);

            await startupLoader.StartAsync(default);

            selector.VerifyAll();
            source1.VerifyAll();
            source2.VerifyAll();
        }

        private Mock<ICertificateSource> CreateCertSource(IEnumerable<X509Certificate2> certs)
        {
            var source = new Mock<ICertificateSource>();
            source
                .Setup(s => s.GetCertificatesAsync(It.IsAny<CancellationToken>()))
                .Returns(Task.FromResult(certs))
                .Verifiable();
            return source;
        }
    }
}
