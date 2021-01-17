// Copyright (c) Nate McMaster.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using LettuceEncrypt.Internal;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using Xunit;
#if NETCOREAPP2_1
using IHostEnvironment = Microsoft.Extensions.Hosting.IHostingEnvironment;

#endif


namespace LettuceEncrypt.UnitTests
{
    public class DeveloperCertLoaderTests
    {
        [Fact]
        public async Task ItFindsDevCert()
        {
            var env = new Mock<IHostEnvironment>();
            env.SetupGet(e => e.EnvironmentName).Returns("Development");

            var loader = new DeveloperCertLoader(env.Object, NullLogger<DeveloperCertLoader>.Instance);

            var certs = await loader.GetCertificatesAsync(default);
            Assert.NotEmpty(certs);
            Assert.All(certs, c => { Assert.Equal("localhost", c.GetNameInfo(X509NameType.SimpleName, false)); });
        }

        [Fact]
        public async Task ItDoesNotLoadCertUnlessDevEnvironment()
        {
            var env = new Mock<IHostEnvironment>();
            env.SetupGet(e => e.EnvironmentName).Returns("Staging");

            var loader = new DeveloperCertLoader(env.Object, NullLogger<DeveloperCertLoader>.Instance);

            var certs = await loader.GetCertificatesAsync(default);
            Assert.Empty(certs);
        }
    }
}
