using System;
using Certes.Acme;
using McMaster.AspNetCore.LetsEncrypt;
using McMaster.AspNetCore.LetsEncrypt.Internal;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Hosting.Internal;
using Xunit;

#if NETCOREAPP2_1
using IHostEnvironment = Microsoft.Extensions.Hosting.IHostingEnvironment;
using Environments = Microsoft.Extensions.Hosting.EnvironmentName;
#endif

namespace LetsEncrypt.UnitTests
{
    public class CertificateFactoryTests
    {
        public static TheoryData<string, Uri> EnvironmentToDefaultAcmeServer()
        {
            return new TheoryData<string, Uri>
            {
                { Environments.Development,  WellKnownServers.LetsEncryptStagingV2 },
                { Environments.Staging,  WellKnownServers.LetsEncryptV2 },
                { Environments.Production,  WellKnownServers.LetsEncryptV2 },
                { null,  WellKnownServers.LetsEncryptV2 },
            };
        }

        [Theory]
        [MemberData(nameof(EnvironmentToDefaultAcmeServer))]

        public void UsesDefaultAcmeServerBasedOnEnvironmentName(string environmentName, Uri acmeServer)
        {
            var env = new HostingEnvironment
            {
                EnvironmentName = environmentName
            };

            Assert.Equal(
                acmeServer,
                CertificateFactory.GetAcmeServer(new LetsEncryptOptions(), env));
        }


        [Theory]
        [InlineData("Development")]
        [InlineData("Production")]
        public void OverridesDefaultAcmeServer(string environmentName)
        {
            var env = new HostingEnvironment
            {
                EnvironmentName = environmentName
            };

            var useStaging = new LetsEncryptOptions
            {
                UseStagingServer = true,
            };

            Assert.Equal(
                WellKnownServers.LetsEncryptStagingV2,
                CertificateFactory.GetAcmeServer(useStaging, env));

            var useProduction = new LetsEncryptOptions
            {
                UseStagingServer = false,
            };

            Assert.Equal(
                WellKnownServers.LetsEncryptV2,
                CertificateFactory.GetAcmeServer(useProduction, env));
        }
    }
}
