using System;
using Certes.Acme;
using LettuceEncrypt.Internal;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Hosting.Internal;
using Microsoft.Extensions.Options;
using Xunit;

#if NETCOREAPP2_1
using Environments = Microsoft.Extensions.Hosting.EnvironmentName;
#endif

namespace LettuceEncrypt.UnitTests
{
    public class LetsEncryptCertificateAuthorityProviderTests
    {
        public static TheoryData<string, Uri> EnvironmentToDefaultAcmeServer()
        {
            return new TheoryData<string, Uri>
            {
                {Environments.Development, WellKnownServers.LetsEncryptStagingV2},
                {Environments.Staging, WellKnownServers.LetsEncryptV2},
                {Environments.Production, WellKnownServers.LetsEncryptV2},
                {null, WellKnownServers.LetsEncryptV2},
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
            var provider = new LetsEncryptCertificateAuthorityProvider(
                env,
                Options.Create(new LettuceEncryptOptions()));

            Assert.Equal(
                acmeServer,
                provider.AcmeDirectoryEndpoint);
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

            var useStaging = Options.Create(new LettuceEncryptOptions
            {
                UseStagingServer = true,
            });
            var provider = new LetsEncryptCertificateAuthorityProvider(env, useStaging);

            Assert.Equal(
                WellKnownServers.LetsEncryptStagingV2,
                provider.AcmeDirectoryEndpoint);

            var useProduction = Options.Create(new LettuceEncryptOptions
            {
                UseStagingServer = false,
            });

            provider = new LetsEncryptCertificateAuthorityProvider(env, useProduction);

            Assert.Equal(
                WellKnownServers.LetsEncryptV2,
                provider.AcmeDirectoryEndpoint);
        }
    }
}
