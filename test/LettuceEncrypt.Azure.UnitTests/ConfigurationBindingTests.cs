// Copyright (c) Nate McMaster.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System.Collections.Generic;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Xunit;

namespace LettuceEncrypt.Azure.UnitTests
{
    public class ConfigurationBindingTests
    {
        [Fact]
        public void ItBindsToConfig()
        {
            var vaultUrl = "https://my.vault.azure.net/";
            var mySecretName = "my-secret-name";
            var data = new Dictionary<string, string>
            {
                ["LettuceEncrypt:AzureKeyVault:AzureKeyVaultEndpoint"] = vaultUrl,
                ["LettuceEncrypt:AzureKeyVault:AccountKeySecretName"] = mySecretName,
            };
            var config = new ConfigurationBuilder()
                .AddInMemoryCollection(data)
                .Build();

            var services = new ServiceCollection()
                .AddSingleton<IConfiguration>(config)
                .AddLettuceEncrypt()
                .PersistCertificatesToAzureKeyVault()
                .Services
                .BuildServiceProvider(true);

            var options = services.GetRequiredService<IOptions<AzureKeyVaultLettuceEncryptOptions>>();

            Assert.Equal(vaultUrl, options.Value.AzureKeyVaultEndpoint);
            Assert.Equal(mySecretName, options.Value.AccountKeySecretName);
        }

        [Fact]
        public void ExplicitOptionsWin()
        {
            var data = new Dictionary<string, string>
            {
                ["LettuceEncrypt:AzureKeyVault:AzureKeyVaultEndpoint"] = "https://fromconfig/",
            };
            var config = new ConfigurationBuilder()
                .AddInMemoryCollection(data)
                .Build();

            var services = new ServiceCollection()
                .AddSingleton<IConfiguration>(config)
                .AddLettuceEncrypt(o => { o.EmailAddress = "code"; })
                .PersistCertificatesToAzureKeyVault(o => o.AzureKeyVaultEndpoint = "https://incode/")
                .Services
                .BuildServiceProvider(true);

            var options = services.GetRequiredService<IOptions<AzureKeyVaultLettuceEncryptOptions>>();

            Assert.Equal("https://incode/", options.Value.AzureKeyVaultEndpoint);
        }

#if NETCOREAPP3_1
        [Theory]
        [InlineData(null)]
        [InlineData("")]
        [InlineData("not a url")]
        public void ItValidatesEndpointIsUrl(string invalidEndpoint)
        {
            var services = new ServiceCollection()
                .AddLettuceEncrypt()
                .PersistCertificatesToAzureKeyVault(o => { o.AzureKeyVaultEndpoint = invalidEndpoint; })
                .Services
                .BuildServiceProvider(true);

            var options = services.GetRequiredService<IOptions<AzureKeyVaultLettuceEncryptOptions>>();

            var ex = Assert.Throws<OptionsValidationException>(() => options.Value);
            Assert.Contains(nameof(AzureKeyVaultLettuceEncryptOptions.AzureKeyVaultEndpoint), ex.Message);
        }
#endif
    }
}
