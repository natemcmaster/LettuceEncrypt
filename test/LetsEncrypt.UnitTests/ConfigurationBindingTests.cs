using System;
using System.Collections.Generic;
using McMaster.AspNetCore.LetsEncrypt;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Xunit;

namespace LetsEncrypt.Tests
{
    public class ConfigurationBindingTests
    {
        [Fact]
        public void ItBindsToConfig()
        {
            var data = new Dictionary<string, string>
            {
                ["LetsEncrypt:AcceptTermsOfService"] = "true",
                ["LetsEncrypt:DomainNames:0"] = "one.com",
                ["LetsEncrypt:DomainNames:1"] = "two.com",
            };
            var config = new ConfigurationBuilder()
                .AddInMemoryCollection(data)
                .Build();

            var services = new ServiceCollection()
                .AddSingleton<IConfiguration>(config)
                .AddLetsEncrypt()
                .BuildServiceProvider(true);

            var options = services.GetRequiredService<IOptions<LetsEncryptOptions>>();

            Assert.True(options.Value.AcceptTermsOfService);
            Assert.Collection(options.Value.DomainNames,
                one => Assert.Equal("one.com", one),
                two => Assert.Equal("two.com", two));
        }

        [Fact]
        public void ExplicitOptionsWin()
        {
            var data = new Dictionary<string, string>
            {
                ["LetsEncrypt:EmailAddress"] = "config",
            };
            var config = new ConfigurationBuilder()
                .AddInMemoryCollection(data)
                .Build();

            var services = new ServiceCollection()
                .AddSingleton<IConfiguration>(config)
                .AddLetsEncrypt(o =>
                {
                    o.EmailAddress = "code";
                })
                .BuildServiceProvider(true);

            var options = services.GetRequiredService<IOptions<LetsEncryptOptions>>();

            Assert.Equal("code", options.Value.EmailAddress);
        }
    }
}
