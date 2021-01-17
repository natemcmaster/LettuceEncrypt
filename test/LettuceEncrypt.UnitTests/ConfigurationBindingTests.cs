// Copyright (c) Nate McMaster.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System.Collections.Generic;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Xunit;

namespace LettuceEncrypt.Tests
{
    public class ConfigurationBindingTests
    {
        [Fact]
        public void ItBindsToConfig()
        {
            var data = new Dictionary<string, string>
            {
                ["LettuceEncrypt:AcceptTermsOfService"] = "true",
                ["LettuceEncrypt:DomainNames:0"] = "one.com",
                ["LettuceEncrypt:DomainNames:1"] = "two.com",
            };
            var config = new ConfigurationBuilder()
                .AddInMemoryCollection(data)
                .Build();

            var services = new ServiceCollection()
                .AddSingleton<IConfiguration>(config)
                .AddLettuceEncrypt()
                .Services
                .BuildServiceProvider(true);

            var options = services.GetRequiredService<IOptions<LettuceEncryptOptions>>();

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
                ["LettuceEncrypt:EmailAddress"] = "config",
            };
            var config = new ConfigurationBuilder()
                .AddInMemoryCollection(data)
                .Build();

            var services = new ServiceCollection()
                .AddSingleton<IConfiguration>(config)
                .AddLettuceEncrypt(o => { o.EmailAddress = "code"; })
                .Services
                .BuildServiceProvider(true);

            var options = services.GetRequiredService<IOptions<LettuceEncryptOptions>>();

            Assert.Equal("code", options.Value.EmailAddress);
        }
    }
}
