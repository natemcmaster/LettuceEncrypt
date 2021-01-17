// Copyright (c) Nate McMaster.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using System.Reflection;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.AspNetCore.Server.Kestrel.Https;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Xunit;

namespace LettuceEncrypt.UnitTests
{
    public class KestrelOptionsSetupTests
    {
        [Fact]
        public void ItSetsCertificateSelector()
        {
            var services = new ServiceCollection()
                .AddLogging()
                .AddLettuceEncrypt()
                .Services
                .BuildServiceProvider(validateScopes: true);

            var kestrelOptions = services.GetRequiredService<IOptions<KestrelServerOptions>>().Value;
            // reflection is gross, but there is no public API for this so (shrug)
            var httpsDefaultsProp =
                typeof(KestrelServerOptions).GetProperty("HttpsDefaults",
                    BindingFlags.Instance | BindingFlags.NonPublic);
            var httpsDefaultsFunc =
                (Action<HttpsConnectionAdapterOptions>)httpsDefaultsProp.GetMethod.Invoke(kestrelOptions,
                    Array.Empty<object>());
            var httpsDefaults = new HttpsConnectionAdapterOptions();

            Assert.Null(httpsDefaults.ServerCertificateSelector);

            httpsDefaultsFunc(httpsDefaults);

            Assert.NotNull(httpsDefaults.ServerCertificateSelector);
        }
    }
}
