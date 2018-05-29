// Copyright (c) Nate McMaster.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using McMaster.AspNetCore.LetsEncrypt;
using McMaster.AspNetCore.LetsEncrypt.Internal;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;

namespace Microsoft.AspNetCore.LetsEncrypt
{
    /// <summary>
    /// Helper methods
    /// </summary>
    public static class LetsEncryptServiceCollectionExtensions
    {
        /// <summary>
        /// Adds services for setting up let's encrypt when the application starts.
        /// </summary>
        /// <param name="services"></param>
        /// <param name="configure"></param>
        /// <returns></returns>
        public static IServiceCollection AddLetsEncrypt(this IServiceCollection services, Action<LetsEncryptOptions> configure)
        {
            services.AddTransient<IConfigureOptions<KestrelServerOptions>, KestrelOptionsSetup>();

            services.AddSingleton<CertificateSelector>()
                .AddSingleton<IHostedService, DeveloperCertLoader>()
                .AddSingleton<IHostedService, AcmeCertificateLoader>()
                .AddSingleton<IHttpChallengeResponseStore, InMemoryHttpChallengeResponseStore>()
                .AddSingleton<ICertificateStore, X509CertStore>()
                .AddSingleton<HttpChallengeResponseMiddleware>();

            services.Configure(configure);
            return services;
        }
    }
}
