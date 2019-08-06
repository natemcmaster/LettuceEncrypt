// Copyright (c) Nate McMaster.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using McMaster.AspNetCore.LetsEncrypt;
using McMaster.AspNetCore.LetsEncrypt.Internal;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;

namespace Microsoft.Extensions.DependencyInjection
{
    /// <summary>
    /// Helper methods for configuring https://letsencrypt.org/.
    /// </summary>
    public static class LetsEncryptServiceCollectionExtensions
    {
        /// <summary>
        /// Use Let's Encrypt (<see href="https://letsencrypt.org/">https://letsencrypt.org/</see>) to automatically
        /// generate HTTPS certificates for this server.
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
                .AddSingleton<HttpChallengeResponseMiddleware>()
                .AddSingleton<IStartupFilter, HttpChallengeStartupFilter>();

            services.Configure(configure);

            return services;
        }
    }
}
