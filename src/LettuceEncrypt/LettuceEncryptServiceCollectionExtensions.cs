// Copyright (c) Nate McMaster.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using LettuceEncrypt;
using LettuceEncrypt.Internal;
using LettuceEncrypt.Internal.IO;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;

#if NETSTANDARD2_0
using IHostEnvironment = Microsoft.Extensions.Hosting.IHostingEnvironment;
#endif

// ReSharper disable once CheckNamespace
namespace Microsoft.Extensions.DependencyInjection
{
    /// <summary>
    /// Helper methods for configuring Lettuce Encrypt services.
    /// </summary>
    public static class LettuceEncryptServiceCollectionExtensions
    {
        /// <summary>
        /// Add services that will automatically generate HTTPS certificates for this server.
        /// By default, this uses Let's Encrypt (<see href="https://letsencrypt.org/">https://letsencrypt.org/</see>).
        /// </summary>
        /// <param name="services"></param>
        /// <returns></returns>
        public static ILettuceEncryptServiceBuilder AddLettuceEncrypt(this IServiceCollection services)
            => services.AddLettuceEncrypt(_ => { });

        /// <summary>
        /// Add services that will automatically generate HTTPS certificates for this server.
        /// By default, this uses Let's Encrypt (<see href="https://letsencrypt.org/">https://letsencrypt.org/</see>).
        /// </summary>
        /// <param name="services"></param>
        /// <param name="configure">A callback to configure options.</param>
        /// <returns></returns>
        public static ILettuceEncryptServiceBuilder AddLettuceEncrypt(this IServiceCollection services,
            Action<LettuceEncryptOptions> configure)
        {
            services.AddTransient<IConfigureOptions<KestrelServerOptions>, KestrelOptionsSetup>();

            services.AddSingleton<CertificateSelector>()
                .AddSingleton<IConsole>(PhysicalConsole.Singleton)
                .AddSingleton<IClock, SystemClock>()
                .AddSingleton<TermsOfServiceChecker>()
                .AddSingleton<IHostedService, StartupCertificateLoader>()
                .AddSingleton<ICertificateSource, DeveloperCertLoader>()
                .AddSingleton<IHostedService, AcmeCertificateLoader>()
                .AddSingleton<IHttpChallengeResponseStore, InMemoryHttpChallengeResponseStore>()
                .AddSingleton<X509CertStore>()
                .AddSingleton<ICertificateSource>(x => x.GetRequiredService<X509CertStore>())
                .AddSingleton<ICertificateRepository>(x => x.GetRequiredService<X509CertStore>())
                .AddSingleton<HttpChallengeResponseMiddleware>()
                .AddSingleton<TlsAlpnChallengeResponder>()
                .AddSingleton<IStartupFilter, HttpChallengeStartupFilter>();

            services.AddSingleton<IConfigureOptions<LettuceEncryptOptions>>(s =>
            {
                var config = s.GetService<IConfiguration?>();
                return new ConfigureOptions<LettuceEncryptOptions>(options => config?.Bind("LettuceEncrypt", options));
            });

            services.Configure(configure);

            return new LettuceEncryptServiceBuilder(services);
        }
    }
}
