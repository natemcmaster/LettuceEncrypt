// Copyright (c) Nate McMaster.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using McMaster.AspNetCore.LetsEncrypt;

namespace Microsoft.Extensions.DependencyInjection
{
    /// <summary>
    /// Extensions to enable Azure KeyVault connections with LetsEncrypt.
    /// </summary>
    public static class AzureKeyVaultExtensions
    {
        /// <summary>
        /// Adds key vault certificate repository for LetsEncrypt.
        /// </summary>
        /// <param name="builder">A LetsEncrypt service builder.</param>
        /// <returns>The original LetsEncrypt service builder.</returns>
        public static ILetsEncryptServiceBuilder AddKeyVaultCertificateRepository(this ILetsEncryptServiceBuilder builder)
            => builder.AddKeyVaultCertificateRepository(_ => { });

        /// <summary>
        /// Adds key vault certificate repository for LetsEncrypt.
        /// </summary>
        /// <param name="builder">A LetsEncrypt service builder.</param>
        /// <param name="config">Configuration for KeyVault connections.</param>
        /// <returns>The original LetsEncrypt service builder.</returns>
        public static ILetsEncryptServiceBuilder AddKeyVaultCertificateRepository(this ILetsEncryptServiceBuilder builder, Action<AzureKeyVaultCertificateRepositoryOptions> config)
        {
            builder.Services
                .AddSingleton<AzureKeyVaultCertificateRepository>()
                .AddSingleton<ICertificateSource>(x => x.GetRequiredService<AzureKeyVaultCertificateRepository>())
                .AddSingleton<ICertificateRepository>(x => x.GetRequiredService<AzureKeyVaultCertificateRepository>());

            var options = builder.Services
                .AddOptions<AzureKeyVaultCertificateRepositoryOptions>()
                .Configure(config);

#if FEATURE_VALIDATE_DATA_ANNOTATIONS
                options.ValidateDataAnnotations();
#endif

            return builder;
        }
    }
}
