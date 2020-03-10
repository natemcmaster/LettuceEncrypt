// Copyright (c) Nate McMaster.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using McMaster.AspNetCore.LetsEncrypt;
using Microsoft.Extensions.DependencyInjection.Extensions;

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
        public static ILetsEncryptServiceBuilder AddAzureKeyVaultCertificateSource(this ILetsEncryptServiceBuilder builder)
            => builder.AddAzureKeyVaultCertificateSource(_ => { });

        /// <summary>
        /// Adds key vault certificate repository for LetsEncrypt.
        /// </summary>
        /// <param name="builder">A LetsEncrypt service builder.</param>
        /// <param name="config">Configuration for KeyVault connections.</param>
        /// <returns>The original LetsEncrypt service builder.</returns>
        public static ILetsEncryptServiceBuilder AddAzureKeyVaultCertificateSource(this ILetsEncryptServiceBuilder builder, Action<AzureKeyVaultCertificateRepositoryOptions> config)
        {
            builder.Services.TryAddSingleton<AzureKeyVaultCertificateRepository>();
            builder.Services.TryAddEnumerable(ServiceDescriptor.Transient<ICertificateSource, AzureKeyVaultCertificateRepository>(x => x.GetRequiredService<AzureKeyVaultCertificateRepository>()));

            return builder.ConfigureOptions(config);
        }

        /// <summary>
        /// Persists certificates to configured key vault.
        /// </summary>
        /// <param name="builder">A LetsEncrypt service builder.</param>
        /// <returns>The original LetsEncrypt service builder.</returns>
        public static ILetsEncryptServiceBuilder PersistCertificatesToAzureKeyVault(this ILetsEncryptServiceBuilder builder)
            => builder.PersistCertificatesToAzureKeyVault(_ => { });

        /// <summary>
        /// Persists certificates to configured key vault.
        /// </summary>
        /// <param name="builder">A LetsEncrypt service builder.</param>
        /// <param name="config">Configuration for KeyVault connections.</param>
        /// <returns>The original LetsEncrypt service builder.</returns>
        public static ILetsEncryptServiceBuilder PersistCertificatesToAzureKeyVault(this ILetsEncryptServiceBuilder builder, Action<AzureKeyVaultCertificateRepositoryOptions> config)
        {
            builder.Services.TryAddSingleton<AzureKeyVaultCertificateRepository>();
            builder.Services.TryAddEnumerable(ServiceDescriptor.Transient<ICertificateRepository, AzureKeyVaultCertificateRepository>(x => x.GetRequiredService<AzureKeyVaultCertificateRepository>()));

            return builder.ConfigureOptions(config);
        }

        private static ILetsEncryptServiceBuilder ConfigureOptions(this ILetsEncryptServiceBuilder builder, Action<AzureKeyVaultCertificateRepositoryOptions> config)
        {
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
