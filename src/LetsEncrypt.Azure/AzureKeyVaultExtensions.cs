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
        /// <param name="configure">Configuration for KeyVault connections.</param>
        /// <returns>The original LetsEncrypt service builder.</returns>
        public static ILetsEncryptServiceBuilder PersistCertificatesToAzureKeyVault(this ILetsEncryptServiceBuilder builder,
            Action<AzureKeyVaultCertificateRepositoryOptions> configure)
        {
            builder.Services.TryAddSingleton<AzureKeyVaultCertificateRepository>();
            builder.Services.TryAddEnumerable(ServiceDescriptor.Singleton<ICertificateRepository, AzureKeyVaultCertificateRepository>(x => x.GetRequiredService<AzureKeyVaultCertificateRepository>()));
            builder.Services.TryAddEnumerable(ServiceDescriptor.Singleton<ICertificateSource, AzureKeyVaultCertificateRepository>(x => x.GetRequiredService<AzureKeyVaultCertificateRepository>()));

            var options = builder.Services
                .AddOptions<AzureKeyVaultCertificateRepositoryOptions>()
                .Configure(configure);

#if FEATURE_VALIDATE_DATA_ANNOTATIONS
                options.ValidateDataAnnotations();
#endif

            return builder;
        }
    }
}
