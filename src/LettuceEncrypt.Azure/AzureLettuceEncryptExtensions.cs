// Copyright (c) Nate McMaster.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using LettuceEncrypt;
using LettuceEncrypt.Accounts;
using LettuceEncrypt.Azure;
using Microsoft.Extensions.DependencyInjection.Extensions;

// ReSharper disable once CheckNamespace
namespace Microsoft.Extensions.DependencyInjection
{
    /// <summary>
    /// Extensions to integrate Azure with LettuceEncrypt.
    /// </summary>
    public static class AzureLettuceEncryptExtensions
    {
        /// <summary>
        /// Persists certificates to configured key vault.
        /// </summary>
        /// <param name="builder">A LettuceEncrypt service builder.</param>
        /// <returns>The original LettuceEncrypt service builder.</returns>
        public static ILettuceEncryptServiceBuilder PersistCertificatesToAzureKeyVault(this ILettuceEncryptServiceBuilder builder)
            => builder.PersistCertificatesToAzureKeyVault(_ => { });

        /// <summary>
        /// Persists certificates to configured key vault.
        /// </summary>
        /// <param name="builder">A LettuceEncrypt service builder.</param>
        /// <param name="configure">Configuration for KeyVault connections.</param>
        /// <returns>The original LettuceEncrypt service builder.</returns>
        public static ILettuceEncryptServiceBuilder PersistCertificatesToAzureKeyVault(this ILettuceEncryptServiceBuilder builder,
            Action<AzureKeyVaultLettuceEncryptOptions> configure)
        {
            builder.Services.TryAddSingleton<AzureKeyVaultCertificateRepository>();
            builder.Services.TryAddSingleton<IAccountStore, AzureKeyVaultAccountStore>();
            builder.Services.TryAddEnumerable(ServiceDescriptor.Singleton<ICertificateRepository, AzureKeyVaultCertificateRepository>(x => x.GetRequiredService<AzureKeyVaultCertificateRepository>()));
            builder.Services.TryAddEnumerable(ServiceDescriptor.Singleton<ICertificateSource, AzureKeyVaultCertificateRepository>(x => x.GetRequiredService<AzureKeyVaultCertificateRepository>()));

            var options = builder.Services
                .AddOptions<AzureKeyVaultLettuceEncryptOptions>()
                .Configure(configure);

#if FEATURE_VALIDATE_DATA_ANNOTATIONS
                options.ValidateDataAnnotations();
#endif

            return builder;
        }
    }
}
