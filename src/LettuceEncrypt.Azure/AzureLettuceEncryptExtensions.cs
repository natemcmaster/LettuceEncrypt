// Copyright (c) Nate McMaster.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using LettuceEncrypt;
using LettuceEncrypt.Accounts;
using LettuceEncrypt.Azure;
using LettuceEncrypt.Azure.Internal;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;

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
        public static ILettuceEncryptServiceBuilder PersistCertificatesToAzureKeyVault(
            this ILettuceEncryptServiceBuilder builder)
            => builder.PersistCertificatesToAzureKeyVault(_ => { });

        /// <summary>
        /// Persists certificates to configured key vault.
        /// </summary>
        /// <param name="builder">A LettuceEncrypt service builder.</param>
        /// <param name="configure">Configuration for KeyVault connections.</param>
        /// <returns>The original LettuceEncrypt service builder.</returns>
        public static ILettuceEncryptServiceBuilder PersistCertificatesToAzureKeyVault(
            this ILettuceEncryptServiceBuilder builder,
            Action<AzureKeyVaultLettuceEncryptOptions> configure)
        {
            var services = builder.Services;
            services
                .AddSingleton<ICertificateClientFactory, CertificateClientFactory>()
                .AddSingleton<ISecretClientFactory, SecretClientFactory>();

            services.TryAddSingleton<AzureKeyVaultCertificateRepository>();
            services.TryAddSingleton<IAccountStore, AzureKeyVaultAccountStore>();
            services.TryAddEnumerable(
                ServiceDescriptor.Singleton<ICertificateRepository, AzureKeyVaultCertificateRepository>(x =>
                    x.GetRequiredService<AzureKeyVaultCertificateRepository>()));
            services.TryAddEnumerable(
                ServiceDescriptor.Singleton<ICertificateSource, AzureKeyVaultCertificateRepository>(x =>
                    x.GetRequiredService<AzureKeyVaultCertificateRepository>()));

            services.AddSingleton<IConfigureOptions<AzureKeyVaultLettuceEncryptOptions>>(s =>
            {
                var config = s.GetService<IConfiguration?>();
                return new ConfigureOptions<AzureKeyVaultLettuceEncryptOptions>(o =>
                    config?.Bind("LettuceEncrypt:AzureKeyVault", o));
            });

            var options = services
                .AddOptions<AzureKeyVaultLettuceEncryptOptions>()
                .Configure(configure);

#if FEATURE_VALIDATE_DATA_ANNOTATIONS
            options.ValidateDataAnnotations();
#endif

            return builder;
        }
    }
}
