// Copyright (c) Nate McMaster.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using LettuceEncrypt.Internal;
using McMaster.AspNetCore.Kestrel.Certificates;
using Microsoft.AspNetCore.Server.Kestrel.Https;
using Microsoft.Extensions.DependencyInjection;

// ReSharper disable once CheckNamespace
namespace Microsoft.AspNetCore.Hosting
{
    /// <summary>
    /// Methods for configuring Kestrel.
    /// </summary>
    public static class LettuceEncryptKestrelHttpsOptionsExtensions
    {
        private const string MissingServicesMessage =
            "Missing required LettuceEncrypt services. Did you call '.AddLettuceEncrypt()' to add these your DI container?";

        /// <summary>
        /// Configured LettuceEncrypt on this HTTPS endpoint for Kestrel.
        /// </summary>
        /// <param name="httpsOptions">Kestrel's HTTPS configuration</param>
        /// <param name="applicationServices"></param>
        /// <returns>The original HTTPS options with some required settings added to it.</returns>
        /// <exception cref="InvalidOperationException">
        /// Raised if <see cref="LettuceEncryptServiceCollectionExtensions.AddLettuceEncrypt(Microsoft.Extensions.DependencyInjection.IServiceCollection)"/>
        /// has not been used to add required services to the application service provider
        /// </exception>
        public static HttpsConnectionAdapterOptions UseLettuceEncrypt(
            this HttpsConnectionAdapterOptions httpsOptions,
            IServiceProvider applicationServices)
        {
            var selector = applicationServices.GetService<IServerCertificateSelector>();

            if (selector is null)
            {
                throw new InvalidOperationException(MissingServicesMessage);
            }

#if NETCOREAPP3_1
            var tlsResponder = applicationServices.GetService<TlsAlpnChallengeResponder>();
            if (tlsResponder is null)
            {
                throw new InvalidOperationException(MissingServicesMessage);
            }

            return httpsOptions.UseLettuceEncrypt(selector, tlsResponder);

#elif NETSTANDARD2_0
            return httpsOptions.UseServerCertificateSelector(selector);
#else
#error Update TFMs
#endif
        }

#if NETCOREAPP3_1
        internal static HttpsConnectionAdapterOptions UseLettuceEncrypt(
            this HttpsConnectionAdapterOptions httpsOptions,
            IServerCertificateSelector selector,
            TlsAlpnChallengeResponder tlsAlpnChallengeResponder
        )
        {
            httpsOptions.OnAuthenticate = tlsAlpnChallengeResponder.OnSslAuthenticate;
            httpsOptions.UseServerCertificateSelector(selector);
            return httpsOptions;
        }
#elif NETSTANDARD2_0
#else
#error Update TFMs
#endif
    }
}
