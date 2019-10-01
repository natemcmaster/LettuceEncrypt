// Copyright (c) Nate McMaster.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using System.Security.Cryptography.X509Certificates;
using Certes.Acme;
using Microsoft.Extensions.Hosting;

#if NETSTANDARD2_0
using IHostEnvironment = Microsoft.Extensions.Hosting.IHostingEnvironment;
#endif

namespace McMaster.AspNetCore.LetsEncrypt
{
    /// <summary>
    /// Options for configuring Let's Encrypt to automatically generate HTTPS certificates.
    /// </summary>
    public class LetsEncryptOptions
    {
        private string[] _domainNames = Array.Empty<string>();
        private bool? _useStagingServer;

        /// <summary>
        /// The domain names for which to generate certificates.
        /// </summary>
        public string[] DomainNames
        {
            get => _domainNames;
            set => _domainNames = value ?? throw new ArgumentNullException(nameof(value));
        }

        /// <summary>
        /// Indicate that you agree with Let's Encrypt's terms of service.
        /// <para>
        /// See <see href="https://letsencrypt.org">https://letsencrypt.org</see> for details.
        /// </para>
        /// </summary>
        public bool AcceptTermsOfService { get; set; }

        /// <summary>
        /// The email address used to register with letsencrypt.org.
        /// </summary>
        public string EmailAddress { get; set; } = string.Empty;

        /// <summary>
        /// Use Let's Encrypt staging server.
        /// <para>
        /// This is recommended during development of the application and is automatically enabled
        /// if the hosting environment name is 'Development'.
        /// </para>
        /// </summary>
        public bool UseStagingServer
        {
            get => _useStagingServer ?? false;
            set => _useStagingServer = value;
        }

        private bool UseStagingServerExplicitlySet => _useStagingServer.HasValue;

        /// <summary>
        /// The uri to the server that implements the ACME protocol for certificate generation.
        /// </summary>
        internal Uri GetAcmeServer(IHostEnvironment env)
        {
            var useStaging = UseStagingServerExplicitlySet
                ? UseStagingServer
                : env.IsDevelopment();

            return useStaging
                ? WellKnownServers.LetsEncryptStagingV2
                : WellKnownServers.LetsEncryptV2;
        }

        /// <summary>
        /// A certificate to use if a certifcates cannot be created automatically.
        /// <para>
        /// This can be null if there is not fallback certificate.
        /// </para>
        /// </summary>
        public X509Certificate2? FallbackCertificate { get; set; }

        /// <summary>
        /// How long before certificate expiration will be renewal attempted
        /// </summary>
        public TimeSpan? RenewDaysInAdvance { get; set; } = TimeSpan.FromDays(30);

        /// <summary>
        /// How often will be certificates checked for renewal
        /// </summary>
        public TimeSpan? RenewalCheckPeriod { get; set; } = TimeSpan.FromDays(1);

        /// <summary>
        /// The uri to the server that implements the ACME protocol for certificate generation.
        /// Asymetric encryption algorithm: RS256, ES256, ES384, ES512
        /// </summary>
        public KeyAlgorithm KeyAlgorithm { get; set; } = KeyAlgorithm.ES256;
    }
}
