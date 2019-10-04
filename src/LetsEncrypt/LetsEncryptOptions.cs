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
        private Uri? _acmeServer;
        private string[] _domainNames = Array.Empty<string>();

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
            get => _acmeServer == WellKnownServers.LetsEncryptStaging;
            set => _acmeServer = value
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
        /// Asymetric encryption algorithm: RS256, ES256, ES384, ES512
        /// </summary>
        public KeyAlgorithm KeyAlgorithm { get; set; } = KeyAlgorithm.ES256;

        /// <summary>
        /// The uri to the server that implements the ACME protocol for certificate generation.
        /// </summary>
        /// <param name="env"></param>
        internal Uri GetAcmeServer(IHostEnvironment env)
        {
            if (_acmeServer != null)
            {
                return _acmeServer;
            }

            return env.IsDevelopment()
                ? WellKnownServers.LetsEncryptStagingV2
                : WellKnownServers.LetsEncryptV2;
        }
    }
}
