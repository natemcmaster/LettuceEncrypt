// Copyright (c) Nate McMaster.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using System.Security.Cryptography.X509Certificates;
using Certes.Acme;

namespace McMaster.AspNetCore.LetsEncrypt
{
    /// <summary>
    /// Options for configuring Let's Encrypt to automatically generate HTTPS certificates.
    /// </summary>
    public class LetsEncryptOptions
    {
        private string[] _hostNames = Array.Empty<string>();

        /// <summary>
        /// Initialize an instance of <see cref="LetsEncryptOptions" />
        /// </summary>
        public LetsEncryptOptions()
        {
            // Default to the production server.
            AcmeServer = WellKnownServers.LetsEncrypt;
        }

        /// <summary>
        /// The domain names for which to generate certificates.
        /// </summary>
        public string[] HostNames
        {
            get => _hostNames;
            set => _hostNames = value ?? throw new ArgumentNullException(nameof(value));
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
        public string EmailAddress { get; set; }

        /// <summary>
        /// Use Let's Encrypt staging server.
        /// <para>
        /// This is recommended during development of the application.
        /// </para>
        /// </summary>
        public bool UseStagingServer
        {
            get => AcmeServer == WellKnownServers.LetsEncryptStaging;
            set => AcmeServer = value
                    ? WellKnownServers.LetsEncryptStaging
                    : WellKnownServers.LetsEncrypt;
        }

        /// <summary>
        /// A certificate to use if a certifcates cannot be created automatically.
        /// <para>
        /// This can be null if there is not fallback certificate.
        /// </para>
        /// </summary>
        public X509Certificate2 FallbackCertificate { get; set; }

        /// <summary>
        /// The uri to the server that implements thE ACME protocol for certificate generation.
        /// </summary>
        internal Uri AcmeServer { get; set; }
    }
}
