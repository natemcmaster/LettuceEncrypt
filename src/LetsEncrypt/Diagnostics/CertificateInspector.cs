// Copyright (c) Nate McMaster.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography.X509Certificates;
using McMaster.AspNetCore.LetsEncrypt.Internal;

namespace McMaster.AspNetCore.LetsEncrypt.Diagnostics
{
    /// <summary>
    /// Provides methods for inspecting the current state of the certificate configuration.
    /// </summary>
    public class CertificateInspector
    {
        private readonly CertificateSelector _selector;

        internal CertificateInspector(CertificateSelector selector)
        {
            _selector = selector;
        }

        /// <summary>
        /// Returns the certificate that is configured for a particular domain name.
        /// </summary>
        /// <param name="domainName">The domain name.</param>
        /// <param name="certificate">The certificate object, if found.</param>
        /// <returns>Whether or not a certificate was found for a given domain name.</returns>
        public bool TryGetCertByDomainName(
            string domainName,
            [MaybeNullWhen(false)]
            out X509Certificate2? certificate)
        {
            if (string.IsNullOrEmpty(domainName))
            {
                certificate = null;
                return false;
            }

            return _selector.TryGetCert(domainName, out certificate);
        }
    }
}
