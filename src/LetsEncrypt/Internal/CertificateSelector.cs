// Copyright (c) Nate McMaster.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore.Connections;
using Microsoft.Extensions.Options;

namespace McMaster.AspNetCore.LetsEncrypt.Internal
{
    internal class CertificateSelector
    {
        private readonly ConcurrentDictionary<string, X509Certificate2> _certs = new ConcurrentDictionary<string, X509Certificate2>(StringComparer.OrdinalIgnoreCase);
        private readonly ConcurrentDictionary<string, X509Certificate2> _challengeCerts = new ConcurrentDictionary<string, X509Certificate2>(StringComparer.OrdinalIgnoreCase);

        private readonly IOptions<LetsEncryptOptions> _options;

        public CertificateSelector(IOptions<LetsEncryptOptions> options)
        {
            _options = options ?? throw new ArgumentNullException(nameof(options));
        }

        public ICollection<string> SupportedDomains => _certs.Keys;

        public virtual void Add(X509Certificate2 certificate)
        {
            foreach (var dnsName in X509CertificateHelpers.GetAllDnsNames(certificate))
            {
                AddWithDomainName(_certs, dnsName, certificate);
            }
        }

        public void AddChallengeCert(X509Certificate2 certificate)
        {
            foreach (var dnsName in X509CertificateHelpers.GetAllDnsNames(certificate))
            {
                AddWithDomainName(_challengeCerts, dnsName, certificate);
            }
        }

        public void ClearChallengeCert(string domainName)
        {
            _challengeCerts.TryRemove(domainName, out _);
        }

        private static void AddWithDomainName(ConcurrentDictionary<string, X509Certificate2> certs, string domainName, X509Certificate2 certificate)
        {
            certs.AddOrUpdate(
                domainName,
                certificate,
                (_, currentCert) =>
                {
                    if (currentCert == null || certificate.NotAfter >= currentCert.NotAfter)
                    {
                        return certificate;
                    }

                    return currentCert;
                });
        }

        public bool HasCertForDomain(string domainName) => _certs.ContainsKey(domainName);

        public X509Certificate2? Select(ConnectionContext context, string? domainName)
        {
#if NETCOREAPP3_0
            if (_challengeCerts.Count > 0)
            {
                var sslStream = context.Features.Get<SslStream>();

                if (sslStream != null
                    && domainName != null
                    && sslStream.NegotiatedApplicationProtocol == TlsAlpnChallengeResponder.AcmeTlsProtocol
                    && _challengeCerts.TryGetValue(domainName, out var challengeCert))
                {
                    // Responds with a self-signed certificate to as a part of the TLS/ALPN challenge verification
                    return challengeCert;
                }
            }
#elif NETSTANDARD2_0
#else
#error Update TFMs
#endif

            if (domainName == null || !_certs.TryGetValue(domainName, out var retVal))
            {
                return _options.Value.FallbackCertificate;
            }

            return retVal;
        }

        public void Reset(string domainName)
        {
            _certs.TryRemove(domainName, out var _);
        }

        public bool TryGet(string domainName, out X509Certificate2? certificate)
        {
            return _certs.TryGetValue(domainName, out certificate);
        }
    }
}
