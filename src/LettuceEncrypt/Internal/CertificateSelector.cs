// Copyright (c) Nate McMaster.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore.Connections;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace LettuceEncrypt.Internal
{
    internal class CertificateSelector
    {
        private readonly ConcurrentDictionary<string, X509Certificate2> _certs = new ConcurrentDictionary<string, X509Certificate2>(StringComparer.OrdinalIgnoreCase);
        private readonly ConcurrentDictionary<string, X509Certificate2> _challengeCerts = new ConcurrentDictionary<string, X509Certificate2>(StringComparer.OrdinalIgnoreCase);

        private readonly IOptions<LettuceEncryptOptions> _options;
        private readonly ILogger<CertificateSelector> _logger;

        public CertificateSelector(IOptions<LettuceEncryptOptions> options, ILogger<CertificateSelector> logger)
        {
            _options = options ?? throw new ArgumentNullException(nameof(options));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
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

        private void AddWithDomainName(ConcurrentDictionary<string, X509Certificate2> certs, string domainName, X509Certificate2 certificate)
        {
            PreloadIntermediateCertificates(certificate);

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
                // var sslStream = context.Features.Get<SslStream>();
                // sslStream.NegotiatedApplicationProtocol hasn't been set yet, so we have to assume that
                // if ALPN challenge certs are configured, we must respond with those.

                if (domainName != null && _challengeCerts.TryGetValue(domainName, out var challengeCert))
                {
                    _logger.LogTrace("Using ALPN challenge cert for {domainName}", domainName);

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

        private void PreloadIntermediateCertificates(X509Certificate2 certificate)
        {
            // workaround for https://github.com/dotnet/aspnetcore/issues/21183
            using var chain = new X509Chain
            {
                ChainPolicy =
                {
                    RevocationMode = X509RevocationMode.NoCheck
                }
            };

            if (chain.Build(certificate))
            {
                _logger.LogTrace("Successfully built certificate chain");
            }
            else
            {
                _logger.LogWarning("Was not able to build certificate chain. This can cause an outage of your app.");
            }
        }
    }
}
