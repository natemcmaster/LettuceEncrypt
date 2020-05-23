// Copyright (c) Nate McMaster.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace LettuceEncrypt.Internal
{
    internal class X509CertStore : ICertificateSource, ICertificateRepository, IDisposable
    {
        private readonly X509Store _store;
        private readonly IOptions<LettuceEncryptOptions> _options;
        private readonly ILogger<X509CertStore> _logger;

        public bool AllowInvalidCerts { get; set; }

        public X509CertStore(IOptions<LettuceEncryptOptions> options, ILogger<X509CertStore> logger)
        {
            _store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
            _store.Open(OpenFlags.ReadWrite);
            _options = options;
            _logger = logger;
        }

        public Task<IEnumerable<X509Certificate2>> GetCertificatesAsync(CancellationToken cancellationToken)
        {
            var domainNames = new HashSet<string>(_options.Value.DomainNames);
            var result = new List<X509Certificate2>();
            var certs = _store.Certificates.Find(X509FindType.FindByTimeValid,
                DateTime.Now,
                validOnly: !AllowInvalidCerts);

            foreach (var cert in certs)
            {
                if (!cert.HasPrivateKey)
                {
                    continue;
                }

                foreach (var dnsName in X509CertificateHelpers.GetAllDnsNames(cert))
                {
                    if (domainNames.Contains(dnsName))
                    {
                        result.Add(cert);
                        break;
                    }
                }
            }

            return Task.FromResult(result.AsEnumerable());
        }

        public Task SaveAsync(X509Certificate2 certificate, CancellationToken cancellationToken)
        {
            try
            {
                _store.Add(certificate);
            }
            catch (Exception ex)
            {
                _logger.LogError(0, ex, "Failed to save certificate to store");
                throw;
            }

            return Task.CompletedTask;
        }

        public void Dispose()
        {
            _store.Close();
        }
    }
}
