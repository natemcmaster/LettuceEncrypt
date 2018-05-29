// Copyright (c) Nate McMaster.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Logging;

namespace McMaster.AspNetCore.LetsEncrypt.Internal
{
    internal class X509CertStore : ICertificateStore, IDisposable
    {
        private readonly X509Store _store;
        private readonly ILogger<X509CertStore> _logger;

        public X509CertStore(ILogger<X509CertStore> logger)
        {
            _store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
            _store.Open(OpenFlags.ReadWrite);
            this._logger = logger;
        }

        public X509Certificate2 GetCertificate(string hostName)
        {
            var certs = _store.Certificates.Find(
                X509FindType.FindBySubjectDistinguishedName,
                "CN=" + hostName,
                validOnly: true);

            if (_logger.IsEnabled(LogLevel.Trace))
            {
                foreach (var cert in certs)
                {
                    _logger.LogTrace("Found certificate {subject}", cert.SubjectName.Name);
                }
            }

            return certs.Count > 0
                ? certs[0]
                : null;
        }

        public void Save(string hostName, X509Certificate2 certificate)
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
        }

        public void Dispose()
        {
            _store.Close();
        }
    }
}
