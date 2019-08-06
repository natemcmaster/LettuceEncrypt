// Copyright (c) Nate McMaster.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

#if NETCOREAPP2_1
using IHostEnvironment = Microsoft.Extensions.Hosting.IHostingEnvironment;
#endif

namespace McMaster.AspNetCore.LetsEncrypt.Internal
{
    /// <summary>
    /// Loads certificates for all configured hostnames
    /// </summary>
    internal class AcmeCertificateLoader : IHostedService
    {
        private readonly CertificateSelector _selector;
        private readonly IHttpChallengeResponseStore _challengeStore;
        private readonly ICertificateStore _certificateStore;
        private readonly IOptions<LetsEncryptOptions> _options;
        private readonly ILogger<AcmeCertificateLoader> _logger;

        private readonly IHostEnvironment _hostEnvironment;
        private volatile bool _hasRegistered;

        public AcmeCertificateLoader(
            CertificateSelector selector,
            IHttpChallengeResponseStore challengeStore,
            ICertificateStore certificateStore,
            IOptions<LetsEncryptOptions> options,
            ILogger<AcmeCertificateLoader> logger,
            IHostEnvironment hostEnvironment)
        {
            _selector = selector;
            _challengeStore = challengeStore;
            _certificateStore = certificateStore;
            _options = options;
            _logger = logger;
            _hostEnvironment = hostEnvironment;
        }

        public Task StopAsync(CancellationToken cancellationToken)
            => Task.CompletedTask;

        public Task StartAsync(CancellationToken cancellationToken)
        {
            // load certificates in the background

            Task.Factory.StartNew(async () =>
            {
                const string errorMessage = "Failed to create certificate";

                try
                {
                    await LoadCerts(cancellationToken);
                }
                catch (AggregateException ex) when (ex.InnerException != null)
                {
                    _logger.LogError(0, ex.InnerException, errorMessage);
                }
                catch (Exception ex)
                {
                    _logger.LogError(0, ex, errorMessage);
                }
            });

            return Task.CompletedTask;
        }

        private async Task LoadCerts(CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            var errors = new List<Exception>();

            using var factory = new CertificateFactory(_options, _challengeStore, _logger, _hostEnvironment);

            try
            {
                var cert = await GetOrCreateCertificate(factory, cancellationToken);
                foreach (var hostName in _options.Value.HostNames)
                {
                    _selector.Use(hostName, cert);
                }
            }
            catch (Exception ex)
            {
                errors.Add(ex);
            }

            if (errors.Count > 0)
            {
                throw new AggregateException(errors);
            }
        }

        private async Task<X509Certificate2> GetOrCreateCertificate(CertificateFactory factory, CancellationToken cancellationToken)
        {
            var hostName = _options.Value.HostNames[0];
            var cert = _certificateStore.GetCertificate(hostName);
            if (cert != null)
            {
                _logger.LogDebug("Certificate for {hostname} already found.", hostName);
                return cert;
            }

            if (!_hasRegistered)
            {
                _hasRegistered = true;
                await factory.RegisterUserAsync(cancellationToken);
            }

            try
            {
                _logger.LogInformation("Creating certificate for {hostname} using ACME server {acmeServer}", hostName, _options.Value.GetAcmeServer(_hostEnvironment));
                cert = await factory.CreateCertificateAsync(cancellationToken);
                _logger.LogInformation("Created certificate {subjectName} ({thumbprint})", cert.Subject, cert.Thumbprint);
                _certificateStore.Save(hostName, cert);
                return cert;
            }
            catch (Exception ex)
            {
                _logger.LogError(0, ex, "Failed to automatically create a certificate for {hostname}", hostName);
                throw;
            }
        }
    }
}
