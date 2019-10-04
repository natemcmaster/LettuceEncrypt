// Copyright (c) Nate McMaster.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

#if NETSTANDARD2_0
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
        private readonly ICertificateStore _certificateStore;
        private readonly CertificateFactory _factory;
        private readonly IOptions<LetsEncryptOptions> _options;
        private readonly ILogger<AcmeCertificateLoader> _logger;

        private readonly IHostEnvironment _hostEnvironment;
        private readonly IServer _server;
        private readonly IConfiguration _config;
        private volatile bool _hasRegistered;

        public AcmeCertificateLoader(
            CertificateSelector selector,
            ICertificateStore certificateStore,
            CertificateFactory factory,
            IOptions<LetsEncryptOptions> options,
            ILogger<AcmeCertificateLoader> logger,
            IHostEnvironment hostEnvironment,
            IServer server,
            IConfiguration config)
        {
            _selector = selector;
            _certificateStore = certificateStore;
            _factory = factory;
            _options = options;
            _logger = logger;
            _hostEnvironment = hostEnvironment;
            _server = server;
            _config = config;
        }

        public Task StopAsync(CancellationToken cancellationToken)
            => Task.CompletedTask;

        public Task StartAsync(CancellationToken cancellationToken)
        {
            if (!(_server is KestrelServer))
            {
                var serverType = _server.GetType().FullName;
                _logger.LogWarning("LetsEncrypt can only be used with Kestrel and is not supported on {serverType} servers. Skipping certificate provisioning.", serverType);
                return Task.CompletedTask;
            }

            if (_config.GetValue<bool>("UseIISIntegration"))
            {
                _logger.LogWarning("LetsEncrypt does not work with apps hosting in IIS. IIS does not allow for dynamic HTTPS certificate binding, " +
                    "so if you want to use Let's Encrypt, you'll need to use a different tool to do so.");
                return Task.CompletedTask;
            }

            // load certificates in the background

            if (!LetsEncryptDomainNamesWereConfigured())
            {
                _logger.LogInformation("No domain names were configured for Let's Encrypt");
                return Task.CompletedTask;
            }

            Task.Factory.StartNew(async () =>
            {
                const string ErrorMessage = "Failed to create certificate";

                try
                {
                    await LoadCerts(cancellationToken);
                }
                catch (AggregateException ex) when (ex.InnerException != null)
                {
                    _logger.LogError(0, ex.InnerException, ErrorMessage);
                }
                catch (Exception ex)
                {
                    _logger.LogError(0, ex, ErrorMessage);
                }
            });

            return Task.CompletedTask;
        }

        private bool LetsEncryptDomainNamesWereConfigured()
        {
            return _options.Value.DomainNames
                .Where(w => !string.Equals("localhost", w, StringComparison.OrdinalIgnoreCase))
                .Any();
        }

        private async Task LoadCerts(CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            var errors = new List<Exception>();

            try
            {
                var cert = await GetOrCreateCertificate(cancellationToken);
                foreach (var domainName in _options.Value.DomainNames)
                {
                    _selector.Use(domainName, cert);
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

        private async Task<X509Certificate2> GetOrCreateCertificate(CancellationToken cancellationToken)
        {
            var domainName = _options.Value.DomainNames[0];
            var cert = _certificateStore.GetCertificate(domainName);
            if (cert != null)
            {
                _logger.LogDebug("Certificate for {hostname} already found.", domainName);
                return cert;
            }

            if (!_hasRegistered)
            {
                _hasRegistered = true;
                await _factory.RegisterUserAsync(cancellationToken);
            }

            try
            {
                _logger.LogInformation("Creating certificate for {hostname} using ACME server {acmeServer}", domainName, _options.Value.GetAcmeServer(_hostEnvironment));
                cert = await _factory.CreateCertificateAsync(cancellationToken);
                _logger.LogInformation("Created certificate {subjectName} ({thumbprint})", cert.Subject, cert.Thumbprint);
                _certificateStore.Save(domainName, cert);
                return cert;
            }
            catch (Exception ex)
            {
                _logger.LogError(0, ex, "Failed to automatically create a certificate for {hostname}", domainName);
                throw;
            }
        }
    }
}
