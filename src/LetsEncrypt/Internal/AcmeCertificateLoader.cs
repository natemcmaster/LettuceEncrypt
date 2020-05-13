// Copyright (c) Nate McMaster.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using McMaster.AspNetCore.LetsEncrypt.Accounts;
using McMaster.AspNetCore.LetsEncrypt.Internal.IO;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

#if NETSTANDARD2_0
using IHostEnvironment = Microsoft.Extensions.Hosting.IHostingEnvironment;
using IHostApplicationLifetime = Microsoft.Extensions.Hosting.IApplicationLifetime;
#endif

namespace McMaster.AspNetCore.LetsEncrypt.Internal
{
    /// <summary>
    /// Loads certificates for all configured hostnames
    /// </summary>
    internal class AcmeCertificateLoader : BackgroundService
    {
        private readonly CertificateSelector _selector;
        private readonly IHttpChallengeResponseStore _challengeStore;
        private readonly IAccountStore? _accountStore;
        private readonly IOptions<LetsEncryptOptions> _options;
        private readonly ILogger _logger;

        private readonly IHostEnvironment _hostEnvironment;
        private readonly IServer _server;
        private readonly IConfiguration _config;
        private readonly TermsOfServiceChecker _tosChecker;
        private readonly IEnumerable<ICertificateRepository> _certificateRepositories;
        private readonly IClock _clock;
        private readonly IHostApplicationLifetime _applicationLifetime;
        private const string ErrorMessage = "Failed to create certificate";

        public AcmeCertificateLoader(
            CertificateSelector selector,
            IHttpChallengeResponseStore challengeStore,
            IOptions<LetsEncryptOptions> options,
            ILogger<AcmeCertificateLoader> logger,
            IHostEnvironment hostEnvironment,
            IServer server,
            IConfiguration config,
            TermsOfServiceChecker tosChecker,
            IEnumerable<ICertificateRepository> certificateRepositories,
            IClock clock,
            IHostApplicationLifetime applicationLifetime,
            IAccountStore? accountStore = default)
        {
            _selector = selector;
            _challengeStore = challengeStore;
            _accountStore = accountStore;
            _options = options;
            _logger = logger;
            _hostEnvironment = hostEnvironment;
            _server = server;
            _config = config;
            _tosChecker = tosChecker;
            _certificateRepositories = certificateRepositories;
            _clock = clock;
            _applicationLifetime = applicationLifetime;
        }

        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            if (!(_server is KestrelServer))
            {
                var serverType = _server.GetType().FullName;
                _logger.LogWarning("LetsEncrypt can only be used with Kestrel and is not supported on {serverType} servers. Skipping certificate provisioning.", serverType);
                return;
            }

            if (_config.GetValue<bool>("UseIISIntegration"))
            {
                _logger.LogWarning("LetsEncrypt does not work with apps hosting in IIS. IIS does not allow for dynamic HTTPS certificate binding, " +
                    "so if you want to use Let's Encrypt, you'll need to use a different tool to do so.");
                return;
            }

            // load certificates in the background

            if (!LetsEncryptDomainNamesWereConfigured())
            {
                _logger.LogInformation("No domain names were configured for Let's Encrypt");
                return;
            }

            await Task.Run(async () =>
            {
                try
                {
                    await LoadCerts(stoppingToken);
                }
                catch (AggregateException ex) when (ex.InnerException != null)
                {
                    _logger.LogError(0, ex.InnerException, ErrorMessage);
                }
                catch (Exception ex)
                {
                    _logger.LogError(0, ex, ErrorMessage);
                }

                await MonitorRenewal(stoppingToken);
            });
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

            var domainNames = _options.Value.DomainNames;
            var hasCertForAllDomains = domainNames.All(_selector.HasCertForDomain);
            if (hasCertForAllDomains)
            {
                _logger.LogDebug("Certificate for {domainNames} already found.", domainNames);
                return;
            }

            await CreateCertificateAsync(domainNames, cancellationToken);
        }

        private async Task CreateCertificateAsync(string[] domainNames, CancellationToken cancellationToken)
        {
            var factory = new CertificateFactory(
                _tosChecker,
                _options,
                _challengeStore,
                _accountStore,
                _logger,
                _hostEnvironment,
                _applicationLifetime);

            var account = await factory.GetOrCreateAccountAsync(cancellationToken);
            _logger.LogInformation("Using Let's Encrypt account {accountId}", account.Id);

            try
            {
                _logger.LogInformation("Creating certificate for {hostname} using ACME server {acmeServer}",
                    domainNames,
                    factory.AcmeServer);

                var cert = await factory.CreateCertificateAsync(cancellationToken);

                _logger.LogInformation("Created certificate {subjectName} ({thumbprint})", cert.Subject, cert.Thumbprint);

                await SaveCertificateAsync(cert, cancellationToken);
            }
            catch (Exception ex)
            {
                _logger.LogError(0, ex, "Failed to automatically create a certificate for {hostname}", domainNames);
                throw;
            }
        }

        private async Task SaveCertificateAsync(X509Certificate2 cert, CancellationToken cancellationToken)
        {
            _selector.Add(cert);

            var saveTasks = new List<Task>
            {
                Task.Delay(TimeSpan.FromMinutes(5), cancellationToken)
            };

            foreach (var repo in _certificateRepositories)
            {
                saveTasks.Add(repo.SaveAsync(cert, cancellationToken));
            }

            await Task.WhenAll(saveTasks);
        }

        private async Task MonitorRenewal(CancellationToken cancellationToken)
        {
            while (!cancellationToken.IsCancellationRequested)
            {
                var checkPeriod = _options.Value.RenewalCheckPeriod;
                var daysInAdvance = _options.Value.RenewDaysInAdvance;
                if (!checkPeriod.HasValue || !daysInAdvance.HasValue)
                {
                    _logger.LogInformation("Automatic Let's Encrypt certificate renewal is not configured. Stopping {service}",
                        nameof(AcmeCertificateLoader));
                    return;
                }

                try
                {
                    var domainNames = _options.Value.DomainNames;
                    _logger.LogDebug("Checking certificates' renewals for {hostname}",
                        domainNames);

                    foreach (var domainName in domainNames)
                    {
                        if (!_selector.TryGet(domainName, out var cert)
                            || cert == null
                            || cert.NotAfter <= _clock.Now.DateTime + daysInAdvance.Value)
                        {
                            await CreateCertificateAsync(domainNames, cancellationToken);
                            break;
                        }
                    }
                }
                catch (AggregateException ex) when (ex.InnerException != null)
                {
                    _logger.LogError(0, ex.InnerException, ErrorMessage);
                }
                catch (Exception ex)
                {
                    _logger.LogError(0, ex, ErrorMessage);
                }

                await Task.Delay(checkPeriod.Value, cancellationToken);
            }
        }
    }
}
