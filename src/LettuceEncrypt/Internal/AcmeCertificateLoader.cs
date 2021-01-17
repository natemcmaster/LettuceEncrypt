// Copyright (c) Nate McMaster.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using LettuceEncrypt.Internal.AcmeStates;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace LettuceEncrypt.Internal
{
    /// <summary>
    /// This starts the ACME state machine, which handles certificate generation and renewal
    /// </summary>
    internal class AcmeCertificateLoader : BackgroundService
    {
        private readonly IServiceScopeFactory _serviceScopeFactory;
        private readonly IOptions<LettuceEncryptOptions> _options;
        private readonly ILogger _logger;

        private readonly IServer _server;
        private readonly IConfiguration _config;

        public AcmeCertificateLoader(
            IServiceScopeFactory serviceScopeFactory,
            IOptions<LettuceEncryptOptions> options,
            ILogger<AcmeCertificateLoader> logger,
            IServer server,
            IConfiguration config)
        {
            _serviceScopeFactory = serviceScopeFactory;
            _options = options;
            _logger = logger;
            _server = server;
            _config = config;
        }

        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            if (!_server.GetType().Name.StartsWith(nameof(KestrelServer)))
            {
                var serverType = _server.GetType().FullName;
                _logger.LogWarning(
                    "LettuceEncrypt can only be used with Kestrel and is not supported on {serverType} servers. Skipping certificate provisioning.",
                    serverType);
                return;
            }

            if (_config.GetValue<bool>("UseIISIntegration"))
            {
                _logger.LogWarning(
                    "LettuceEncrypt does not work with apps hosting in IIS. IIS does not allow for dynamic HTTPS certificate binding." +
                    "Skipping certificate provisioning.");
                return;
            }

            // load certificates in the background
            if (!LettuceEncryptDomainNamesWereConfigured())
            {
                _logger.LogInformation("No domain names were configured");
                return;
            }

            using var acmeStateMachineScope = _serviceScopeFactory.CreateScope();

            try
            {
                IAcmeState state = acmeStateMachineScope.ServiceProvider.GetRequiredService<ServerStartupState>();

                while (!stoppingToken.IsCancellationRequested)
                {
                    _logger.LogTrace("ACME state transition: moving to {stateName}", state.GetType().Name);
                    state = await state.MoveNextAsync(stoppingToken);
                }
            }
            catch (OperationCanceledException)
            {
                _logger.LogDebug("State machine cancellation requested. Exiting...");
            }
            catch (AggregateException ex) when (ex.InnerException != null)
            {
                _logger.LogError(0, ex.InnerException, "ACME state machine encountered unhandled error");
            }
            catch (Exception ex)
            {
                _logger.LogError(0, ex, "ACME state machine encountered unhandled error");
            }
        }

        private bool LettuceEncryptDomainNamesWereConfigured()
        {
            return _options.Value.DomainNames
                .Any(w => !string.Equals("localhost", w, StringComparison.OrdinalIgnoreCase));
        }
    }
}
