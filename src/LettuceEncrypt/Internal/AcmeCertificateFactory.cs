// Copyright (c) Nate McMaster.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using Certes;
using Certes.Acme;
using Certes.Acme.Resource;
using LettuceEncrypt.Internal.AcmeStates;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

#if NETSTANDARD2_0
using IHostApplicationLifetime = Microsoft.Extensions.Hosting.IApplicationLifetime;
#endif

namespace LettuceEncrypt.Internal
{
    internal class AcmeCertificateFactory
    {
        private readonly IOptions<LettuceEncryptOptions> _options;
        private readonly IHttpChallengeResponseStore _challengeStore;
        private readonly ILogger _logger;
        private readonly TlsAlpnChallengeResponder _tlsAlpnChallengeResponder;
        private readonly TaskCompletionSource<object?> _appStarted;

        public AcmeCertificateFactory(
            IOptions<LettuceEncryptOptions> options,
            IHttpChallengeResponseStore challengeStore,
            ILogger logger,
            IHostApplicationLifetime appLifetime,
            TlsAlpnChallengeResponder tlsAlpnChallengeResponder)
        {
            _options = options;
            _challengeStore = challengeStore;
            _logger = logger;
            _tlsAlpnChallengeResponder = tlsAlpnChallengeResponder;

            _appStarted = new TaskCompletionSource<object?>();
            appLifetime.ApplicationStarted.Register(() => _appStarted.TrySetResult(null));
            if (appLifetime.ApplicationStarted.IsCancellationRequested)
            {
                _appStarted.TrySetResult(null);
            }
        }

        public async Task<X509Certificate2> CreateCertificateAsync(AcmeStateMachineContext context,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            IOrderContext? orderContext = null;
            var orders = await context.Client.GetOrdersAsync(context.Account);
            if (orders.Any())
            {
                var expectedDomains = new HashSet<string>(_options.Value.DomainNames);
                foreach (var order in orders)
                {
                    var orderDetails = await context.Client.GetOrderDetailsAsync(order);
                    if (orderDetails.Status != OrderStatus.Pending)
                    {
                        continue;
                    }

                    var orderDomains = orderDetails
                        .Identifiers
                        .Where(i => i.Type == IdentifierType.Dns)
                        .Select(s => s.Value);

                    if (expectedDomains.SetEquals(orderDomains))
                    {
                        _logger.LogDebug("Found an existing order for a certificate");
                        orderContext = order;
                        break;
                    }
                }
            }

            if (orderContext == null)
            {
                _logger.LogDebug("Creating new order for a certificate");
                orderContext = await context.Client.CreateOrderAsync(_options.Value.DomainNames);
            }

            cancellationToken.ThrowIfCancellationRequested();
            var authorizations = await context.Client.GetOrderAuthorizations(orderContext);

            cancellationToken.ThrowIfCancellationRequested();
            await Task.WhenAll(BeginValidateAllAuthorizations(context, authorizations, cancellationToken));

            cancellationToken.ThrowIfCancellationRequested();
            return await CompleteCertificateRequestAsync(context, orderContext, cancellationToken);
        }

        private IEnumerable<Task> BeginValidateAllAuthorizations(AcmeStateMachineContext context,
            IEnumerable<IAuthorizationContext> authorizations,
            CancellationToken cancellationToken)
        {
            foreach (var authorization in authorizations)
            {
                yield return ValidateDomainOwnershipAsync(context, authorization, cancellationToken);
            }
        }

        private async Task ValidateDomainOwnershipAsync(AcmeStateMachineContext context,
            IAuthorizationContext authorizationContext,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            var authorization = await context.Client.GetAuthorizationAsync(authorizationContext);
            var domainName = authorization.Identifier.Value;

            if (authorization.Status == AuthorizationStatus.Valid)
            {
                // Short circuit if authorization is already complete
                return;
            }

            _logger.LogDebug("Requesting authorization to create certificate for {domainName}", domainName);

            cancellationToken.ThrowIfCancellationRequested();

            if (_tlsAlpnChallengeResponder.IsEnabled)
            {
                await PrepareTlsAlpnChallengeResponseAsync(context, authorizationContext, domainName,
                    cancellationToken);
            }

            await PrepareHttpChallengeResponseAsync(context, authorizationContext, domainName, cancellationToken);

            var retries = 60;
            var delay = TimeSpan.FromSeconds(2);

            try
            {
                while (retries > 0)
                {
                    retries--;

                    cancellationToken.ThrowIfCancellationRequested();

                    authorization = await context.Client.GetAuthorizationAsync(authorizationContext);

                    _logger.LogAcmeAction("GetAuthorization");

                    switch (authorization.Status)
                    {
                        case AuthorizationStatus.Valid:
                            return;
                        case AuthorizationStatus.Pending:
                            await Task.Delay(delay, cancellationToken);
                            continue;
                        case AuthorizationStatus.Invalid:
                            throw InvalidAuthorizationError(authorization);
                        case AuthorizationStatus.Revoked:
                            throw new InvalidOperationException(
                                $"The authorization to verify domainName '{domainName}' has been revoked.");
                        case AuthorizationStatus.Expired:
                            throw new InvalidOperationException(
                                $"The authorization to verify domainName '{domainName}' has expired.");
                        default:
                            throw new ArgumentOutOfRangeException("authorization",
                                "Unexpected response from server while validating domain ownership.");
                    }
                }

                throw new TimeoutException("Timed out waiting for domain ownership validation.");
            }
            finally
            {
                if (_tlsAlpnChallengeResponder.IsEnabled)
                {
                    // cleanup after authorization is done to skip unnecessary cert lookup on all incoming SSL connections
                    _tlsAlpnChallengeResponder.DiscardChallenge(domainName);
                }
            }
        }

        private async Task PrepareHttpChallengeResponseAsync(
            AcmeStateMachineContext context,
            IAuthorizationContext authorizationContext,
            string domainName,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            var httpChallenge = await context.Client.CreateChallengeAsync(authorizationContext, ChallengeTypes.Http01);
            if (httpChallenge == null)
            {
                throw new InvalidOperationException(
                    $"Did not receive challenge information for challenge type {ChallengeTypes.Http01}");
            }

            var keyAuth = httpChallenge.KeyAuthz;
            _challengeStore.AddChallengeResponse(httpChallenge.Token, keyAuth);

            _logger.LogTrace("Waiting for server to start accepting HTTP requests");
            await _appStarted.Task;

            _logger.LogTrace("Requesting server to validate HTTP challenge");
            await context.Client.ValidateChallengeAsync(httpChallenge);
        }

        private async Task PrepareTlsAlpnChallengeResponseAsync(
            AcmeStateMachineContext context,
            IAuthorizationContext authorizationContext,
            string domainName,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            var tlsAlpnChallenge =
                await context.Client.CreateChallengeAsync(authorizationContext, ChallengeTypes.TlsAlpn01);

            _tlsAlpnChallengeResponder.PrepareChallengeCert(domainName, tlsAlpnChallenge.KeyAuthz);

            _logger.LogTrace("Waiting for server to start accepting HTTP requests");
            await _appStarted.Task;

            _logger.LogTrace("Requesting server to validate TLS/ALPN challenge");
            await context.Client.ValidateChallengeAsync(tlsAlpnChallenge);
        }

        private Exception InvalidAuthorizationError(Authorization authorization)
        {
            var reason = "unknown";
            var domainName = authorization.Identifier.Value;
            try
            {
                var errors = authorization.Challenges.Where(a => a.Error != null).Select(a => a.Error)
                    .Select(error => $"{error.Type}: {error.Detail}, Code = {error.Status}");
                reason = string.Join("; ", errors);
            }
            catch
            {
                _logger.LogTrace("Could not determine reason why validation failed. Response: {resp}", authorization);
            }

            _logger.LogError("Failed to validate ownership of domainName '{domainName}'. Reason: {reason}", domainName,
                reason);

            return new InvalidOperationException($"Failed to validate ownership of domainName '{domainName}'");
        }

        private async Task<X509Certificate2> CompleteCertificateRequestAsync(AcmeStateMachineContext context,
            IOrderContext order,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            var commonName = _options.Value.DomainNames[0];
            _logger.LogDebug("Creating cert for {commonName}", commonName);

            var csrInfo = new CsrInfo
            {
                CommonName = commonName,
            };
            var privateKey = KeyFactory.NewKey((Certes.KeyAlgorithm) _options.Value.KeyAlgorithm);
            var acmeCert = await context.Client.GetCertificateAsync(csrInfo, privateKey, order);

            _logger.LogAcmeAction("NewCertificate");

            var pfxBuilder = acmeCert.ToPfx(privateKey);
            var pfx = pfxBuilder.Build("HTTPS Cert - " + _options.Value.DomainNames, string.Empty);
            return new X509Certificate2(pfx, string.Empty, X509KeyStorageFlags.Exportable);
        }
    }
}
