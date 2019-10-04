﻿// Copyright (c) Nate McMaster.
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
using Certes.Pkcs;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Newtonsoft.Json;

#if NETSTANDARD2_0
using IHostEnvironment = Microsoft.Extensions.Hosting.IHostingEnvironment;
#endif

namespace McMaster.AspNetCore.LetsEncrypt.Internal
{
    internal class CertificateFactory
    {
        private readonly IOptions<LetsEncryptOptions> _options;
        private readonly IHttpChallengeResponseStore _challengeStore;
        private readonly ILogger _logger;
        private readonly AcmeContext _context;
        private IAccountContext? _account;

        public CertificateFactory(
            IOptions<LetsEncryptOptions> options,
            IHttpChallengeResponseStore challengeStore,
            ILogger logger,
            IHostEnvironment env)
        {
            _options = options;
            _challengeStore = challengeStore;
            _logger = logger;
            var acmeUrl = _options.Value.GetAcmeServer(env);
            _context = new AcmeContext(acmeUrl);
        }

        public async Task RegisterUserAsync(CancellationToken cancellationToken)
        {
            var options = _options.Value;

            var tosUri = await _context.TermsOfService();
            EnsureAgreementToTermsOfServices(tosUri);

            _logger.LogDebug("Terms of service has been accepted");

            cancellationToken.ThrowIfCancellationRequested();

            _logger.LogInformation("Creating certificate registration for {email}", options.EmailAddress);
            _account = await _context.NewAccount(options.EmailAddress, termsOfServiceAgreed: true);
            _logger.LogResource("NewRegistration", _account);

        }

        public async Task<X509Certificate2> CreateCertificateAsync(CancellationToken cancellationToken)
        {
            var order = await _context.NewOrder(_options.Value.DomainNames);

            cancellationToken.ThrowIfCancellationRequested();
            var authorizations = await order.Authorizations();

            cancellationToken.ThrowIfCancellationRequested();
            await Task.WhenAll(BeginValidateAllAuthorizations(authorizations, cancellationToken));

            cancellationToken.ThrowIfCancellationRequested();
            return await CompleteCertificateRequestAsync(order, cancellationToken);
        }

        private IEnumerable<Task> BeginValidateAllAuthorizations(IEnumerable<IAuthorizationContext> authorizations, CancellationToken cancellationToken)
        {
            foreach (var authorization in authorizations)
            {
                yield return ValidateDomainOwnershipAsync(authorization, cancellationToken);
            }
        }

        private void EnsureAgreementToTermsOfServices(Uri tosUri)
        {
            if (_options.Value.AcceptTermsOfService)
            {
                return;
            }

            if (!Console.IsInputRedirected)
            {
                Console.BackgroundColor = ConsoleColor.DarkBlue;
                Console.ForegroundColor = ConsoleColor.White;
                Console.WriteLine("By proceeding, you must agree with Let's Encrypt terms of services.");
                Console.WriteLine(tosUri);
                Console.Write("Do you accept? [Y/n] ");
                Console.ResetColor();
                try
                {
                    Console.CursorVisible = true;
                }
                catch { }

                var result = Console.ReadLine().Trim();

                try
                {
                    Console.CursorVisible = false;
                }
                catch { }

                if (string.IsNullOrEmpty(result)
                    || string.Equals("y", result, StringComparison.OrdinalIgnoreCase))
                {
                    return;
                }
            }

            _logger.LogError($"You must accept the terms of service to continue.");
            throw new InvalidOperationException("Could not automatically accept the terms of service");
        }

        private async Task ValidateDomainOwnershipAsync(IAuthorizationContext authorization, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            var httpChallenge = await authorization.Http();

            cancellationToken.ThrowIfCancellationRequested();

            if (httpChallenge == null)
            {
                throw new InvalidOperationException($"Did not receive challenge information for challenge type {ChallengeTypes.Http01}");
            }

            var keyAuth = httpChallenge.KeyAuthz;
            _challengeStore.AddChallengeResponse(httpChallenge.Token, keyAuth);

            cancellationToken.ThrowIfCancellationRequested();

            _logger.LogDebug("Requesting completion of challenge to prove ownership of domain");

            var challange = await httpChallenge.Validate();

            var retries = 60;
            var delay = TimeSpan.FromSeconds(2);

            //AcmeResult<AuthorizationEntity> authorization;

            while (retries > 0)
            {
                retries--;

                cancellationToken.ThrowIfCancellationRequested();

                var resource = await authorization.Resource();

                _logger.LogDebug("GetAuthorization", resource);

                switch (resource.Status)
                {
                    case AuthorizationStatus.Valid:
                        return;
                    case AuthorizationStatus.Pending:
                        await Task.Delay(delay);
                        continue;
                    case AuthorizationStatus.Invalid:
                        //throw InvalidAuthorizationError(domainName, authorization);
                        throw new InvalidOperationException($"Failed to validate ownership of domainName");
                    case AuthorizationStatus.Revoked:
                        throw new InvalidOperationException($"The authorization to verify domainName has been revoked.");
                    case AuthorizationStatus.Expired:
                        throw new InvalidOperationException($"The authorization to verify domainName has expired.");
                    default:
                        throw new ArgumentOutOfRangeException("Unexpected response from server while validating domain ownership.");
                }
            }

            throw new TimeoutException("Timed out waiting for domain ownership validation.");
        }

        private Exception InvalidAuthorizationError(string domainName, AcmeResult<AuthorizationEntity> authorization)
        {
            var reason = "unknown";
            try
            {
                var errorStub = new { error = new { type = "", detail = "", status = -1 } };
                var data = JsonConvert.DeserializeAnonymousType(authorization.Json, errorStub);
                reason = $"{data.error.type}: {data.error.detail}, Code = {data.error.status}";
            }
            catch
            {
                _logger.LogTrace("Could not determine reason why validation failed. Response: {resp}", authorization.Json);
            }

            _logger.LogError("Failed to validate ownership of domainName '{domainName}'. Reason: {reason}", domainName, reason);

            return new InvalidOperationException($"Failed to validate ownership of domainName '{domainName}'");
        }

        private async Task<X509Certificate2> CompleteCertificateRequestAsync(IOrderContext order, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var commonName = _options.Value.DomainNames[0];
            _logger.LogDebug("Creating cert for {commonName}", commonName);

            var csrInfo = new CsrInfo
            {
                CommonName = commonName,
            };
            var privateKey = KeyFactory.NewKey(KeyAlgorithm.ES256);
            var acmeCert = await order.Generate(csrInfo, privateKey);


            _logger.LogDebug("NewCertificate", acmeCert);

            var pfxBuilder = acmeCert.ToPfx(privateKey);
            var pfx = pfxBuilder.Build("Let's Encrypt - " + _options.Value.DomainNames, string.Empty);
            return new X509Certificate2(pfx, string.Empty, X509KeyStorageFlags.Exportable);
        }
    }
}
