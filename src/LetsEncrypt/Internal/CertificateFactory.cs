// Copyright (c) Nate McMaster.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using Certes;
using Certes.Acme;
using Certes.Acme.Resource;
using Certes.Pkcs;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Newtonsoft.Json;

namespace McMaster.AspNetCore.LetsEncrypt.Internal
{
    internal class CertificateFactory : IDisposable
    {
        private readonly IOptions<LetsEncryptOptions> _options;
        private readonly IHttpChallengeResponseStore _challengeStore;
        private readonly ILogger _logger;
        private readonly AcmeClient _client;

        public CertificateFactory(IOptions<LetsEncryptOptions> options,
            IHttpChallengeResponseStore challengeStore,
            ILogger logger)
        {
            _options = options;
            _challengeStore = challengeStore;
            _logger = logger;
            _client = new AcmeClient(_options.Value.AcmeServer);
        }

        public async Task RegisterUserAsync(CancellationToken cancellationToken)
        {
            var options = _options.Value;
            var registration = "mailto:" + options.EmailAddress;

            _logger.LogInformation("Creating certificate registration for {registration}", registration);
            var account = await _client.NewRegistraton(registration);
            _logger.LogResponse("NewRegistration", account);

            var tosUri = account.GetTermsOfServiceUri();
            account.Data.Agreement = tosUri;
            EnsureAgreementToTermsOfServices(options, tosUri);

            cancellationToken.ThrowIfCancellationRequested();
            _logger.LogDebug("Accepting the terms of service");
            account = await _client.UpdateRegistration(account);
            _logger.LogResponse("UpdateRegistration", account);
        }

        public async Task<X509Certificate2> CreateCertificateAsync(string hostName, CancellationToken cancellationToken)
        {
            await ValidateDomainOwnershipAsync(hostName, cancellationToken);
            return await CompleteCertificateRequestAsync(hostName, cancellationToken);
        }

        private void EnsureAgreementToTermsOfServices(LetsEncryptOptions options, Uri tosUri)
        {
            if (options.AcceptTermsOfService)
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
                if (string.IsNullOrEmpty(result)
                    || string.Equals("y", result, StringComparison.OrdinalIgnoreCase))
                {
                    return;
                }
            }

            _logger.LogError($"You must accept the terms of service to continue.");
            throw new InvalidOperationException("Could not automatically accept the terms of service");
        }

        private async Task ValidateDomainOwnershipAsync(string hostName, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            _logger.LogDebug("Requesting authorization to create certificates for {hostname}", hostName);
            var auth = await _client.NewAuthorization(new AuthorizationIdentifier
            {
                Type = AuthorizationIdentifierTypes.Dns,
                Value = hostName,
            });
            _logger.LogResponse("NewAuthorization", auth);

            cancellationToken.ThrowIfCancellationRequested();

            var httpChallenge = auth.Data.Challenges.FirstOrDefault(c => c.Type == ChallengeTypes.Http01);

            if (httpChallenge == null)
            {
                throw new InvalidOperationException($"Did not receive challenge information for challenge type {ChallengeTypes.Http01}");
            }

            var keyAuth = _client.ComputeKeyAuthorization(httpChallenge);
            _challengeStore.AddChallengeResponse(httpChallenge.Token, keyAuth);

            cancellationToken.ThrowIfCancellationRequested();

            _logger.LogDebug("Requesting completion of challenge to prove ownership of {hostname}", hostName);

            var challengeCompletion = await _client.CompleteChallenge(httpChallenge);

            _logger.LogResponse("CompleteChallenge", challengeCompletion);

            var retries = 60;
            var delay = TimeSpan.FromSeconds(2);

            AcmeResult<AuthorizationEntity> authorization;

            while (retries > 0)
            {
                retries--;

                cancellationToken.ThrowIfCancellationRequested();

                authorization = await _client.GetAuthorization(challengeCompletion.Location);

                _logger.LogResponse("GetAuthorization", authorization);

                switch (authorization.Data.Status)
                {
                    case EntityStatus.Valid:
                        return;
                    case EntityStatus.Pending:
                    case EntityStatus.Processing:
                        await Task.Delay(delay);
                        continue;
                    case EntityStatus.Invalid:
                        throw InvalidAuthorizationError(hostName, authorization);
                    case EntityStatus.Revoked:
                        throw new InvalidOperationException($"The authorization to verify hostname '{hostName}' has been revoked.");
                    case EntityStatus.Unknown:
                    default:
                        throw new ArgumentOutOfRangeException("Unexpected response from server while validating domain ownership.");
                }
            }

            throw new TimeoutException("Timed out waiting for domain ownership validation.");
        }

        private Exception InvalidAuthorizationError(string hostName, AcmeResult<AuthorizationEntity> authorization)
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

            _logger.LogError("Failed to validate ownership of hostname '{hostName}'. Reason: {reason}", hostName, reason);

            return new InvalidOperationException($"Failed to validate ownership of hostname '{hostName}'");
        }

        private async Task<X509Certificate2> CompleteCertificateRequestAsync(string hostName, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            var csr = new CertificationRequestBuilder();
            var dn = "CN=" + hostName;
            csr.AddName(dn);

            _logger.LogInformation("Sending certifcate request for '{dn}'", dn);

            var cert = await _client.NewCertificate(csr);

            _logger.LogResponse("NewCertificate", cert);

            var pfx = cert.ToPfx().Build(hostName, string.Empty);
            return new X509Certificate2(pfx, string.Empty, X509KeyStorageFlags.Exportable);
        }

        public void Dispose()
        {
            _client.Dispose();
        }
    }
}
