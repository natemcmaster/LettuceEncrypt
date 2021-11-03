// Copyright (c) Nate McMaster.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Certes;
using Certes.Acme;
using Certes.Acme.Resource;
using LettuceEncrypt.Accounts;
using LettuceEncrypt.Acme;
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
        private readonly AcmeClientFactory _acmeClientFactory;
        private readonly TermsOfServiceChecker _tosChecker;
        private readonly IOptions<LettuceEncryptOptions> _options;
        private readonly IHttpChallengeResponseStore _challengeStore;
        private readonly IAccountStore _accountRepository;
        private readonly ILogger _logger;
        private readonly IHostApplicationLifetime _appLifetime;
        private readonly TlsAlpnChallengeResponder _tlsAlpnChallengeResponder;
        private readonly TaskCompletionSource<object?> _appStarted = new();
        private AcmeClient? _client;
        private IKey? _acmeAccountKey;

        public AcmeCertificateFactory(
            AcmeClientFactory acmeClientFactory,
            TermsOfServiceChecker tosChecker,
            IOptions<LettuceEncryptOptions> options,
            IHttpChallengeResponseStore challengeStore,
            ILogger<AcmeCertificateFactory> logger,
            IHostApplicationLifetime appLifetime,
            TlsAlpnChallengeResponder tlsAlpnChallengeResponder,
            ICertificateAuthorityConfiguration certificateAuthority,
            IAccountStore? accountRepository = null)
        {
            _acmeClientFactory = acmeClientFactory;
            _tosChecker = tosChecker;
            _options = options;
            _challengeStore = challengeStore;
            _logger = logger;
            _appLifetime = appLifetime;
            _tlsAlpnChallengeResponder = tlsAlpnChallengeResponder;

            appLifetime.ApplicationStarted.Register(() => _appStarted.TrySetResult(null));
            if (appLifetime.ApplicationStarted.IsCancellationRequested)
            {
                _appStarted.TrySetResult(null);
            }

            _accountRepository = accountRepository ?? new FileSystemAccountStore(logger, certificateAuthority);
        }

        public async Task<AccountModel> GetOrCreateAccountAsync(CancellationToken cancellationToken)
        {
            var account = await _accountRepository.GetAccountAsync(cancellationToken);

            _acmeAccountKey = account != null
                ? KeyFactory.FromDer(account.PrivateKey)
                : KeyFactory.NewKey(Certes.KeyAlgorithm.ES256);

            _client = _acmeClientFactory.Create(_acmeAccountKey);

            if (account != null && await ExistingAccountIsValidAsync())
            {
                return account;
            }

            return await CreateAccount(cancellationToken);
        }

        private async Task<AccountModel> CreateAccount(CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (_client == null || _acmeAccountKey == null)
            {
                throw new InvalidOperationException();
            }

            var tosUri = await _client.GetTermsOfServiceAsync();

            _tosChecker.EnsureTermsAreAccepted(tosUri);

            var options = _options.Value;
            _logger.LogInformation("Creating new account for {email}", options.EmailAddress);
            var accountId = await _client.CreateAccountAsync(options.EmailAddress);

            var accountModel = new AccountModel
            {
                Id = accountId,
                EmailAddresses = new[] { options.EmailAddress },
                PrivateKey = _acmeAccountKey.ToDer(),
            };

            await _accountRepository.SaveAccountAsync(accountModel, cancellationToken);

            return accountModel;
        }

        private async Task<bool> ExistingAccountIsValidAsync()
        {
            if (_client == null)
            {
                throw new InvalidOperationException();
            }

            // double checks the account is still valid
            Account existingAccount;
            try
            {
                existingAccount = await _client.GetAccountAsync();
            }
            catch (AcmeRequestException exception)
            {
                _logger.LogWarning(
                    "An account key was found, but could not be matched to a valid account. Validation error: {acmeError}",
                    exception.Error);
                return false;
            }

            if (existingAccount.Status != AccountStatus.Valid)
            {
                _logger.LogWarning(
                    "An account key was found, but the account is no longer valid. Account status: {status}." +
                    "A new account will be registered.",
                    existingAccount.Status);
                return false;
            }

            _logger.LogInformation("Using existing account for {contact}", existingAccount.Contact);

            if (existingAccount.TermsOfServiceAgreed != true)
            {
                var tosUri = await _client.GetTermsOfServiceAsync();
                _tosChecker.EnsureTermsAreAccepted(tosUri);
                await _client.AgreeToTermsOfServiceAsync();
            }

            return true;
        }

        public async Task<X509Certificate2> CreateCertificateAsync(CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (_client == null)
            {
                throw new InvalidOperationException();
            }

            IOrderContext? orderContext = null;
            var orders = await _client.GetOrdersAsync();
            if (orders.Any())
            {
                var expectedDomains = new HashSet<string>(_options.Value.DomainNames);
                foreach (var order in orders)
                {
                    var orderDetails = await _client.GetOrderDetailsAsync(order);
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
                orderContext = await _client.CreateOrderAsync(_options.Value.DomainNames);
            }

            cancellationToken.ThrowIfCancellationRequested();
            var authorizations = await _client.GetOrderAuthorizations(orderContext);

            cancellationToken.ThrowIfCancellationRequested();
            await Task.WhenAll(BeginValidateAllAuthorizations(authorizations, cancellationToken));

            cancellationToken.ThrowIfCancellationRequested();
            return await CompleteCertificateRequestAsync(orderContext, cancellationToken);
        }

        private IEnumerable<Task> BeginValidateAllAuthorizations(IEnumerable<IAuthorizationContext> authorizations,
            CancellationToken cancellationToken)
        {
            foreach (var authorization in authorizations)
            {
                yield return ValidateDomainOwnershipAsync(authorization, cancellationToken);
            }
        }

        private async Task ValidateDomainOwnershipAsync(IAuthorizationContext authorizationContext,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (_client == null)
            {
                throw new InvalidOperationException();
            }

            var authorization = await _client.GetAuthorizationAsync(authorizationContext);
            var domainName = authorization.Identifier.Value;

            if (authorization.Status == AuthorizationStatus.Valid)
            {
                // Short circuit if authorization is already complete
                return;
            }

            _logger.LogDebug("Requesting authorization to create certificate for {domainName}", domainName);

            cancellationToken.ThrowIfCancellationRequested();

            var validators = new List<DomainOwnershipValidator>();

            if (_tlsAlpnChallengeResponder.IsEnabled)
            {
                validators.Add(new TlsAlpn01DomainValidator(
                    _tlsAlpnChallengeResponder, _appLifetime, _client, _logger, domainName));
            }

            if (_options.Value.AllowedChallengeTypes.HasFlag(ChallengeType.Http01))
            {
                validators.Add(new Http01DomainValidator(
                    _challengeStore, _appLifetime, _client, _logger, domainName));
            }

            if (validators.Count == 0)
            {
                var challengeTypes = string.Join(", ", Enum.GetNames(typeof(ChallengeType)));
                throw new InvalidOperationException(
                    "Could not find a method for validating domain ownership. " +
                    "Ensure at least one kind of these challenge types is configured: " + challengeTypes);
            }

            foreach (var validator in validators)
            {
                cancellationToken.ThrowIfCancellationRequested();
                try
                {
                    await validator.ValidateOwnershipAsync(authorizationContext, cancellationToken);
                    // The method above raises if validation fails. If no exception occurs, we assume validation completed successfully.
                    return;
                }
                catch (Exception ex)
                {
                    _logger.LogDebug(ex, "Validation with {validatorType} failed with error: {error}", validator.GetType().Name, ex.Message);
                }
            }

            throw new InvalidOperationException($"Failed to validate ownership of domainName '{domainName}'");
        }

        private byte[] X1RootCertificate => Encoding.ASCII.GetBytes(@"-----BEGIN CERTIFICATE-----
MIIDrzCCApegAwIBAgIRALqMZiRNaRF4EGZS9urlj+0wDQYJKoZIhvcNAQELBQAw
cTELMAkGA1UEBhMCVVMxMzAxBgNVBAoTKihTVEFHSU5HKSBJbnRlcm5ldCBTZWN1
cml0eSBSZXNlYXJjaCBHcm91cDEtMCsGA1UEAxMkKFNUQUdJTkcpIERvY3RvcmVk
IER1cmlhbiBSb290IENBIFgzMB4XDTAwMDkzMDIxMTIxOVoXDTIxMDEzMDE0MDEx
NVowcTELMAkGA1UEBhMCVVMxMzAxBgNVBAoTKihTVEFHSU5HKSBJbnRlcm5ldCBT
ZWN1cml0eSBSZXNlYXJjaCBHcm91cDEtMCsGA1UEAxMkKFNUQUdJTkcpIERvY3Rv
cmVkIER1cmlhbiBSb290IENBIFgzMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIB
CgKCAQEAqUZjoRbjgXecPWxXkGCUEXcNrupL7dkbwc0jUTLFEDvcyfD1gYekY5uL
D19uzYTl0pKZzzDXHJPnJY5EEp27nACFOm8XzX9sORAangP0OnGUkXJZDHM+8cX2
EHJbfj0lg1JirRF3w2u1/KRuFEvIlWg3FdXdsSFHBF5z1Ij7MLn7Ska5c/5fKsDW
EYzOMB6EBW1T9RDkVk/Q965EwDT4bR6BOXakasgfKrH9m1f6l9MmA0VnXdw9rZ+s
TvMHG1yWBqNMSqCKe3jG6caWgN7llEbj5YsCWs32bz2dMftGkXBPcy1fNWvpeT7G
Dz2Z0QWTlHkyXA2kGw32fdoXLHWOEwIDAQABo0IwQDAOBgNVHQ8BAf8EBAMCAQYw
DwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUCFfaiceiU3kMT93gkI90uuInc0Qw
DQYJKoZIhvcNAQELBQADggEBAF7lEtHuSN4j+xFQsM/ujaVKcn57VbrbTecnspmJ
JA7Hrn6OErshGNO0p1/u14c7tGHKjtF1tEFFSVhbNXlKw9O99AfhmlFgdGcJKEHn
ZctBB8bhNO387vbiCYIHdU/nSba9MCDYw2/UCtobZ6ao+KJA3IKmPixctAbn2Ikr
EN9X0SXNP1gnqQP4VhZJIh6cd7rg9MimzoLlMI3m2z11dSGYbh8OWSdvA7aLbSGo
gDO5H4WD8fgqEG0reSBO89eeH+we+BZxQtBiU3b9VMV0drc+7zC2NbXqeQwu6QTl
fbJ8ytqcqUy0g5XSE6WCzPOL3H9r0j9G64dfotGlBA5tG6w=
-----END CERTIFICATE-----");

        private async Task<X509Certificate2> CompleteCertificateRequestAsync(IOrderContext order,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (_client == null)
            {
                throw new InvalidOperationException();
            }

            var commonName = _options.Value.DomainNames[0];
            _logger.LogDebug("Creating cert for {commonName}", commonName);

            var csrInfo = new CsrInfo
            {
                CommonName = commonName,
            };
            var privateKey = KeyFactory.NewKey((Certes.KeyAlgorithm)_options.Value.KeyAlgorithm);
            var acmeCert = await _client.GetCertificateAsync(csrInfo, privateKey, order);

            _logger.LogAcmeAction("NewCertificate");

            var pfxBuilder = acmeCert.ToPfx(privateKey);
            pfxBuilder.AddIssuers(X1RootCertificate);

            var pfx = pfxBuilder.Build("HTTPS Cert - " + _options.Value.DomainNames, string.Empty);
            return new X509Certificate2(pfx, string.Empty, X509KeyStorageFlags.Exportable);
        }
    }
}
