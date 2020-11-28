// Copyright (c) Nate McMaster.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Certes;
using Certes.Acme;
using Certes.Acme.Resource;
using Microsoft.Extensions.Logging;

namespace LettuceEncrypt.Internal
{
    class AcmeClient : IAcmeClient
    {
        private readonly AcmeContext _context;
        private readonly ILogger<AcmeClient> _logger;

        public AcmeClient(ILogger<AcmeClient> logger, Uri directoryUri, IKey acmeAccountKey)
        {
            _logger = logger;
            _logger.LogInformation("Using certificate authority {directoryUri}", directoryUri);
            _context = new AcmeContext(directoryUri, acmeAccountKey);
        }

        public async Task<IAccountContext> GetAccountAsync()
        {
            _logger.LogAcmeAction("FetchAccount");
            return await _context.Account();
        }

        public async Task<Account> GetAccountDetailsAsync(IAccountContext accountContext)
        {
            _logger.LogAcmeAction("FetchAccountDetails", accountContext);
            return await accountContext.Resource();
        }

        public async Task<IAccountContext> CreateAccountAsync(string emailAddress)
        {
            _logger.LogAcmeAction("NewAccount");
            return await _context.NewAccount(emailAddress, termsOfServiceAgreed: true);
        }

        public async Task<Uri> GetTermsOfServiceAsync()
        {
            _logger.LogAcmeAction("FetchTOS");
            return await _context.TermsOfService();
        }

        public async Task AgreeToTermsOfServiceAsync(IAccountContext accountContext)
        {
            _logger.LogAcmeAction("UpdateTOS");
            await accountContext.Update(agreeTermsOfService: true);
        }

        public async Task<IEnumerable<IOrderContext>> GetOrdersAsync(IAccountContext accountContext)
        {
            _logger.LogAcmeAction("FetchOrderList");
            var orderListContext = await accountContext.Orders();

            if (orderListContext == null)
            {
                return Enumerable.Empty<IOrderContext>();
            }

            _logger.LogAcmeAction("FetchOrderDetails", orderListContext);
            return await orderListContext.Orders();
        }

        public async Task<IOrderContext> CreateOrderAsync(string[] domainNames)
        {
            _logger.LogAcmeAction("NewOrder");
            return await _context.NewOrder(domainNames);
        }

        public async Task<Order> GetOrderDetailsAsync(IOrderContext order)
        {
            _logger.LogAcmeAction("FetchOrderDetails", order);
            return await order.Resource();
        }

        public async Task<IEnumerable<IAuthorizationContext>> GetOrderAuthorizations(IOrderContext orderContext)
        {
            _logger.LogAcmeAction("FetchAuthorizations", orderContext);
            return await orderContext.Authorizations();
        }

        public async Task<Authorization> GetAuthorizationAsync(IAuthorizationContext authorizationContext)
        {
            _logger.LogAcmeAction("FetchAuthorizationDetails", authorizationContext);
            return await authorizationContext.Resource();
        }

        public async Task<IChallengeContext> CreateChallengeAsync(IAuthorizationContext authorizationContext,
            string challengeType)
        {
            _logger.LogAcmeAction("CreateChallenge", authorizationContext);
            return await authorizationContext.Challenge(challengeType);
        }

        public async Task<Challenge> ValidateChallengeAsync(IChallengeContext httpChallenge)
        {
            _logger.LogAcmeAction("ValidateChallenge", httpChallenge);
            return await httpChallenge.Validate();
        }

        public async Task<CertificateChain> GetCertificateAsync(CsrInfo csrInfo, IKey privateKey, IOrderContext order)
        {
            _logger.LogAcmeAction("GenerateCertificate", order);
            return await order.Generate(csrInfo, privateKey);
        }
    }
}
