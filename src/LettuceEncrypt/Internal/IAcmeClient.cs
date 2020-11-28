// Copyright (c) Nate McMaster.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Certes;
using Certes.Acme;
using Certes.Acme.Resource;

namespace LettuceEncrypt.Internal
{
    interface IAcmeClient
    {
        Task<IAccountContext> GetAccountAsync();
        Task<Account> GetAccountDetailsAsync(IAccountContext accountContext);
        Task<IAccountContext> CreateAccountAsync(string emailAddress);
        Task<Uri> GetTermsOfServiceAsync();
        Task AgreeToTermsOfServiceAsync(IAccountContext accountContext);
        Task<IEnumerable<IOrderContext>> GetOrdersAsync(IAccountContext accountContext);
        Task<IOrderContext> CreateOrderAsync(string[] domainNames);
        Task<Order> GetOrderDetailsAsync(IOrderContext order);
        Task<IEnumerable<IAuthorizationContext>> GetOrderAuthorizations(IOrderContext orderContext);
        Task<Authorization> GetAuthorizationAsync(IAuthorizationContext authorizationContext);
        Task<IChallengeContext> CreateChallengeAsync(IAuthorizationContext authorizationContext, string challengeType);
        Task<Challenge> ValidateChallengeAsync(IChallengeContext httpChallenge);
        Task<CertificateChain> GetCertificateAsync(CsrInfo csrInfo, IKey privateKey, IOrderContext order);
    }
}
