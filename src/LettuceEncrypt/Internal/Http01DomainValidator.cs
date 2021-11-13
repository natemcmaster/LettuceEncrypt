// Copyright (c) Nate McMaster.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using Certes.Acme;
using Certes.Acme.Resource;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

#if NETSTANDARD2_0
using IHostApplicationLifetime = Microsoft.Extensions.Hosting.IApplicationLifetime;
#endif

namespace LettuceEncrypt.Internal;

internal class Http01DomainValidator : DomainOwnershipValidator
{
    private readonly IHttpChallengeResponseStore _challengeStore;

    public Http01DomainValidator(IHttpChallengeResponseStore challengeStore,
        IHostApplicationLifetime appLifetime,
        AcmeClient client, ILogger logger, string domainName) : base(appLifetime, client, logger, domainName)
    {
        _challengeStore = challengeStore;
    }

    public override async Task ValidateOwnershipAsync(IAuthorizationContext authzContext, CancellationToken cancellationToken)
    {
        await PrepareHttpChallengeResponseAsync(authzContext, cancellationToken);
        await WaitForChallengeResultAsync(authzContext, cancellationToken);
    }

    private async Task PrepareHttpChallengeResponseAsync(
        IAuthorizationContext authorizationContext,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (_client == null)
        {
            throw new InvalidOperationException();
        }

        var httpChallenge = await _client.CreateChallengeAsync(authorizationContext, ChallengeTypes.Http01);
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
        await _client.ValidateChallengeAsync(httpChallenge);
    }
}
