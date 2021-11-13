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

internal class TlsAlpn01DomainValidator : DomainOwnershipValidator
{
    private readonly TlsAlpnChallengeResponder _tlsAlpnChallengeResponder;

    public TlsAlpn01DomainValidator(TlsAlpnChallengeResponder tlsAlpnChallengeResponder,
        IHostApplicationLifetime appLifetime,
        AcmeClient client, ILogger logger, string domainName) : base(appLifetime, client, logger, domainName)
    {
        _tlsAlpnChallengeResponder = tlsAlpnChallengeResponder;
    }

    public override async Task ValidateOwnershipAsync(IAuthorizationContext authzContext, CancellationToken cancellationToken)
    {
        try
        {
            await PrepareTlsAlpnChallengeResponseAsync(authzContext, _domainName, cancellationToken);
            await WaitForChallengeResultAsync(authzContext, cancellationToken);
        }
        finally
        {
            // cleanup after authorization is done to skip unnecessary cert lookup on all incoming SSL connections
            _tlsAlpnChallengeResponder.DiscardChallenge(_domainName);
        }
    }

    private async Task PrepareTlsAlpnChallengeResponseAsync(
        IAuthorizationContext authorizationContext,
        string domainName,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        var tlsAlpnChallenge = await _client.CreateChallengeAsync(authorizationContext, ChallengeTypes.TlsAlpn01);

        _tlsAlpnChallengeResponder.PrepareChallengeCert(domainName, tlsAlpnChallenge.KeyAuthz);

        _logger.LogTrace("Waiting for server to start accepting HTTP requests");
        await _appStarted.Task;

        _logger.LogTrace("Requesting server to validate TLS/ALPN challenge");
        await _client.ValidateChallengeAsync(tlsAlpnChallenge);
    }
}
