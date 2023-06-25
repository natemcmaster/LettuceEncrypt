// Copyright (c) Nate McMaster.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using Certes;
using Certes.Acme;
using Certes.Acme.Resource;
using LettuceEncrypt.Acme;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace LettuceEncrypt.Internal;

internal class Dns01DomainValidator : DomainOwnershipValidator
{
    private readonly IDnsChallengeProvider _dnsChallengeProvider;

    public Dns01DomainValidator(
        IDnsChallengeProvider dnsChallengeProvider,
        IHostApplicationLifetime appLifetime,
        AcmeClient client,
        ILogger logger,
        string domainName
    ) : base(appLifetime, client, logger, domainName)
    {
        _dnsChallengeProvider = dnsChallengeProvider;
    }

    public override async Task ValidateOwnershipAsync(
        IAuthorizationContext authzContext,
        CancellationToken cancellationToken
    )
    {
        var context = new DnsTxtRecordContext(_domainName, string.Empty);
        try
        {
            context = await PrepareDns01ChallengeResponseAsync(authzContext, _domainName, cancellationToken);
            await WaitForChallengeResultAsync(authzContext, cancellationToken);
        }
        finally
        {
            // Cleanup
            await _dnsChallengeProvider.RemoveTxtRecordAsync(context, cancellationToken);
        }
    }

    private async Task<DnsTxtRecordContext> PrepareDns01ChallengeResponseAsync(
        IAuthorizationContext authorizationContext,
        string domainName,
        CancellationToken cancellationToken
    )
    {
        cancellationToken.ThrowIfCancellationRequested();

        var account = _client.GetAccountKey();
        var dnsChallenge = await _client.CreateChallengeAsync(authorizationContext, ChallengeTypes.Dns01);

        var dnsTxt = account.DnsTxt(dnsChallenge.Token);

        var acmeDomain = GetAcmeDnsDomain(domainName);

        var context = await _dnsChallengeProvider.AddTxtRecordAsync(acmeDomain, dnsTxt, cancellationToken);

        _logger.LogTrace("Requesting server to validate DNS challenge");
        await _client.ValidateChallengeAsync(dnsChallenge);

        return context;
    }

    private const string DnsAcmePrefix = "_acme-challenge";

    private string GetAcmeDnsDomain(string domainName) =>
        $"{DnsAcmePrefix}.{domainName.TrimStart('*')}";
}
