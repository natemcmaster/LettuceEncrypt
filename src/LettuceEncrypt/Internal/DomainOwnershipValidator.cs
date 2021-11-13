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

internal abstract class DomainOwnershipValidator
{
    protected readonly AcmeClient _client;
    protected readonly ILogger _logger;
    protected readonly string _domainName;
    protected readonly TaskCompletionSource<object?> _appStarted = new();

    protected DomainOwnershipValidator(IHostApplicationLifetime appLifetime, AcmeClient client, ILogger logger, string domainName)
    {
        _client = client;
        _logger = logger;
        _domainName = domainName;

        appLifetime.ApplicationStarted.Register(() => _appStarted.TrySetResult(null));
        if (appLifetime.ApplicationStarted.IsCancellationRequested)
        {
            _appStarted.TrySetResult(null);
        }
    }

    public abstract Task ValidateOwnershipAsync(IAuthorizationContext authzContext, CancellationToken cancellationToken);

    protected async Task WaitForChallengeResultAsync(IAuthorizationContext authorizationContext, CancellationToken cancellationToken)
    {
        var retries = 60;
        var delay = TimeSpan.FromSeconds(2);

        while (retries > 0)
        {
            retries--;

            cancellationToken.ThrowIfCancellationRequested();

            var authorization = await _client.GetAuthorizationAsync(authorizationContext);

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
                        $"The authorization to verify domainName '{_domainName}' has been revoked.");
                case AuthorizationStatus.Expired:
                    throw new InvalidOperationException(
                        $"The authorization to verify domainName '{_domainName}' has expired.");
                case AuthorizationStatus.Deactivated:
                default:
                    throw new ArgumentOutOfRangeException("authorization",
                        "Unexpected response from server while validating domain ownership.");
            }
        }

        throw new TimeoutException("Timed out waiting for domain ownership validation.");
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
}
