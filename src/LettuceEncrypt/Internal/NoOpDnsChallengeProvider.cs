// Copyright (c) Nate McMaster.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using LettuceEncrypt.Acme;

namespace LettuceEncrypt.Internal;

internal class NoOpDnsChallengeProvider : IDnsChallengeProvider
{
    public Task<DnsTxtRecordContext> AddTxtRecordAsync(
        string domainName,
        string txt,
        CancellationToken ct = default
    ) => Task.FromResult(new DnsTxtRecordContext(domainName, txt));

    public Task RemoveTxtRecordAsync(DnsTxtRecordContext context, CancellationToken ct = default) =>
        Task.CompletedTask;
}
