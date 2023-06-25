// Copyright (c) Nate McMaster.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

namespace LettuceEncrypt.Internal;

internal class NoOpDnsChallengeProvider : IDnsChallengeProvider
{
    public Task<ITxtRecordContext> AddTxtRecordAsync(
        string domainName,
        string txt,
        CancellationToken ct = default
    ) => Task.FromResult((ITxtRecordContext)new DefaultTxtRecordContext(domainName, txt));

    public Task RemoveTxtRecordAsync(ITxtRecordContext context, CancellationToken ct = default) =>
        Task.CompletedTask;
}
