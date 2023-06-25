// Copyright (c) Nate McMaster.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

namespace LettuceEncrypt.Acme;

/// <summary>
/// External Dns provider to update for DNS-01 challenge
/// </summary>
public interface IDnsChallengeProvider
{
    /// <summary>
    /// call to add record in advance of the validation
    /// </summary>
    /// <param name="domainName">domain name including _acme-challenge.	&lt;YOUR_DOMAIN&gt;</param>
    /// <param name="txt">TXT value for DNS-01 Challenge</param>
    /// <param name="ct">A cancellation token.</param>
    /// <returns>context of added txt record</returns>
    Task<DnsTxtRecordContext> AddTxtRecordAsync(string domainName, string txt, CancellationToken ct = default);

    /// <summary>
    /// callback to remove dns record after validations
    /// </summary>
    /// <param name="context">context from previous added txt record</param>
    /// <param name="ct">A cancellation token.</param>
    /// <returns></returns>
    Task RemoveTxtRecordAsync(DnsTxtRecordContext context, CancellationToken ct = default);
}
