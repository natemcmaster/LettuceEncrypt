// Copyright (c) Nate McMaster.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Hosting;

namespace LettuceEncrypt.Internal;

internal class StartupCertificateLoader : IHostedService
{
    private readonly IEnumerable<ICertificateSource> _certSources;
    private readonly CertificateSelector _selector;

    public StartupCertificateLoader(
        IEnumerable<ICertificateSource> certSources,
        CertificateSelector selector)
    {
        _certSources = certSources;
        _selector = selector;
    }

    public async Task StartAsync(CancellationToken cancellationToken)
    {
        var allCerts = new List<X509Certificate2>();
        foreach (var certSource in _certSources)
        {
            var certs = await certSource.GetCertificatesAsync(cancellationToken);
            allCerts.AddRange(certs);
        }

        // Add newer certificates first. This avoid potentially unnecessary cert validations on older certificates
        foreach (var cert in allCerts.OrderByDescending(c => c.NotAfter))
        {
            _selector.Add(cert);
        }
    }

    public Task StopAsync(CancellationToken cancellationToken)
        => Task.CompletedTask;
}
