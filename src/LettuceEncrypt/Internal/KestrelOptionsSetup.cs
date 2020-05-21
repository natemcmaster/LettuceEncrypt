// Copyright (c) Nate McMaster.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.Extensions.Options;

namespace LettuceEncrypt.Internal
{
    internal class KestrelOptionsSetup : IConfigureOptions<KestrelServerOptions>
    {
        private readonly CertificateSelector _certificateSelector;
        private readonly TlsAlpnChallengeResponder _tlsAlpnChallengeResponder;

        public KestrelOptionsSetup(CertificateSelector certificateSelector, TlsAlpnChallengeResponder tlsAlpnChallengeResponder)
        {
            _certificateSelector = certificateSelector ?? throw new ArgumentNullException(nameof(certificateSelector));
            _tlsAlpnChallengeResponder = tlsAlpnChallengeResponder ?? throw new ArgumentNullException(nameof(tlsAlpnChallengeResponder));
        }

        public void Configure(KestrelServerOptions options)
        {
            options.ConfigureHttpsDefaults(o =>
            {
#if NETCOREAPP3_0
                o.OnAuthenticate = _tlsAlpnChallengeResponder.OnSslAuthenticate;
#elif NETSTANDARD2_0
#else
#error Update TFMs
#endif
                o.ServerCertificateSelector = _certificateSelector.Select;
            });
        }
    }
}
