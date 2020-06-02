// Copyright (c) Nate McMaster.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using LettuceEncrypt.Accounts;
using LettuceEncrypt.Acme;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

#if NETSTANDARD2_0
using IHostApplicationLifetime = Microsoft.Extensions.Hosting.IApplicationLifetime;
#endif

namespace LettuceEncrypt.Internal
{
    internal class AcmeCertificateCreatorFactory
    {
        private readonly IHttpChallengeResponseStore _challengeStore;
        private readonly IOptions<LettuceEncryptOptions> _options;
        private readonly ILogger<AcmeCertificateCreatorFactory> _logger;
        private readonly TermsOfServiceChecker _tosChecker;
        private readonly IHostApplicationLifetime _applicationLifetime;
        private readonly TlsAlpnChallengeResponder _tlsAlpnChallengeResponder;
        private readonly ICertificateAuthorityConfiguration _certificateAuthority;
        private readonly IAccountStore? _accountStore;

        public AcmeCertificateCreatorFactory(
            IHttpChallengeResponseStore challengeStore,
            IOptions<LettuceEncryptOptions> options,
            ILogger<AcmeCertificateCreatorFactory> logger,
            TermsOfServiceChecker tosChecker,
            IHostApplicationLifetime applicationLifetime,
            TlsAlpnChallengeResponder tlsAlpnChallengeResponder,
            ICertificateAuthorityConfiguration certificateAuthority,
            IAccountStore? accountStore = default)
        {
            _challengeStore = challengeStore;
            _options = options;
            _logger = logger;
            _tosChecker = tosChecker;
            _applicationLifetime = applicationLifetime;
            _tlsAlpnChallengeResponder = tlsAlpnChallengeResponder;
            _certificateAuthority = certificateAuthority;
            _accountStore = accountStore;
        }

        public CertificateFactory Create()
        {
            return new CertificateFactory(
                _tosChecker,
                _options,
                _challengeStore,
                _accountStore,
                _logger,
                _applicationLifetime,
                _tlsAlpnChallengeResponder,
                _certificateAuthority);
        }
    }
}
