// Copyright (c) Nate McMaster.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using Certes;
using LettuceEncrypt.Acme;
using Microsoft.Extensions.Logging;

namespace LettuceEncrypt.Internal
{
    interface IAcmeClientFactory
    {
        IAcmeClient Create(IKey acmeAccountKey);
    }

    class AcmeClientFactory : IAcmeClientFactory
    {
        private readonly ICertificateAuthorityConfiguration _certificateAuthority;
        private readonly ILogger<AcmeClient> _logger;

        public AcmeClientFactory(
            ICertificateAuthorityConfiguration certificateAuthority,
            ILogger<AcmeClient> logger)
        {
            _certificateAuthority = certificateAuthority;
            _logger = logger;
        }

        public IAcmeClient Create(IKey acmeAccountKey)
        {
            var directoryUri = _certificateAuthority.AcmeDirectoryUri;

            return new AcmeClient(_logger, directoryUri, acmeAccountKey);
        }
    }
}
