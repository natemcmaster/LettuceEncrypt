// Copyright (c) Nate McMaster.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System.Linq;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace LettuceEncrypt.Internal.AcmeStates
{
    internal class ServerStartupState : SyncAcmeState
    {
        private readonly IOptions<LettuceEncryptOptions> _options;
        private readonly CertificateSelector _selector;
        private readonly ILogger<ServerStartupState> _logger;

        public ServerStartupState(
            AcmeStateMachineContext context,
            IOptions<LettuceEncryptOptions> options,
            CertificateSelector selector,
            ILogger<ServerStartupState> logger) :
            base(context)
        {
            _options = options;
            _selector = selector;
            _logger = logger;
        }

        public override IAcmeState MoveNext()
        {
            var domainNames = _options.Value.DomainNames;
            var hasCertForAllDomains = domainNames.All(_selector.HasCertForDomain);
            if (hasCertForAllDomains)
            {
                _logger.LogDebug("Certificate for {domainNames} already found.", domainNames);
                return MoveTo<CheckForRenewalState>();
            }

            return MoveTo<BeginCertificateCreationState>();
        }
    }
}
