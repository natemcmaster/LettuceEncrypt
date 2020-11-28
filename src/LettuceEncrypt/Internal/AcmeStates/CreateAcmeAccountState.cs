// Copyright (c) Nate McMaster.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Certes;
using LettuceEncrypt.Accounts;
using LettuceEncrypt.Acme;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace LettuceEncrypt.Internal.AcmeStates
{
    class CreateAcmeAccountState : AcmeState
    {
        private readonly IOptions<LettuceEncryptOptions> _options;
        private readonly ILogger<CreateAcmeAccountState> _logger;
        private readonly IAcmeClientFactory _acmeClientFactory;
        private readonly ITermsOfServiceChecker _tosChecker;
        private readonly IAccountStore _accountStore;

        public CreateAcmeAccountState(
            AcmeStateMachineContext context,
            ILogger<CreateAcmeAccountState> logger,
            IOptions<LettuceEncryptOptions> options,
            IAcmeClientFactory acmeClientFactory,
            ITermsOfServiceChecker tosChecker,
            ICertificateAuthorityConfiguration certificateAuthority,
            IAccountStore? accountStore = null)
            : base(context)
        {
            _logger = logger;
            _options = options;
            _acmeClientFactory = acmeClientFactory;
            _tosChecker = tosChecker;
            _accountStore = accountStore ?? new FileSystemAccountStore(logger, certificateAuthority);
        }

        public override async Task<IAcmeState> MoveNextAsync(CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            var acmeAccountKey = KeyFactory.NewKey(Certes.KeyAlgorithm.ES256);
            Context.Client = _acmeClientFactory.Create(acmeAccountKey);

            var tosUri = await Context.Client.GetTermsOfServiceAsync();

            _tosChecker.EnsureTermsAreAccepted(tosUri);

            var options = _options.Value;
            _logger.LogInformation("Creating new account for {email}", options.EmailAddress);
            Context.Account = await Context.Client.CreateAccountAsync(options.EmailAddress);

            int.TryParse(Context.Account.Location.Segments.Last(), out var accountId);

            var accountModel = new AccountModel
            {
                Id = accountId,
                EmailAddresses = new[] {options.EmailAddress},
                PrivateKey = acmeAccountKey.ToDer(),
            };

            await _accountStore.SaveAccountAsync(accountModel, cancellationToken);

            return MoveTo<GenerateCertificateState>();
        }
    }
}
