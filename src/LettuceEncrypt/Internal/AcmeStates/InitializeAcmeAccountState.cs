// Copyright (c) Nate McMaster.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System.Threading;
using System.Threading.Tasks;
using Certes;
using LettuceEncrypt.Accounts;

namespace LettuceEncrypt.Internal.AcmeStates
{
    class InitializeAcmeAccountState : AcmeState
    {
        private readonly IAccountStore _accountStore;
        private readonly IAcmeClientFactory _acmeClientFactory;

        public InitializeAcmeAccountState(
            AcmeStateMachineContext context,
            IAccountStore accountStore,
            IAcmeClientFactory acmeClientFactory)
            : base(context)
        {
            _accountStore = accountStore;
            _acmeClientFactory = acmeClientFactory;
        }

        public override async Task<IAcmeState> MoveNextAsync(CancellationToken cancellationToken)
        {
            var storedAccount = await _accountStore.GetAccountAsync(cancellationToken);

            if (storedAccount == null)
            {
                return MoveTo<CreateAcmeAccountState>();
            }

            var acmeAccountKey = KeyFactory.FromDer(storedAccount.PrivateKey);
            Context.Client = _acmeClientFactory.Create(acmeAccountKey);
            Context.Account = await Context.Client.GetAccountAsync();
            return MoveTo<RevalidateAccountStatusState>();
        }
    }
}
