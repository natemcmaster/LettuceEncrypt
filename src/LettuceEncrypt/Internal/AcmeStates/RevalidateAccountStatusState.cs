// Copyright (c) Nate McMaster.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Certes;
using Certes.Acme.Resource;
using Microsoft.Extensions.Logging;

namespace LettuceEncrypt.Internal.AcmeStates
{
    class RevalidateAccountStatusState : AcmeState
    {
        private readonly ILogger<RevalidateAccountStatusState> _logger;
        private readonly ITermsOfServiceChecker _tosChecker;

        public RevalidateAccountStatusState(
            AcmeStateMachineContext context,
            ILogger<RevalidateAccountStatusState> logger,
            ITermsOfServiceChecker tosChecker)
            : base(context)
        {
            _logger = logger;
            _tosChecker = tosChecker;
        }

        public override async Task<IAcmeState> MoveNextAsync(CancellationToken cancellationToken)
        {
            Account existingAccount;
            try
            {
                existingAccount = await Context.Client.GetAccountDetailsAsync(Context.Account);
                if (existingAccount.Status != AccountStatus.Valid)
                {
                    _logger.LogWarning(
                        "An account key was found, but the account is no longer valid. Account status: {status}." +
                        "A new account will be registered.",
                        existingAccount.Status);
                    return MoveTo<CreateAcmeAccountState>();
                }

                if (existingAccount.TermsOfServiceAgreed != true)
                {
                    var tosUri = await Context.Client.GetTermsOfServiceAsync();
                    _tosChecker.EnsureTermsAreAccepted(tosUri);
                    await Context.Client.AgreeToTermsOfServiceAsync(Context.Account);
                }
            }
            catch (AcmeRequestException exception)
            {
                _logger.LogWarning(
                    "An account key was found, but could not be matched to a valid account. Validation error: {acmeError}",
                    exception.Error);
                return MoveTo<CreateAcmeAccountState>();
            }


            int.TryParse(Context.Account.Location.Segments.Last(), out var accountId);

            _logger.LogInformation("Using existing account {accountId} for {contact}",
                accountId, existingAccount.Contact);
            return MoveTo<GenerateCertificateState>();
        }
    }
}
