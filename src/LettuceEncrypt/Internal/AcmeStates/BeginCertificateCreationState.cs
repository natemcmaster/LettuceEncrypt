// Copyright (c) Nate McMaster.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

namespace LettuceEncrypt.Internal.AcmeStates
{
    class BeginCertificateCreationState : SyncAcmeState
    {
        public BeginCertificateCreationState(AcmeStateMachineContext context) : base(context)
        {
        }

        public override IAcmeState MoveNext()
        {
            if (!Context.IsAccountInitialized)
            {
                return MoveTo<InitializeAcmeAccountState>();
            }

            return MoveTo<RevalidateAccountStatusState>();
        }
    }
}
