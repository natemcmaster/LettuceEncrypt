// Copyright (c) Nate McMaster.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using Certes.Acme;

namespace LettuceEncrypt.Internal.AcmeStates
{
    internal class AcmeStateMachineContext
    {
        private IAccountContext? _account;
        private IAcmeClient? _acmeClient;

        public AcmeStateMachineContext(IServiceProvider services)
        {
            Services = services;
        }

        // for testing
        internal AcmeStateMachineContext(
            IServiceProvider services,
            IAccountContext? account = null,
            IAcmeClient? acmeClient = null)
            : this(services)
        {
            _account = account;
            _acmeClient = acmeClient;
        }

        public IServiceProvider Services { get; }

        public bool IsAccountInitialized => _account != null;

        public IAccountContext Account
        {
            get => _account ?? throw new InvalidOperationException("Account has not been initialized yet");
            set => _account = value;
        }

        public IAcmeClient Client
        {
            get => _acmeClient ?? throw new InvalidOperationException("Acme client has not been initialized yet");
            set => _acmeClient = value;
        }
    }
}
