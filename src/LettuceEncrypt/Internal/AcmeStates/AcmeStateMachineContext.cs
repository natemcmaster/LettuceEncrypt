// Copyright (c) Nate McMaster.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;

namespace LettuceEncrypt.Internal.AcmeStates
{
    internal class AcmeStateMachineContext
    {
        public IServiceProvider Services { get; }

        public AcmeStateMachineContext(IServiceProvider services)
        {
            Services = services;
        }
    }
}
