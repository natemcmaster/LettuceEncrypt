// Copyright (c) Nate McMaster.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.DependencyInjection;

namespace LettuceEncrypt.Internal.AcmeStates
{
    internal interface IAcmeState
    {
        Task<IAcmeState> MoveNextAsync(CancellationToken cancellationToken);
    }

    internal class TerminalState : IAcmeState
    {
        public static TerminalState Singleton { get; } = new TerminalState();

        private TerminalState() {}

        public Task<IAcmeState> MoveNextAsync(CancellationToken cancellationToken)
            => throw new OperationCanceledException();
    }

    internal abstract class AcmeState : IAcmeState
    {
        protected AcmeState(AcmeStateMachineContext context)
        {
            Context = context;
        }

        protected AcmeStateMachineContext Context { get; }

        public abstract Task<IAcmeState> MoveNextAsync(CancellationToken cancellationToken);

        protected virtual T MoveTo<T>() where T : IAcmeState
        {
            return Context.Services.GetRequiredService<T>();
        }
    }

    internal abstract class SyncAcmeState : AcmeState
    {
        protected SyncAcmeState(AcmeStateMachineContext context) : base(context)
        {
        }

        public override Task<IAcmeState> MoveNextAsync(CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            var next = MoveNext();

            return Task.FromResult(next);
        }

        public abstract IAcmeState MoveNext();
    }
}
