// Copyright (c) Nate McMaster.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using Microsoft.Extensions.DependencyInjection;

namespace LettuceEncrypt.Internal
{
    internal class LettuceEncryptServiceBuilder : ILettuceEncryptServiceBuilder
    {
        public LettuceEncryptServiceBuilder(IServiceCollection services)
        {
            Services = services ?? throw new ArgumentNullException(nameof(services));
        }

        public IServiceCollection Services { get; }
    }
}
