// Copyright (c) Nate McMaster.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using Microsoft.Extensions.DependencyInjection;

namespace McMaster.AspNetCore.LetsEncrypt
{
    internal class LetsEncryptServiceBuilder : ILetsEncryptServiceBuilder
    {
        public LetsEncryptServiceBuilder(IServiceCollection services)
        {
            Services = services ?? throw new ArgumentNullException(nameof(services));
        }


        /// <inheritdoc />
        public IServiceCollection Services { get; }
    }
}
