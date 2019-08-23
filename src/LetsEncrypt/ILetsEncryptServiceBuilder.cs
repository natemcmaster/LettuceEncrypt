// Copyright (c) Nate McMaster.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using Microsoft.Extensions.DependencyInjection;

namespace McMaster.AspNetCore.LetsEncrypt
{
    /// <summary>
    /// Configures options for Let's Encrypt
    /// </summary>
    public interface ILetsEncryptServiceBuilder
    {
        /// <summary>
        /// The service collection.
        /// </summary>
        IServiceCollection Services { get; }
    }
}
