// Copyright (c) Nate McMaster.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using McMaster.AspNetCore.LetsEncrypt;
using McMaster.AspNetCore.LetsEncrypt.Internal;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.DependencyInjection;

namespace Microsoft.Extensions.Hosting
{
    /// <summary>
    /// Helper methods for configuring Let's Encrypt with an ASP.NET Core server.
    /// </summary>
    public static class LetsEncryptWebHostBuilderExtensions
    {
        /// <summary>
        /// Use Let's Encrypt (<see href="https://letsencrpyt.org">https://letsencrpyt.org</see>) to automatically
        /// generate HTTPs certificates for this server.
        /// </summary>
        /// <param name="builder">The web host builder</param>
        /// <param name="configure">Options for configuring certificate generation</param>
        /// <returns>The web host builder</returns>
        public static IHostBuilder UseLetsEncrypt(this IHostBuilder builder, Action<LetsEncryptOptions> configure)
        {
            builder.ConfigureServices((_, services) =>
            {
                services.AddLetsEncrypt(configure);
                services.AddSingleton<IStartupFilter, HttpChallengeStartupFilter>();
            });

            return builder;
        }
    }
}
