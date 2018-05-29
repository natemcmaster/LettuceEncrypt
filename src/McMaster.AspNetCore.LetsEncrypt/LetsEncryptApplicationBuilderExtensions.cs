// Copyright (c) Nate McMaster.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using McMaster.AspNetCore.LetsEncrypt.Internal;
using Microsoft.AspNetCore.Builder;

namespace McMaster.AspNetCore.LetsEncrypt
{
    /// <summary>
    /// Helper methods
    /// </summary>
    public static class LetsEncryptApplicationBuilderExtensions
    {
        /// <summary>
        /// Adds middleware use to verify domain ownership.
        /// </summary>
        /// <param name="app">The application builder</param>
        /// <returns>The application builder</returns>
        public static IApplicationBuilder UseLetsEncryptDomainVerification(this IApplicationBuilder app)
        {
            app.Map("/.well-known/acme-challenge", mapped =>
            {
                mapped.UseMiddleware<HttpChallengeResponseMiddleware>();
            });
            return app;
        }
    }
}
