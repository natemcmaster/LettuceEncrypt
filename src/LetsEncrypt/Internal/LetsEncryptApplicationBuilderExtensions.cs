// Copyright (c) Nate McMaster.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using McMaster.AspNetCore.LetsEncrypt.Internal;

namespace Microsoft.AspNetCore.Builder
{
    /// <summary>
    /// Helper methods
    /// </summary>
    internal static class LetsEncryptApplicationBuilderExtensions
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
