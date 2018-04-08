using System;
using McMaster.AspNetCore.LetsEncrypt;
using McMaster.AspNetCore.LetsEncrypt.Internal;
using Microsoft.AspNetCore.LetsEncrypt;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;

namespace Microsoft.AspNetCore.Hosting
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
        public static IWebHostBuilder UseLetsEncrypt(this IWebHostBuilder builder, Action<LetsEncryptOptions> configure)
        {
            builder.ConfigureServices(services =>
            {
                services.AddLetsEncrypt(configure);
                services.AddSingleton<IStartupFilter, HttpChallengeStartupFilter>();
            });

            return builder;
        }
    }
}
