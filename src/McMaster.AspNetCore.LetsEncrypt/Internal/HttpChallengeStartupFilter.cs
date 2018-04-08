using System;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;

namespace McMaster.AspNetCore.LetsEncrypt.Internal
{
    internal class HttpChallengeStartupFilter : IStartupFilter
    {
        public Action<IApplicationBuilder> Configure(Action<IApplicationBuilder> next)
        {
            return app =>
            {
                app.UseLetsEncryptDomainVerification();
                next(app);
            };
        }
    }
}
