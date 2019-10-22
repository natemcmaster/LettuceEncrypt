// Copyright (c) Nate McMaster.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using Microsoft.Extensions.Logging;

namespace McMaster.AspNetCore.LetsEncrypt.Internal
{
    internal static class LoggerExtensions
    {
        public static void LogAcmeAction(this ILogger logger, string actionName, object result)
        {
            if (!logger.IsEnabled(LogLevel.Trace))
            {
                return;
            }

            logger.LogTrace("ACMEv2 action: {name}", actionName);
        }
    }
}
