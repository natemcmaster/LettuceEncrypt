// Copyright (c) Nate McMaster.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using Certes.Acme;
using Microsoft.Extensions.Logging;

namespace McMaster.AspNetCore.LetsEncrypt.Internal
{
    internal static class LoggerExtensions
    {
        public static void LogResponse<T>(this ILogger logger, string actionName, AcmeResult<T> response)
        {
            if (!logger.IsEnabled(LogLevel.Trace))
            {
                return;
            }

            logger.LogTrace("ACME action: {name}, json response: {data}", actionName, response.Json);
        }
    }
}
