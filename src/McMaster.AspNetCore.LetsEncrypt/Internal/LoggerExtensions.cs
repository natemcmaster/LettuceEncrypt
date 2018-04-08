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
