using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;

namespace McMaster.AspNetCore.LetsEncrypt.Internal
{
    internal class HttpChallengeResponseMiddleware : IMiddleware
    {
        private readonly IHttpChallengeResponseStore _responseStore;
        private readonly ILogger<HttpChallengeResponseMiddleware> _logger;

        public HttpChallengeResponseMiddleware(
            IHttpChallengeResponseStore responseStore,
            ILogger<HttpChallengeResponseMiddleware> logger)
        {
            _responseStore = responseStore;
            _logger = logger;
        }

        public async Task InvokeAsync(HttpContext context, RequestDelegate next)
        {
            // assumes that this middleware has been mapped
            var token = context.Request.Path.ToString();
            if (token.StartsWith("/"))
            {
                token = token.Substring(1);
            }

            if (!_responseStore.TryGetResponse(token, out var value))
            {
                await next(context);
                return;
            }

            if (_logger.IsEnabled(LogLevel.Information))
            {
                _logger.LogDebug("Confirmed challenge request for {token}", token);
            }

            context.Response.ContentLength = value.Length;
            context.Response.ContentType = "application/octet-stream";
            await context.Response.WriteAsync(value, context.RequestAborted);
        }
    }
}
