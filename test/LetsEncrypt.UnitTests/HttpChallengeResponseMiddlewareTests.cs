using System.IO;
using System.Threading.Tasks;
using McMaster.AspNetCore.LetsEncrypt.Internal;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

#if NETCOREAPP2_1
using ApplicationBuilder = Microsoft.AspNetCore.Builder.Internal.ApplicationBuilder;
#endif

namespace LetsEncrypt.UnitTests
{
    public class HttpChallengeResponseMiddlewareTests
    {
        [Fact]
        public async Task ItResponsesWithToken()
        {
            var services = new ServiceCollection()
                .AddLogging()
                .AddLetsEncrypt()
                .Services
                .BuildServiceProvider(validateScopes: true);

            var appBuilder = new ApplicationBuilder(services);
            appBuilder.UseLetsEncryptDomainVerification();
            appBuilder.Run(_ => Task.CompletedTask);

            var app = appBuilder.Build();

            var challengeStore = services.GetRequiredService<IHttpChallengeResponseStore>();
            challengeStore.AddChallengeResponse("TOKEN-1", "Hello World");

            var context = new DefaultHttpContext
            {
                Request =
                {
                    Path = "/.well-known/acme-challenge/TOKEN-1",
                },
                Response =
                {
                    Body = new MemoryStream(),
                }
            };

            await app.Invoke(context);

            context.Response.Body.Seek(0, SeekOrigin.Begin);
            var reader = new StreamReader(context.Response.Body);
            var streamText = reader.ReadToEnd();

            Assert.Equal("Hello World", streamText);
        }
    }
}
