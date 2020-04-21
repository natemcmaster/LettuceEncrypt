using System;
using McMaster.AspNetCore.LetsEncrypt;
using McMaster.AspNetCore.LetsEncrypt.Internal;
using McMaster.AspNetCore.LetsEncrypt.Internal.IO;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Moq;
using Xunit;

namespace LetsEncrypt.UnitTests
{
    public class TermsOfServiceCheckerTests
    {
        private readonly Uri _tosUri = new Uri("https://any");

        [Fact]
        public void UnreadableConsoleAndUnsetInOptions()
        {
            var console = new Mock<IConsole>();
            console.SetupGet(c => c.IsInputRedirected).Returns(true);
            var checker = new TermsOfServiceChecker(
                console.Object,
                Options.Create<LetsEncryptOptions>(new LetsEncryptOptions()),
                NullLogger<TermsOfServiceChecker>.Instance
            );

            Assert.Throws<InvalidOperationException>(()
                => checker.EnsureTermsAreAccepted(_tosUri));
        }

        [Theory]
        [InlineData("no")]
        [InlineData("N")]

        public void InvalidResponse(string response)
        {
            var console = new Mock<IConsole>();
            console.SetupGet(c => c.IsInputRedirected).Returns(false);
            console.Setup(c => c.ReadLine()).Returns(response);
            var checker = new TermsOfServiceChecker(
                console.Object,
                Options.Create<LetsEncryptOptions>(new LetsEncryptOptions()),
                NullLogger<TermsOfServiceChecker>.Instance
            );

            Assert.Throws<InvalidOperationException>(()
                => checker.EnsureTermsAreAccepted(_tosUri));
        }


        [Theory]
        [InlineData("")]
        [InlineData("yes")]
        [InlineData("y")]
        [InlineData("Y")]
        public void YesOnCommandLine(string response)
        {
            var console = new Mock<IConsole>();
            console.SetupGet(c => c.IsInputRedirected).Returns(false);
            console.Setup(c => c.ReadLine()).Returns(response);
            var checker = new TermsOfServiceChecker(
                console.Object,
                Options.Create<LetsEncryptOptions>(new LetsEncryptOptions()),
                NullLogger<TermsOfServiceChecker>.Instance
            );

            checker.EnsureTermsAreAccepted(_tosUri);
        }

        [Fact]
        public void ConfiguredInOptions()
        {
            var checker = new TermsOfServiceChecker(
                Mock.Of<IConsole>(),
                Options.Create<LetsEncryptOptions>(new LetsEncryptOptions
                {
                    AcceptTermsOfService = true,
                }),
                NullLogger<TermsOfServiceChecker>.Instance
            );

            checker.EnsureTermsAreAccepted(_tosUri);
        }
    }
}
