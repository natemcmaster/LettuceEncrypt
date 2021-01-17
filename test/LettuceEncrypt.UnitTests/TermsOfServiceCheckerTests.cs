// Copyright (c) Nate McMaster.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using LettuceEncrypt.Internal;
using LettuceEncrypt.Internal.IO;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Moq;
using Xunit;

namespace LettuceEncrypt.UnitTests
{
    public class TermsOfServiceCheckerTests
    {
        private readonly Uri _tosUri = new("https://any");

        [Fact]
        public void UnreadableConsoleAndUnsetInOptions()
        {
            var console = new Mock<IConsole>();
            console.SetupGet(c => c.IsInputRedirected).Returns(true);
            var checker = new TermsOfServiceChecker(
                console.Object,
                Options.Create<LettuceEncryptOptions>(new LettuceEncryptOptions()),
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
                Options.Create<LettuceEncryptOptions>(new LettuceEncryptOptions()),
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
                Options.Create<LettuceEncryptOptions>(new LettuceEncryptOptions()),
                NullLogger<TermsOfServiceChecker>.Instance
            );

            checker.EnsureTermsAreAccepted(_tosUri);
        }

        [Fact]
        public void ConfiguredInOptions()
        {
            var checker = new TermsOfServiceChecker(
                Mock.Of<IConsole>(),
                Options.Create<LettuceEncryptOptions>(new LettuceEncryptOptions
                {
                    AcceptTermsOfService = true,
                }),
                NullLogger<TermsOfServiceChecker>.Instance
            );

            checker.EnsureTermsAreAccepted(_tosUri);
        }
    }
}
