// Copyright (c) Nate McMaster.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System.Security.Cryptography.X509Certificates;
using McMaster.AspNetCore.Kestrel.Certificates;
using Microsoft.AspNetCore.Connections;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Server.Kestrel.Https;
using Moq;
using Xunit;

namespace LettuceEncrypt.UnitTests;

using SelectorFunc = Func<ConnectionContext, string, X509Certificate2>;

public class KestrelHttpsOptionsExtensionsTests
{
    [Fact]
    public void UseServerCertificateSelectorFallsbackToOriginalSelector()
    {
        var injectedSelector = new Mock<IServerCertificateSelector>();
        injectedSelector
            .Setup(c => c.Select(It.IsAny<ConnectionContext>(), It.IsAny<string>()))
            .Returns(() => null);

        var originalSelectorWasCalled = false;
        SelectorFunc originalSelector = (_, __) => { originalSelectorWasCalled = true; return null; };

        var options = new HttpsConnectionAdapterOptions
        {
            ServerCertificateSelector = originalSelector
        };

        KestrelHttpsOptionsExtensions.UseServerCertificateSelector(options, injectedSelector.Object);
        options.ServerCertificateSelector(null, null);

        Assert.NotSame(options.ServerCertificateSelector, originalSelector);
        Assert.True(originalSelectorWasCalled);
        injectedSelector.VerifyAll();
    }

    [Fact]
    public void UseServerCertificateSelectorDoesNotCallFallback()
    {
        var injectedSelector = new Mock<IServerCertificateSelector>();
        injectedSelector
            .Setup(c => c.Select(It.IsAny<ConnectionContext>(), It.IsAny<string>()))
            .Returns(() => TestUtils.CreateTestCert("foo.test"));

        var originalSelectorWasCalled = false;
        SelectorFunc originalSelector = (_, __) => { originalSelectorWasCalled = true; return null; };

        var options = new HttpsConnectionAdapterOptions
        {
            ServerCertificateSelector = originalSelector
        };

        KestrelHttpsOptionsExtensions.UseServerCertificateSelector(options, injectedSelector.Object);
        options.ServerCertificateSelector(null, null);

        Assert.NotSame(options.ServerCertificateSelector, originalSelector);
        Assert.False(originalSelectorWasCalled);
        injectedSelector.VerifyAll();
    }
}
