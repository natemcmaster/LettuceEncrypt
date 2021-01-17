// Copyright (c) Nate McMaster.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using System.Collections.Generic;
using LettuceEncrypt.Internal;
using Microsoft.AspNetCore.Connections;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Moq;
using Xunit;

namespace LettuceEncrypt.UnitTests
{
    using static TestUtils;

    public class CertificateSelectorTests
    {
        [Fact]
        public void ItUsesCertCommonName()
        {
            const string CommonName = "selector.test.natemcmaster.com";

            var testCert = CreateTestCert(CommonName);
            var selector = new CertificateSelector(
                Options.Create(new LettuceEncryptOptions()),
                NullLogger<CertificateSelector>.Instance);

            selector.Add(testCert);

            var domain = Assert.Single(selector.SupportedDomains);
            Assert.Equal(CommonName, domain);
        }

        [Fact]
        public void ItUsesSubjectAlternativeName()
        {
            var domainNames = new[]
            {
                "san1.test.natemcmaster.com",
                "san2.test.natemcmaster.com",
                "san3.test.natemcmaster.com",
            };
            var testCert = CreateTestCert(domainNames);
            var selector = new CertificateSelector(
                Options.Create(new LettuceEncryptOptions()),
                NullLogger<CertificateSelector>.Instance);

            selector.Add(testCert);


            Assert.Equal(
                new HashSet<string>(domainNames),
                new HashSet<string>(selector.SupportedDomains));
        }

        [Fact]
        public void ItSelectsCertificateWithLongestTTL()
        {
            const string CommonName = "test.natemcmaster.com";
            var fiveDays = CreateTestCert(CommonName, DateTimeOffset.Now.AddDays(5));
            var tenDays = CreateTestCert(CommonName, DateTimeOffset.Now.AddDays(10));

            var selector = new CertificateSelector(
                Options.Create(new LettuceEncryptOptions()),
                NullLogger<CertificateSelector>.Instance);

            selector.Add(fiveDays);
            selector.Add(tenDays);

            Assert.Same(tenDays, selector.Select(Mock.Of<ConnectionContext>(), CommonName));

            selector.Reset(CommonName);

            Assert.Null(selector.Select(Mock.Of<ConnectionContext>(), CommonName));

            selector.Add(tenDays);
            selector.Add(fiveDays);

            Assert.Same(tenDays, selector.Select(Mock.Of<ConnectionContext>(), CommonName));
        }
    }
}
