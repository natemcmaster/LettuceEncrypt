using System.Collections.Generic;
using System.Linq;
using McMaster.AspNetCore.LetsEncrypt;
using McMaster.AspNetCore.LetsEncrypt.Internal;
using Microsoft.Extensions.Options;
using Xunit;

namespace LetsEncrypt.UnitTests
{
    using static TestUtils;

    public class CertificateSelectorTests
    {
        [Fact]
        public void ItUsesCertCommonName()
        {
            const string CommonName = "selector.letsencrypt.natemcmaster.com";

            var testCert = CreateTestCert(CommonName);
            var selector = new CertificateSelector(Options.Create(new LetsEncryptOptions()));

            selector.Add(testCert);

            var domain = Assert.Single(selector.SupportedDomains);
            Assert.Equal(CommonName, domain);
        }

        [Fact]
        public void ItUsesSubjectAlternativeName()
        {
            var domainNames = new[]
            {
                "san1.letsencrypt.natemcmaster.com",
                "san2.letsencrypt.natemcmaster.com",
                "san3.letsencrypt.natemcmaster.com",
            };
            var testCert = CreateTestCert(domainNames);
            var selector = new CertificateSelector(Options.Create(new LetsEncryptOptions()));

            selector.Add(testCert);


            Assert.Equal(
                new HashSet<string>(domainNames),
                new HashSet<string>(selector.SupportedDomains));
        }
    }
}
