using System;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using McMaster.AspNetCore.LetsEncrypt;
using Xunit;

namespace LetsEncrypt.UnitTests
{
    public class FileSystemCertificateRepoTests
    {
        [Fact]
        public async System.Threading.Tasks.Task ItCreatesCertOnDiskAsync()
        {
            var dir = new DirectoryInfo(Path.Combine(AppContext.BaseDirectory, Path.GetRandomFileName()));
            var repo = new FileSystemCertificateRepository(dir, "testpassword");
            var key = RSA.Create(2048);
            var csr = new CertificateRequest("CN=localhost", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            var cert = csr.CreateSelfSigned(DateTimeOffset.Now, DateTimeOffset.Now.AddHours(1));
            var expectedFile = Path.Combine(dir.FullName, cert.Thumbprint + ".pfx");

            Assert.False(dir.Exists, "Directory should not exist yet created");

            await repo.SaveAsync(cert);

            dir.Refresh();
            Assert.True(dir.Exists, "Directory was created");
            Assert.True(File.Exists(expectedFile), "Cert exists");
        }
    }
}
