// Copyright (c) Nate McMaster.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System.IO;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;

namespace McMaster.AspNetCore.LetsEncrypt
{
    internal class FileSystemCertificateRepository : ICertificateRepository
    {
        private readonly string _pfxPassword;
        private readonly DirectoryInfo _directory;

        public FileSystemCertificateRepository(DirectoryInfo directory, string pfxPassword)
        {
            _pfxPassword = pfxPassword;
            _directory = directory;
        }

        public Task SaveAsync(X509Certificate2 certificate)
        {
            _directory.Create();

            var fileName = certificate.Thumbprint + ".pfx";
            var output = Path.Combine(_directory.FullName, fileName);

            File.WriteAllBytes(
                output,
                certificate.Export(X509ContentType.Pfx, _pfxPassword));

            return Task.CompletedTask;
        }
    }
}
