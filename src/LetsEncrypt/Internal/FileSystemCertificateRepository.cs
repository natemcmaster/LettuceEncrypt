// Copyright (c) Nate McMaster.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System.IO;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;

namespace McMaster.AspNetCore.LetsEncrypt
{
    internal class FileSystemCertificateRepository : ICertificateRepository
    {
        private readonly string? _pfxPassword;
        private readonly DirectoryInfo _directory;

        public FileSystemCertificateRepository(DirectoryInfo directory, string? pfxPassword)
        {
            _pfxPassword = pfxPassword;
            _directory = directory;
        }

        public Task SaveAsync(X509Certificate2 certificate, CancellationToken cancellationToken)
        {
            _directory.Create();

            var tmpFile = Path.GetTempFileName();
            File.WriteAllBytes(
                tmpFile,
                certificate.Export(X509ContentType.Pfx, _pfxPassword));

            var fileName = certificate.Thumbprint + ".pfx";
            var output = Path.Combine(_directory.FullName, fileName);

            // File.Move is an atomic operation on most operating systems. By writing to a temporary file
            // first and then moving it, it avoids potential race conditions with readers.

            File.Move(tmpFile, output);

            return Task.CompletedTask;
        }
    }
}
