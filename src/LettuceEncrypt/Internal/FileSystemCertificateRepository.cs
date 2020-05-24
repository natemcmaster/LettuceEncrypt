// Copyright (c) Nate McMaster.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;

namespace LettuceEncrypt.Internal
{
    internal class FileSystemCertificateRepository : ICertificateRepository, ICertificateSource
    {
        private readonly DirectoryInfo _certDir;

        public FileSystemCertificateRepository(DirectoryInfo directory, string? pfxPassword)
        {
            RootDir = directory;
            PfxPassword = pfxPassword;
            _certDir = directory.CreateSubdirectory("certs");
        }

        public DirectoryInfo RootDir { get; }
        public string? PfxPassword { get; }

        public Task<IEnumerable<X509Certificate2>> GetCertificatesAsync(CancellationToken cancellationToken)
        {
            var certs = new List<X509Certificate2>();
            foreach (var file in _certDir.GetFiles("*.pfx"))
            {
                var cert = new X509Certificate2(
                    fileName: file.FullName,
                    password: PfxPassword);
                certs.Add(cert);
            }

            return Task.FromResult(certs.AsEnumerable());
        }

        public Task SaveAsync(X509Certificate2 certificate, CancellationToken cancellationToken)
        {
            _certDir.Create();

            var tmpFile = Path.GetTempFileName();
            File.WriteAllBytes(
                tmpFile,
                certificate.Export(X509ContentType.Pfx, PfxPassword));

            var fileName = certificate.Thumbprint + ".pfx";
            var output = Path.Combine(_certDir.FullName, fileName);

            // File.Move is an atomic operation on most operating systems. By writing to a temporary file
            // first and then moving it, it avoids potential race conditions with readers.

            File.Move(tmpFile, output);

            return Task.CompletedTask;
        }
    }
}
