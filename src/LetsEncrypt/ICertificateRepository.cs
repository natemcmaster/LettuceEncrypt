// Copyright (c) Nate McMaster.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;

namespace McMaster.AspNetCore.LetsEncrypt
{
    /// <summary>
    /// Manages certificate persistence after it is generated.
    /// </summary>
    public interface ICertificateRepository
    {
        /// <summary>
        /// Save the certificate.
        /// </summary>
        /// <param name="certificate">The certificate, including its private keys</param>
        /// <returns>A task which completes once the certificate is one saving.</returns>
        Task SaveAsync(X509Certificate2 certificate);
    }
}
