// Copyright (c) Nate McMaster.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;

namespace LettuceEncrypt
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
        /// <param name="cancellationToken">A token which, when canceled, should stop any async operations.</param>
        /// <returns>A task which completes once the certificate is done saving.</returns>
        Task SaveAsync(X509Certificate2 certificate, CancellationToken cancellationToken);
    }
}
