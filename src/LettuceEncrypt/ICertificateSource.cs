// Copyright (c) Nate McMaster.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;

namespace LettuceEncrypt
{
    /// <summary>
    /// Defines a source for certificates.
    /// </summary>
    public interface ICertificateSource
    {
        /// <summary>
        /// Gets available certificates from the source.
        /// </summary>
        /// <param name="cancellationToken">A cancellation token.</param>
        /// <returns>A collection of certificates</returns>
        Task<IEnumerable<X509Certificate2>> GetCertificatesAsync(CancellationToken cancellationToken);
    }
}
