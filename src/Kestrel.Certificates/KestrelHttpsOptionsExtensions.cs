// Copyright (c) Nate McMaster.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using McMaster.AspNetCore.Kestrel.Certificates;
using Microsoft.AspNetCore.Server.Kestrel.Https;

// ReSharper disable once CheckNamespace
namespace Microsoft.AspNetCore.Hosting
{
    /// <summary>
    /// API for configuring Kestrel certificiate options
    /// </summary>
    public static class KestrelHttpsOptionsExtensions
    {
        /// <summary>
        /// Configure HTTPS certificates dynamically with an implementation of <see cref="IServerCertificateSelector"/>.
        /// </summary>
        /// <param name="httpsOptions">The HTTPS configuration</param>
        /// <param name="certificateSelector">The server certificate selector.</param>
        /// <returns>The HTTPS configuration</returns>
        public static HttpsConnectionAdapterOptions UseServerCertificateSelector(
            this HttpsConnectionAdapterOptions httpsOptions,
            IServerCertificateSelector certificateSelector)
        {
            httpsOptions.ServerCertificateSelector = certificateSelector.Select;
            return httpsOptions;
        }
    }
}
