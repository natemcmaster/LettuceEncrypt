// Copyright (c) Nate McMaster.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using System.IO;
using Microsoft.Extensions.DependencyInjection;

namespace McMaster.AspNetCore.LetsEncrypt
{
    /// <summary>
    /// Extensions for configuring certificate persistence
    /// </summary>
    public static class FileSystemStorageExtensions
    {
        /// <summary>
        /// Save generated certificates to
        /// </summary>
        /// <param name="builder"></param>
        /// <param name="directory"></param>
        /// <param name="pfxPassword"></param>
        /// <returns></returns>
        public static ILetsEncryptServiceBuilder PersistCertificatesToDirectory(this ILetsEncryptServiceBuilder builder, DirectoryInfo directory, string pfxPassword)
        {
            if (builder is null)
            {
                throw new ArgumentNullException(nameof(builder));
            }

            if (directory is null)
            {
                throw new ArgumentNullException(nameof(directory));
            }

            if (string.IsNullOrEmpty(pfxPassword))
            {
                throw new ArgumentException("Certificate password should be non-empty.", nameof(pfxPassword));
            }

            builder.Services.AddSingleton<ICertificateRepository>(new FileSystemCertificateRepository(directory, pfxPassword));
            return builder;
        }
    }
}
