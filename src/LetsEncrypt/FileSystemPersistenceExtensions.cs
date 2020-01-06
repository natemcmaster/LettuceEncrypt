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
        /// Save generated certificates to a directory in the .pfx format.
        /// </summary>
        /// <param name="builder"></param>
        /// <param name="directory">The directory where .pfx files will be saved.</param>
        /// <param name="pfxPassword">Set to null or empty for passwordless .pfx files.</param>
        /// <returns></returns>
        public static ILetsEncryptServiceBuilder PersistCertificatesToDirectory(
            this ILetsEncryptServiceBuilder builder,
            DirectoryInfo directory,
            string? pfxPassword)
        {
            if (builder is null)
            {
                throw new ArgumentNullException(nameof(builder));
            }

            if (directory is null)
            {
                throw new ArgumentNullException(nameof(directory));
            }

            builder.Services.AddSingleton<ICertificateRepository>(new FileSystemCertificateRepository(directory, pfxPassword));
            return builder;
        }
    }
}
