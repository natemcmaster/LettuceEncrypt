// Copyright (c) Nate McMaster.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using Azure.Core;
using Azure.Identity;

#if FEATURE_VALIDATE_DATA_ANNOTATIONS
using System.ComponentModel.DataAnnotations;
#endif

namespace McMaster.AspNetCore.LetsEncrypt
{
    /// <summary>
    /// Options to connect to an Azure KeyVault
    /// </summary>
    public class AzureKeyVaultCertificateRepositoryOptions
    {
        /// <summary>
        /// Gets or sets the Url for the KeyVault instance.
        /// </summary>
#if FEATURE_VALIDATE_DATA_ANNOTATIONS
        [Url]
        [Required]
#endif
        public string Url { get; set; } = null!;

        /// <summary>
        /// Gets or sets the credentials used for connecting to the key vault. If null, will use <see cref="DefaultAzureCredential" />.
        /// </summary>
        public TokenCredential? Credentials { get; set; }
    }
}
