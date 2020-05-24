// Copyright (c) Nate McMaster.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

#if FEATURE_VALIDATE_DATA_ANNOTATIONS
using System.ComponentModel.DataAnnotations;
#endif
using Azure.Core;
using Azure.Identity;
using LettuceEncrypt.Accounts;

namespace LettuceEncrypt.Azure
{
    /// <summary>
    /// Options to connect to an Azure KeyVault
    /// </summary>
    public class AzureKeyVaultLettuceEncryptOptions
    {
        /// <summary>
        /// Gets or sets the Url for the KeyVault instance.
        /// </summary>
#if FEATURE_VALIDATE_DATA_ANNOTATIONS
        [Url]
        [Required]
#endif
        public string AzureKeyVaultEndpoint { get; set; } = null!;

        /// <summary>
        /// Gets or sets the credentials used for connecting to the key vault. If null, will use <see cref="DefaultAzureCredential" />.
        /// </summary>
        public TokenCredential? Credentials { get; set; }

        /// <summary>
        /// Gets or sets the name the secret used to store the account information for accessing the certificate authority.
        /// This is a JSON string which encodes the information in <see cref="AccountModel"/>.
        /// If not set, the name defaults to the name of the "le-account-${ACME server hostname}".
        /// </summary>
#if FEATURE_VALIDATE_DATA_ANNOTATIONS
        [MaxLength(127)]
#endif
        public string? AccountKeySecretName { get; set; }
    }
}
