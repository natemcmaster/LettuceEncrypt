// Copyright (c) Nate McMaster.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using Azure.Identity;
using Azure.Security.KeyVault.Secrets;
using Microsoft.Extensions.Options;

namespace LettuceEncrypt.Azure.Internal
{
    internal interface ISecretClientFactory
    {
        SecretClient Create();
    }

    internal class SecretClientFactory : ISecretClientFactory
    {
        private readonly IOptions<AzureKeyVaultLettuceEncryptOptions> _options;

        public SecretClientFactory(IOptions<AzureKeyVaultLettuceEncryptOptions> options)
        {
            _options = options ?? throw new ArgumentNullException(nameof(options));
        }

        public SecretClient Create()
        {
            var value = _options.Value;

            if (string.IsNullOrEmpty(value.AzureKeyVaultEndpoint))
            {
                throw new ArgumentException("Missing required option: AzureKeyVaultEndpoint");
            }

            var vaultUri = new Uri(value.AzureKeyVaultEndpoint);
            var credentials = value.Credentials ?? new DefaultAzureCredential();

            return new SecretClient(vaultUri, credentials);
        }
    }
}
