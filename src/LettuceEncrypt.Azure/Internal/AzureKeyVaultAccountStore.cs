// Copyright (c) Nate McMaster.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Azure;
using LettuceEncrypt.Accounts;
using LettuceEncrypt.Acme;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace LettuceEncrypt.Azure.Internal
{
    internal class AzureKeyVaultAccountStore : IAccountStore
    {
        private readonly ILogger<AzureKeyVaultAccountStore> _logger;
        private readonly IOptions<AzureKeyVaultLettuceEncryptOptions> _options;
        private readonly ICertificateAuthorityConfiguration _certificateAuthority;
        private readonly ISecretClientFactory _secretClientFactory;

        public AzureKeyVaultAccountStore(
            ILogger<AzureKeyVaultAccountStore> logger,
            IOptions<AzureKeyVaultLettuceEncryptOptions> options,
            ISecretClientFactory secretClientFactory,
            ICertificateAuthorityConfiguration certificateAuthority)
        {
            _logger = logger;
            _options = options;
            _secretClientFactory = secretClientFactory;
            _certificateAuthority = certificateAuthority;
        }

        public async Task SaveAccountAsync(AccountModel account, CancellationToken cancellationToken)
        {
            var secretName = GetSecretName();
            _logger.LogTrace("Saving account information to Azure Key Vault as {secretName}", secretName);
            var secretValue = JsonSerializer.Serialize(account);
            try
            {
                var secretClient = _secretClientFactory.Create();

                await secretClient.SetSecretAsync(secretName, secretValue, cancellationToken);
                _logger.LogInformation("Saved account information to Azure Key Vault as {secretName}", secretName);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to save account information to Azure Key Vault as {secretName}",
                    secretName);
                throw;
            }
        }

        public async Task<AccountModel?> GetAccountAsync(CancellationToken cancellationToken)
        {
            var secretName = GetSecretName();

            _logger.LogTrace("Searching account information to Azure Key Vault in secret {secretName}", secretName);

            try
            {
                var secretClient = _secretClientFactory.Create();

                var secret = await secretClient.GetSecretAsync(secretName, version: null, cancellationToken);

                _logger.LogInformation("Found account key in {secretName}, version {version}",
                    secret.Value.Name,
                    secret.Value.Properties.Version);

                return JsonSerializer.Deserialize<AccountModel>(secret.Value.Value);
            }
            catch (RequestFailedException ex) when (ex.Status == 404)
            {
                _logger.LogInformation("Could not find account information in secret '{secretName}' in Azure Key Vault",
                    secretName);
                return null;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to fetch secret '{secretName}' from Azure Key Vault", secretName);
                throw;
            }
        }

        private string GetSecretName()
        {
            const int MaxLength = 127;
            string name;

            var options = _options.Value;
            if (!string.IsNullOrEmpty(options.AccountKeySecretName))
            {
                name = options.AccountKeySecretName!;
            }
            else
            {
                name = _certificateAuthority.AcmeDirectoryUri.Host;
            }

            name = "le-account-" + name.Replace(".", "-");
            return name.Length > MaxLength
                ? name.Substring(0, MaxLength)
                : name;
        }
    }
}
