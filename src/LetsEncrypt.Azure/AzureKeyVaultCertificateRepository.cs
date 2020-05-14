// Copyright (c) Nate McMaster.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using Azure;
using Azure.Identity;
using Azure.Security.KeyVault.Certificates;
using Azure.Security.KeyVault.Secrets;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace McMaster.AspNetCore.LetsEncrypt
{
    internal class AzureKeyVaultCertificateRepository : ICertificateRepository, ICertificateSource
    {
        private readonly IOptions<LetsEncryptOptions> _encryptOptions;
        private readonly ILogger<AzureKeyVaultCertificateRepository> _logger;
        private readonly CertificateClient _certificateClient;
        private readonly SecretClient _secretClient;

        public AzureKeyVaultCertificateRepository(
            CertificateClient certificateClient,
            SecretClient secretClient,
            IOptions<LetsEncryptOptions> encryptOptions,
            ILogger<AzureKeyVaultCertificateRepository> logger)
        {
            _certificateClient = certificateClient ?? throw new ArgumentNullException(nameof(certificateClient));
            _secretClient = secretClient ?? throw new ArgumentNullException(nameof(secretClient));
            _encryptOptions = encryptOptions ?? throw new ArgumentNullException(nameof(encryptOptions));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        public AzureKeyVaultCertificateRepository(
            IOptions<LetsEncryptOptions> encryptOptions,
            IOptions<AzureKeyVaultCertificateRepositoryOptions> options,
            ILogger<AzureKeyVaultCertificateRepository> logger)
            : this(CreateCertificateClient(options), CreateSecretClient(options), encryptOptions, logger)
        {
        }

        public async Task<IEnumerable<X509Certificate2>> GetCertificatesAsync(CancellationToken cancellationToken)
        {
            var certs = new List<X509Certificate2>();

            foreach (var domain in _encryptOptions.Value.DomainNames)
            {
                var cert = await GetCertificateAsync(domain, cancellationToken);

                if (cert != null)
                {
                    certs.Add(cert);
                }
            }

            return certs;
        }

        private async Task<X509Certificate2?> GetCertificateAsync(string domain, CancellationToken token)
        {
            _logger.LogInformation("Searching for certificate in KeyVault for {Domain}", domain);

            try
            {
                var normalizedName = NormalizeHostName(domain);

                var certificate = await _secretClient.GetSecretAsync(normalizedName, null, token);

                return new X509Certificate2(Convert.FromBase64String(certificate.Value.Value));
            }
            catch (RequestFailedException ex) when (ex.Status == 404)
            {
                _logger.LogWarning("Could not find certificate for {Domain} in Azure KeyVault", domain);
            }
            catch (CredentialUnavailableException ex)
            {
                _logger.LogError(ex, "Could not retrieve credentials for Azure Key Vault");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Unexpected error attempting to retrieve certificate for {Domain} from Azure KeyVault. Verify settings and try again.", domain);
            }

            return null;
        }

        public async Task SaveAsync(X509Certificate2 certificate, CancellationToken cancellationToken)
        {
            var domainName = certificate.GetNameInfo(X509NameType.DnsName, false);

            _logger.LogInformation("Saving certificate for {Domain} in Azure KeyVault.", domainName);

            if (!(await ShouldImportVersionAsync(domainName, certificate, cancellationToken)))
            {
                _logger.LogInformation("Certificate for {Domain} is already up-to-date in Azure KeyVault. Skipping importing.", domainName);
                return;
            }

            var exported = certificate.Export(X509ContentType.Pfx);

            var options = new ImportCertificateOptions(NormalizeHostName(domainName), exported);

            try
            {
                await _certificateClient.ImportCertificateAsync(options, cancellationToken);

                _logger.LogInformation("Imported certificate into Azure KeyVault for {Domain}", domainName);
            }
            catch (RequestFailedException ex)
            {
                _logger.LogWarning(ex, "Failed to save {Domain} certificate to Azure KeyVault", domainName);
            }
        }

        private async ValueTask<bool> ShouldImportVersionAsync(string domainName, X509Certificate2 certificate, CancellationToken token)
        {
            using var other = await GetCertificateAsync(domainName, token);

            if (other is null)
            {
                return true;
            }

            return !string.Equals(certificate.Thumbprint, other.Thumbprint, StringComparison.Ordinal);
        }

        /// <summary>
        /// Names must follow the regular expression <c>/^[0-9a-zA-Z-]+$/</c>
        /// See https://docs.microsoft.com/en-us/rest/api/keyvault/ImportCertificate/ImportCertificate.
        /// </summary>
        internal static string NormalizeHostName(string hostName) => hostName.Replace(".", "-");

        private static CertificateClient CreateCertificateClient(IOptions<AzureKeyVaultCertificateRepositoryOptions> options)
        {
            if (options is null)
            {
                throw new ArgumentNullException(nameof(options));
            }

            var value = options.Value;

            if (string.IsNullOrEmpty(value.AzureKeyVaultEndpoint))
            {
                throw new ArgumentException("Missing required option: AzureKeyVaultEndpoint");
            }

            var vaultUri = new Uri(value.AzureKeyVaultEndpoint);
            var credentials = value.Credentials ?? new DefaultAzureCredential();

            return new CertificateClient(vaultUri, credentials);
        }
        private static SecretClient CreateSecretClient(IOptions<AzureKeyVaultCertificateRepositoryOptions> options)
        {
            if (options is null)
            {
                throw new ArgumentNullException(nameof(options));
            }

            var value = options.Value;

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
