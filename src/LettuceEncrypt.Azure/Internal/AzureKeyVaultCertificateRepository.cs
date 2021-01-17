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
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace LettuceEncrypt.Azure.Internal
{
    internal class AzureKeyVaultCertificateRepository : ICertificateRepository, ICertificateSource
    {
        private readonly IOptions<LettuceEncryptOptions> _encryptOptions;
        private readonly ILogger<AzureKeyVaultCertificateRepository> _logger;
        private readonly ICertificateClientFactory _certificateClientFactory;
        private readonly ISecretClientFactory _secretClientFactory;

        public AzureKeyVaultCertificateRepository(
            ICertificateClientFactory certificateClientFactory,
            ISecretClientFactory secretClientFactory,
            IOptions<LettuceEncryptOptions> encryptOptions,
            ILogger<AzureKeyVaultCertificateRepository> logger)
        {
            _certificateClientFactory = certificateClientFactory ??
                                        throw new ArgumentNullException(nameof(_certificateClientFactory));
            _secretClientFactory = secretClientFactory ?? throw new ArgumentNullException(nameof(secretClientFactory));
            _encryptOptions = encryptOptions ?? throw new ArgumentNullException(nameof(encryptOptions));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        public async Task<IEnumerable<X509Certificate2>> GetCertificatesAsync(CancellationToken cancellationToken)
        {
            var certs = new List<X509Certificate2>();

            foreach (var domain in _encryptOptions.Value.DomainNames)
            {
                var cert = await GetCertificateWithPrivateKeyAsync(domain, cancellationToken);

                if (cert != null)
                {
                    certs.Add(cert);
                }
            }

            return certs;
        }

        private async Task<X509Certificate2?> GetCertificateAsync(string domainName, CancellationToken token)
        {
            _logger.LogInformation("Searching for certificate in KeyVault for {domainName}", domainName);

            try
            {
                var normalizedName = NormalizeHostName(domainName);
                var certificateClient = _certificateClientFactory.Create();

                var certificate = await certificateClient.GetCertificateAsync(normalizedName, token);

                return new X509Certificate2(certificate.Value.Cer);
            }
            catch (RequestFailedException ex) when (ex.Status == 404)
            {
                _logger.LogWarning("Could not find certificate for {domainName} in Azure KeyVault", domainName);
            }
            catch (CredentialUnavailableException ex)
            {
                _logger.LogError(ex, "Could not retrieve credentials for Azure Key Vault");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex,
                    "Unexpected error attempting to retrieve certificate for {domainName} from Azure KeyVault. Verify settings and try again.",
                    domainName);
            }

            return null;
        }

        private async Task<X509Certificate2?> GetCertificateWithPrivateKeyAsync(string domainName, CancellationToken token)
        {
            _logger.LogDebug("Searching for certificate in KeyVault for {domainName}", domainName);

            try
            {
                var normalizedName = NormalizeHostName(domainName);
                var secretClient = _secretClientFactory.Create();

                var certificate = await secretClient.GetSecretAsync(normalizedName, null, token);

                var cert = new X509Certificate2(Convert.FromBase64String(certificate.Value.Value));

                _logger.LogInformation(
                    "Found certificate for {domainName} from Azure Key Vault with thumbprint {thumbprint}",
                    domainName, cert.Thumbprint);

                return cert;
            }
            catch (RequestFailedException ex) when (ex.Status == 404)
            {
                _logger.LogInformation("Could not find certificate for {domainName} in Azure KeyVault", domainName);
            }
            catch (CredentialUnavailableException ex)
            {
                _logger.LogError(ex, "Could not retrieve credentials for Azure Key Vault");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex,
                    "Unexpected error attempting to retrieve certificate for {domainName} from Azure KeyVault. Verify settings and try again.",
                    domainName);
            }

            return null;
        }

        public async Task SaveAsync(X509Certificate2 certificate, CancellationToken cancellationToken)
        {
            var domainName = certificate.GetNameInfo(X509NameType.DnsName, false);

            _logger.LogInformation("Saving certificate for {domainName} in Azure KeyVault.", domainName);

            if (!await ShouldImportVersionAsync(domainName, certificate, cancellationToken))
            {
                _logger.LogInformation(
                    "Certificate for {domainName} is already up-to-date in Azure KeyVault. Skipping importing.",
                    domainName);
                return;
            }

            byte[] exported;
            try
            {
                exported = certificate.Export(X509ContentType.Pfx);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to export {domainName} certificate", domainName);
                return;
            }

            var options = new ImportCertificateOptions(NormalizeHostName(domainName), exported);

            try
            {
                var certificateClient = _certificateClientFactory.Create();

                await certificateClient.ImportCertificateAsync(options, cancellationToken);

                _logger.LogInformation("Imported certificate into Azure KeyVault for {domainName}", domainName);
            }
            catch (RequestFailedException ex)
            {
                _logger.LogWarning(ex, "Failed to save {domainName} certificate to Azure KeyVault", domainName);
            }
        }

        private async ValueTask<bool> ShouldImportVersionAsync(string domainName, X509Certificate2 certificate,
            CancellationToken token)
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
    }
}
