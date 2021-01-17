// Copyright (c) Nate McMaster.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using System.Threading.Tasks;
using Azure;
using Azure.Security.KeyVault.Secrets;
using Certes;
using LettuceEncrypt.Accounts;
using LettuceEncrypt.Acme;
using LettuceEncrypt.Azure.Internal;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Moq;
using Xunit;


namespace LettuceEncrypt.Azure.UnitTests
{
    public class AzureKeyVaultAccountStoreTests
    {
        private readonly ICertificateAuthorityConfiguration _mockCertificateAuthority;

        public AzureKeyVaultAccountStoreTests()
        {
            var mock = new Mock<ICertificateAuthorityConfiguration>();
            mock.Setup(g => g.AcmeDirectoryUri)
                .Returns(new Uri("https://acme-v02.api.letsencrypt.org/directory"));
            _mockCertificateAuthority = mock.Object;
        }

        [Fact]
        public async Task StoresAccountAsJsonSecret()
        {
            var (secretClient, secretClientFactory) = CreateMockClient();

            var store = new AzureKeyVaultAccountStore(
                NullLogger<AzureKeyVaultAccountStore>.Instance,
                Options.Create(new AzureKeyVaultLettuceEncryptOptions()),
                secretClientFactory,
                _mockCertificateAuthority);

            var accountModel = new AccountModel
            {
                Id = 1234,
                EmailAddresses = new[] { "test@example.com" },
                PrivateKey = KeyFactory.NewKey(Certes.KeyAlgorithm.ES512).ToDer(),
            };

            await store.SaveAccountAsync(accountModel, default);

            secretClient.Verify(c => c.SetSecretAsync(
                "le-account-acme-v02-api-letsencrypt-org",
                It.IsAny<string>(),
                default));
        }

        [Fact]
        public async Task ReturnsNullIfNoAccount()
        {
            var (secretClient, secretClientFactory) = CreateMockClient();

            var store = new AzureKeyVaultAccountStore(
                NullLogger<AzureKeyVaultAccountStore>.Instance,
                Options.Create(new AzureKeyVaultLettuceEncryptOptions()),
                secretClientFactory,
                _mockCertificateAuthority);

            secretClient.Setup(c =>
                    c.GetSecretAsync(It.IsAny<string>(),
                        null,
                        default))
                .Throws(new RequestFailedException(404, "Not found"));

            var account = await store.GetAccountAsync(default);

            Assert.Null(account);
        }

        [Fact]
        public async Task DeserializesAccountFromJsonSecret()
        {
            var name = "le-account-acme-v02-api-letsencrypt-org";
            var (secretClient, secretClientFactory) = CreateMockClient();

            var store = new AzureKeyVaultAccountStore(
                NullLogger<AzureKeyVaultAccountStore>.Instance,
                Options.Create(new AzureKeyVaultLettuceEncryptOptions()),
                secretClientFactory,
                _mockCertificateAuthority);
            var returnSecret = Response.FromValue(new KeyVaultSecret(name, SampleSecretValue), null);

            secretClient.Setup(c =>
                    c.GetSecretAsync(name,
                        null,
                        default))
                .Returns(Task.FromResult(returnSecret));

            var account = await store.GetAccountAsync(default);

            Assert.NotNull(account);
            Assert.Equal(1234, account.Id);
            var email = Assert.Single(account.EmailAddresses);
            Assert.Equal("test@example.com", email);
            Assert.NotEmpty(account.PrivateKey);
        }

        private const string SampleSecretValue =
            "{\"Id\":1234,\"EmailAddresses\":[\"test@example.com\"],\"PrivateKey\":\"MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCr+J/AVPtOt3Py1C5jXQTFqO1HC3HZgnNPDrSXUOgIUoPytpm2vBUCXELVeSfrdNXIYuLPDX6m7pcr7H7dgkKPseGJQLF9VqGSTB1TPXw2Q7UBcVCA3YLLxKNoJfZy7PxFw85Bg65uHL7Za/tI0xk59FyPZTb0JpoZyqrXKhOrJbBdTSlJyDMQWcE1MVXu8AcqWRYE1b5V89viqys7NUSCElm5BYLDZDDNo2L8k/+ZQ/gCV/y8ANKopg1Y4saoyU4JjzAkXnul4+U2tU6VmjcI5DcjpHg3fxIaS3zVoA0qV5a6vh5n9ngMIRsPKArA6D4G0DZt0Jn2wxYMOOOkJcwFAgMBAAECggEAQ4iM78JPuG9prMQvfVzTmW3H1H0FliXY84RyXfPrUw1YfNHBlpXQ6E7j/iIoj5oftCRFLot9n7+VhS3H+mQDkJuJ1tUdfnutUp7qazx7kXHQXMMrmpeinDPZ+fXijOpM/XayAl9ceih2uDpkAYrI3s38JWHZjVK1dIh2w61l8PDkY6f7gGVNP4cKIEvwDJMkC+3RnPVBSVUQTTxR/o7QgWNAL9OUD++MwTC4k9szcIb/ZoXdF4DmTKJaUj9SsOv651NXKVAOZ4P+2eMSlYqM4rx5QEDBT9dHsxICMKHLiB3nfcogLWPFV0S+oWzb3KFD+7+4i2UHvo0zrKcAnk/bZwKBgQDgMJU1D1irB7dr134+X8v18DbWhT4E5CWYVmIkv054exlFegWGqMlg8gU0UIazwTw31q+NVYLIyR+s2INHGcS5YAcxd2Lr2EZJtQGKskCCpaOqemq2mBvsssYLMS1Q9qNvEt+0Rb2ZcgjDeOTForHbnTWvEy0ItGvK2zSSFv/tewKBgQDEX0PtFSQ4tBO8vInLNMVWEHjmjMdX0biGACvPDkXjqgft3W65tTMGAHTrbgowm1gv/8Jmiz3RZiAtZd92KpJfFbjPRuPNHtp+f1xG50NhIPeMf+fm8pe8PJQCNxEKGPZC50ym8bx3LtdTJ2Ylasr3Tvawe80mOVq884xARTY0fwKBgQCEcK70lYhQIVLeRoOx3W3kcHA08qncwdrjz8RS6SE2U6JuRNOW5Ydx2gfxC9FHx9QHOLCk0etdKlOoDJAhJLvutygItPqfUTjUujWa9greI3Q4dfEsxVdZ0ZLlcbvPpKSQLZoyKTEEwTUkJPshNifUEV9xeeaUyeEUCcNYunWemQKBgACMX40u7O33msKBKEVX/WETJLNIG1pkbIZ7Q6QNXyaWl/UTFDcSiXTv1WO+5+pg1Ks1pJ5SrzaBeX+G9EvJLKV1UxHJGeO9vVBzHJfaF3cS93398XDUppXQ+XzUGIkVrsJbEPy6WhNfHxzNVFywYqa0Ir41ako8CMPUTkTzrIYTAoGAJDHdTQlvWDBkpqOT8utjb3DBhU1dAnETwxTEqLp6abXv8w4pC/BTIGVQZV2GVPAqqQkEooWaVnvt82VeMFfwwvNUOt6u8duEOp1NUUM55yBDzM6BOF+Aa7t7fKZvx/Ef9XnaUy5F3NYSQzlxGOjwcZC3LmvuPttCAc2dGXeEvz0=\"}";

        private (Mock<SecretClient>, ISecretClientFactory) CreateMockClient()
        {
            var secretClient = new Mock<SecretClient>();
            var secretClientFactory = new Mock<ISecretClientFactory>();
            secretClientFactory.Setup(c => c.Create()).Returns(secretClient.Object);
            return (secretClient, secretClientFactory.Object);
        }
    }
}
