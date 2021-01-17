// Copyright (c) Nate McMaster.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

#nullable enable
using System;
using System.IO;
using System.Text.Json;
using System.Threading.Tasks;
using Certes;
using LettuceEncrypt.Accounts;
using LettuceEncrypt.Internal;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Moq;
using Xunit;

#if NETCOREAPP2_1
using IHostEnvironment = Microsoft.Extensions.Hosting.IHostingEnvironment;
#endif

namespace LettuceEncrypt.UnitTests
{
    public class FileSystemAccountStoreTests : IDisposable
    {
        private readonly DirectoryInfo _testDir =
            new(Path.Combine(AppContext.BaseDirectory, Path.GetRandomFileName()));

        public void Dispose()
        {
            _testDir.Delete(recursive: true);
        }

        [Fact]
        public void ItWritesCreatesSubdir()
        {
            CreateStore();

            Assert.True(Directory.Exists($"{_testDir}/accounts/acme-staging-v02.api.letsencrypt.org/directory/"));
        }

        [Fact]
        public async Task ItReturnsNullForNoAccountAsync()
        {
            var store = CreateStore();

            Assert.Null(await store.GetAccountAsync(default));
        }

        [Fact]
        public async Task ItStoresAsJson()
        {
            var store = CreateStore();
            var key = KeyFactory.NewKey(Certes.KeyAlgorithm.RS256);
            var bytes = key.ToDer();

            var account = new AccountModel
            {
                Id = 1,
                EmailAddresses = new[] { "test@test.com" },
                PrivateKey = bytes,
            };

            await store.SaveAccountAsync(account, default);

            var jsonFile =
                new FileInfo(
                    Path.Combine(_testDir.FullName, "accounts/acme-staging-v02.api.letsencrypt.org/directory/1.json"));
            Assert.True(jsonFile.Exists);
            using var readStream = jsonFile.OpenRead();
            var doc = await JsonDocument.ParseAsync(readStream);
            Assert.Equal(JsonValueKind.Object, doc.RootElement.ValueKind);
        }

        [Fact]
        public async Task ItParsesJson()
        {
            const string TestJson = @"
{
    ""id"": 1,
    ""emailAddresses"": [
        ""test@test.com""
    ],
    ""privateKey"": ""MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCeM90BxLItcyEFJh/WrqYCpMtFLOuV0smrJMJKhHXnQNGR+MEH4LKvJf0SOLnUfKGSqHzoG16wakrJQpUXKEGHWIdCdtHOnwnP1A52JGyPipx7CU8dILN7EtHg/j2t5Z/XuG28ua0rz6WODBLQyV3/UuzXVAaEfWNL+49Az0sbJEetE2xVeKe22rZuMYeblLsoLGs9b4PBimkjmB5x0q2kJKX3OZh1i0qZwSOEb0+uIWYhoy+TZ7hcJJI3xKjbulHFoLdbUvrnTsf746R58j6HVpdfHK9D4AYJ27Cz+LAbVKXhR4aSahDr5f6NraLpaDq8KTPwfAl6kaUW41Z5iGOrAgMBAAECggEAER9B2zAjrKGaQElpBr4uP3kAewMqmDORGhHHaXM+o4GzbN4EXkrma+hrpG45RpMalZngsupLbEKEx5WKN1BnDzP4p6ved0NlN3YW/phgm4R//Rz70AY7BqX5yyUZHdoNW7adQeDCqkw1+dK6spgosTqTYZa5gdtkRNP8JCKLWWt+psWG27c6xJlxWaQtsdrmrj2lB09sgmEDJRjZcS+QK/5NKXfhFV01N9A3BdxFGZzJ3CHoEkvaINnlc8YnDBBG/G9WIeF0/p+KTvkppMxWk4QUrgKzcXgP1PsfHE4kUvN5LZcEzw/C5DNN4Fm7NycaApk8KdL/fTeHgGX+anqZqQKBgQDsydiJuzxQvomMsd1ykoEu5wZw7pXNWUrk4+nLIZ1B/99X2nsl7iGUa4t75X0gBj9E73IpsGlGS2j5B+fRZ+kcpWROl+AUk1lCgknLthtsKQxrgBVKW99NK7muACJTmvOYS96o0fK64mDQquMn0GniwhFwX1aHpIbUEJQMfP25FwKBgQCrCcUO82EsEBgRQyYWxEN+pIiksxjzvAjj/yYYVn0MzuDR0eyEUEED2Xx5GH45Z6TK3fYdFiORntNoeYpgxj1NELRuNJygYQFKMYtjQEjlEbcNuy0Fi5baijiHUyyP7dps76sd2SHof+UJX5Mq59Mr/d+mS1bC5u6/RSC8tKVejQKBgQCxqwoU3i51j2H59YNpclAH90S3++ze9b7iW7iSuBgc63aTntWEMldz2/X+8sSeANH8UYXhjgKPwglzweDJGSSqX9cRuZdjGOSCqOviNDQDRhGRn7tZ3fGBH+vkiSk4fi2E+niJR27Plwh5yZ9DwneQs3kOThrJEEQyXnYXoLln5QKBgQCYDp96ozUIj2ZWMnRyWRoIRQ6WHgNY7RqaWAPuLzYNZP7Kiu7S0uZ6HahjoDrXniULljlvsnb8x0772tIDJzrogKloMK3uh082PsXE/ynPPOiY9IcaHveGYsvOw0siyjseDhT6/EcBBHMC2k1kH6XFvnZOyTvhGp22viZUneVHIQKBgFqJweAApLjG+NuLhJXt1VccGwfPg4ilJJhizzk8Orl2A37Nav2pbY+z1d6Asuj3RwgqZx3yb8OQLhrQrkQ5h9YBEfX3l8wNCOwnYH43/QonpHnpC9aUPiQp27veFl4v1zkXSL86Il8d0qGZ+boKkeUMirmb/4lwpyZ3ApXJhcHL""
}";
            var jsonFile = Path.Combine(_testDir.FullName,
                "accounts/acme-staging-v02.api.letsencrypt.org/directory/1.json");
            Directory.CreateDirectory(Path.GetDirectoryName(jsonFile));
            await File.WriteAllTextAsync(jsonFile, TestJson);

            var store = CreateStore();
            var account = await store.GetAccountAsync(default);

            Assert.NotNull(account);
            Assert.Equal(1, account!.Id);
            var email = Assert.Single(account.EmailAddresses);
            Assert.Equal("test@test.com", email);
            Assert.NotNull(account.Key);
        }

        private FileSystemAccountStore CreateStore()
        {
            var options = Options.Create(new LettuceEncryptOptions
            {
                UseStagingServer = true
            });
            var mockCertificateAuthority =
                new DefaultCertificateAuthorityConfiguration(Mock.Of<IHostEnvironment>(), options);

            return new FileSystemAccountStore(
                _testDir,
                NullLogger<FileSystemAccountStore>.Instance,
                mockCertificateAuthority);
        }
    }
}
