// Copyright (c) Nate McMaster.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using System.IO;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using LettuceEncrypt.Accounts;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;

#if NETSTANDARD2_0
using IHostEnvironment = Microsoft.Extensions.Hosting.IHostingEnvironment;
#endif

namespace LettuceEncrypt.Internal
{
    internal class FileSystemAccountStore : IAccountStore
    {
        private readonly DirectoryInfo _accountDir;
        private readonly ILogger _logger;

        public FileSystemAccountStore(
            ILogger logger,
            IOptions<LettuceEncryptOptions> options,
            IHostEnvironment env)
            : this(new DirectoryInfo(AppContext.BaseDirectory), logger, options, env)
        {
        }

        public FileSystemAccountStore(
            DirectoryInfo rootDirectory,
            ILogger logger,
            IOptions<LettuceEncryptOptions> options,
            IHostEnvironment env)
        {
            _logger = logger;

            var topAccountDir = rootDirectory.CreateSubdirectory("accounts");
            var directoryUri = options.Value.GetAcmeServer(env);
            var subPath = Path.Combine(directoryUri.Authority, directoryUri.LocalPath.Substring(1));
            _accountDir = topAccountDir.CreateSubdirectory(subPath);
        }

        public async Task<AccountModel?> GetAccountAsync(CancellationToken cancellationToken)
        {
            _logger.LogDebug("Looking for account information in {path}", _accountDir.FullName);

            foreach (var jsonFile in _accountDir.GetFiles("*.json"))
            {
                var item = await Deserialize(jsonFile, cancellationToken);
                if (item != null)
                {
                    return item;
                }
            }

            return default;
        }

        private async Task<AccountModel?> Deserialize(FileInfo jsonFile, CancellationToken cancellationToken)
        {
            using var log = _logger.BeginScope("parsing {filename}", jsonFile.FullName);
            using var fileStream = jsonFile.OpenRead();
            var deserializeOptions = new JsonSerializerOptions
            {
                PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
            };

            return await JsonSerializer.DeserializeAsync<AccountModel>(fileStream, deserializeOptions,
                cancellationToken);
        }

        public async Task SaveAccountAsync(AccountModel account, CancellationToken cancellationToken)
        {
            _accountDir.Create();

            var jsonFile = new FileInfo(Path.Combine(_accountDir.FullName, $"{account.Id}.json"));
            _logger.LogDebug("Saving account information to {path}", jsonFile.FullName);

            using var writeStream = jsonFile.OpenWrite();
            var serializerOptions = new JsonSerializerOptions
            {
                PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
            };
            await JsonSerializer.SerializeAsync(writeStream, account, serializerOptions, cancellationToken);
        }
    }
}
