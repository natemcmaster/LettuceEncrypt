// Copyright (c) Nate McMaster.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System.Threading;
using System.Threading.Tasks;

namespace LettuceEncrypt.Accounts
{
    /// <summary>
    /// Manages persistence and retrieval of account information.
    /// </summary>
    public interface IAccountStore
    {
        /// <summary>
        /// Save account information for reuse later after a server restart.
        /// </summary>
        /// <param name="account">All information in this model should round trip with <see cref="GetAccountAsync" />.</param>
        /// <param name="cancellationToken"></param>
        /// <returns></returns>
        Task SaveAccountAsync(AccountModel account, CancellationToken cancellationToken);

        /// <summary>
        /// Fetch account information.
        /// </summary>
        /// <param name="cancellationToken"></param>
        /// <returns>Should return null if no account could be found.</returns>
        Task<AccountModel?> GetAccountAsync(CancellationToken cancellationToken);
    }
}
