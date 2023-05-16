// Copyright (c) Nate McMaster.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

namespace LettuceEncrypt.Internal;

/// <summary>
/// Context returned from dns update
/// </summary>
public interface ITxtRecordContext
{
    /// <summary>
    /// Domain name for the txt record
    /// </summary>
    string DomainName { get; }
    /// <summary>
    /// TXT record Value
    /// </summary>
    string Txt { get; }
}
