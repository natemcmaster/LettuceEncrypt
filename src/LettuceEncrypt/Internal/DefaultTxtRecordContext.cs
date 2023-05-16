// Copyright (c) Nate McMaster.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

namespace LettuceEncrypt.Internal;

/// <summary>
/// Default txt record context
/// </summary>
public class DefaultTxtRecordContext : ITxtRecordContext
{
    /// <summary>
    /// default constructor
    /// </summary>
    /// <param name="domainName">Domain name for the txt record</param>
    /// <param name="txt">TXT record Value</param>
    public DefaultTxtRecordContext(string domainName, string txt)
    {
        DomainName = domainName;
        Txt = txt;
    }

    /// <summary>
    /// Domain name for the txt record
    /// </summary>
    public string DomainName { get; }
    /// <summary>
    /// TXT record Value
    /// </summary>
    public string Txt { get; }
}
