// Copyright (c) Nate McMaster.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

#if NETCOREAPP3_1_OR_GREATER
using Microsoft.Extensions.Options;

namespace LettuceEncrypt.Internal;

internal class OptionsValdiation : IValidateOptions<LettuceEncryptOptions>
{
    public ValidateOptionsResult Validate(string name, LettuceEncryptOptions options)
    {
        foreach (var dnsName in options.DomainNames)
        {
            if (dnsName.IndexOf('*') >= 0)
            {
                return ValidateOptionsResult.Fail($"Cannot use '*' in domain name '{dnsName}'. Wildcard domains are not supported.");
            }
        }

        return ValidateOptionsResult.Success;
    }
}
#endif
