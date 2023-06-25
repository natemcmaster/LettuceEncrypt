// Copyright (c) Nate McMaster.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using LettuceEncrypt.Acme;
using Microsoft.Extensions.Options;

namespace LettuceEncrypt.Internal;

internal class OptionsValidation : IValidateOptions<LettuceEncryptOptions>
{
    public ValidateOptionsResult Validate(string name, LettuceEncryptOptions options)
    {
        if (options.AllowedChallengeTypes == ChallengeType.Dns01)
            return ValidateOptionsResult.Success;

        foreach (var dnsName in options.DomainNames)
        {
            if (dnsName.Contains('*'))
            {
                return ValidateOptionsResult.Fail($"Cannot use '*' in domain name '{dnsName}'. Wildcard domains are not supported.");
            }
        }

        return ValidateOptionsResult.Success;
    }
}
