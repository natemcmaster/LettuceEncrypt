// Copyright (c) Nate McMaster.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System.Diagnostics.CodeAnalysis;

namespace LettuceEncrypt.Internal
{
    internal interface IHttpChallengeResponseStore
    {
        void AddChallengeResponse(string token, string response);

        bool TryGetResponse(string token, [MaybeNullWhen(false)] out string? value);
    }
}
