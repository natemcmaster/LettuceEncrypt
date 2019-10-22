// Copyright (c) Nate McMaster.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System.Collections.Concurrent;

namespace McMaster.AspNetCore.LetsEncrypt.Internal
{
    internal class InMemoryHttpChallengeResponseStore : IHttpChallengeResponseStore
    {
        private readonly ConcurrentDictionary<string, string> _values
            = new ConcurrentDictionary<string, string>();

        public void AddChallengeResponse(string token, string response)
            => _values.AddOrUpdate(token, response, (_, __) => response);

#pragma warning disable CS8601
        // it seems like there is a bug in C# 8 with out parameters which causes a warning here that I can't figure
        // out how to resolve, so suppressing and moving on.
        public bool TryGetResponse(string token, out string value)
            => _values.TryGetValue(token, out value);
#pragma warning restore CS8601
    }
}
