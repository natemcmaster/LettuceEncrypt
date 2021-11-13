// Copyright (c) Nate McMaster.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using LettuceEncrypt.Acme;
using Xunit;

namespace LettuceEncrypt.UnitTests;

public class ChallengeTypeTests
{
    [Fact]
    public void AnyIsAlwaysTrue()
    {
        Assert.True(ChallengeType.Any.HasFlag(ChallengeType.Http01));
        Assert.True(ChallengeType.Any.HasFlag(ChallengeType.TlsAlpn01));
        Assert.True(ChallengeType.Any.HasFlag(ChallengeType.Any));
    }
}
