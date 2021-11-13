﻿// Copyright (c) Nate McMaster.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

namespace LettuceEncrypt.Internal.IO;

internal class SystemClock : IClock
{
    public DateTimeOffset Now => DateTimeOffset.Now;
}
