// Copyright (c) Nate McMaster.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

namespace LettuceEncrypt.Internal.PfxBuilder;

internal interface IPfxBuilder
{
    void AddIssuer(byte[] certificate);

    byte[] Build(string friendlyName, string password);
}
