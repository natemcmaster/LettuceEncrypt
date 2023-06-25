// Copyright (c) Nate McMaster.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

namespace LettuceEncrypt.Internal.PfxBuilder;

internal sealed class PfxBuilderWrapper : IPfxBuilder
{
    private readonly Certes.Pkcs.PfxBuilder _pfxBuilder;

    public PfxBuilderWrapper(Certes.Pkcs.PfxBuilder pfxBuilder)
    {
        _pfxBuilder = pfxBuilder;
    }

    public void AddIssuer(byte[] certificate)
        => _pfxBuilder.AddIssuer(certificate);

    public byte[] Build(string friendlyName, string password)
        => _pfxBuilder.Build(friendlyName, password);
}
