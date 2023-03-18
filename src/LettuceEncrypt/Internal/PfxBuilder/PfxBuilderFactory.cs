// Copyright (c) Nate McMaster.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using Certes;
using Certes.Acme;

namespace LettuceEncrypt.Internal.PfxBuilder;

internal sealed class PfxBuilderFactory : IPfxBuilderFactory
{
    public IPfxBuilder FromChain(CertificateChain certificateChain, IKey certKey)
        => new PfxBuilderWrapper(certificateChain.ToPfx(certKey));
}
