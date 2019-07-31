// Copyright (c) Nate McMaster.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System.Security.Cryptography.X509Certificates;

namespace McMaster.AspNetCore.LetsEncrypt.Internal
{
    internal interface ICertificateStore
    {
        X509Certificate2? GetCertificate(string hostName);
        void Save(string hostName, X509Certificate2 certificate);
    }
}
