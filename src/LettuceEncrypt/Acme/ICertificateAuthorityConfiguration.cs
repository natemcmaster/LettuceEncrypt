// Copyright (c) Nate McMaster.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

namespace LettuceEncrypt.Acme;

/// <summary>
/// Provides configuration for the certificate authority which implements the ACME protocol.
/// </summary>
public interface ICertificateAuthorityConfiguration
{
    /// <summary>
    /// The base uri of the ACME protocol.
    /// </summary>
    Uri AcmeDirectoryUri { get; }

    /// <summary>
    /// Certificates passed to certes before building the successfully downloaded certificate,
    /// used internally by certes to verify the issuer for authenticity.
    /// </summary>
    /// <seealso cref="LettuceEncryptOptions.AdditionalIssuers" />
    public string[] IssuerCertificates => Array.Empty<string>();
}
