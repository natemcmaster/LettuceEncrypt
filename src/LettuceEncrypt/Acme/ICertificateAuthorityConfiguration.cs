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
    /// <remarks>
    /// Lettuce encrypt uses certes internally, while certes depends on BouncyCastle.Cryptography to parse
    /// certificates. See https://github.com/bcgit/bc-csharp/blob/830d9b8c7bdfcec511bff0a6cf4a0e8ed568e7c1/crypto/src/x509/X509CertificateParser.cs#L20
    /// if you're wondering what certificate formats are supported.
    /// </remarks>
    /// <seealso cref="LettuceEncryptOptions.AdditionalIssuers" />
    string[] IssuerCertificates => Array.Empty<string>();
}
