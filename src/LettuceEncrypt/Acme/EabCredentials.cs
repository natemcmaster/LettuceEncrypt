// Copyright (c) Nate McMaster.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

namespace LettuceEncrypt.Acme;

/// <summary>
/// External Account Binding (EAB) account credentials
/// </summary>
public class EabCredentials
{
    /// <summary>
    /// Optional key identifier for external account binding
    /// </summary>
    public string? EabKeyId { get; set; }

    /// <summary>
    /// Optional key for use with external account binding
    /// </summary>
    public string? EabKey { get; set; }

    /// <summary>
    /// Optional key algorithm e.g HS256, for external account binding
    /// </summary>
    public string? EabKeyAlg { get; set; }
}
