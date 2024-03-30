// Copyright (c) Nate McMaster.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace LettuceEncrypt.UnitTests;

public class TestUtils
{
    public static X509Certificate2 CreateTestCert(string commonName, DateTimeOffset? expires = null)
    {
        return CreateTestCert(new[] { commonName }, expires);
    }

    public static X509Certificate2 CreateTestCert(string[] domainNames, DateTimeOffset? expires = null)
    {
        expires ??= DateTimeOffset.Now.AddMinutes(10);
        var key = RSA.Create(2048);
        var csr = new CertificateRequest(
            "CN=" + domainNames[0],
            key,
            HashAlgorithmName.SHA512,
            RSASignaturePadding.Pkcs1);

        if (domainNames.Length > 1)
        {
            var sanBuilder = new SubjectAlternativeNameBuilder();
            foreach (var san in domainNames.Skip(1))
            {
                sanBuilder.AddDnsName(san);
            }

            csr.CertificateExtensions.Add(sanBuilder.Build());
        }

        var cert = csr.CreateSelfSigned(DateTimeOffset.Now.AddMinutes(-1), expires.Value);
        int retries = 5;
        while (retries > 0)
        {
            try
            {
                // https://github.com/dotnet/runtime/issues/29144
                var certWithKey = cert.Export(X509ContentType.Pfx);
                return new X509Certificate2(certWithKey, "", X509KeyStorageFlags.PersistKeySet | X509KeyStorageFlags.Exportable);
            }
            catch
            {
                retries--;
                if (retries > 0)
                {
                    // For unclear reasons, on macOS it takes times for certs to be available for re-export.
                    // Retries appear to work.
                    Thread.Sleep(50);
                    continue;
                }
                else
                {
                    throw;
                }
            }
        }
        throw new Exception($"Could not create self signed cert for {domainNames}");
    }
}
