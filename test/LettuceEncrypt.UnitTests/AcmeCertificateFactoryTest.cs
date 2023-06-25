// Copyright (c) Nate McMaster.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System.Collections.Immutable;
using System.Text;
using Certes;
using Certes.Acme;
using LettuceEncrypt.Acme;
using LettuceEncrypt.Internal;
using LettuceEncrypt.Internal.PfxBuilder;
using Microsoft.Extensions.Hosting.Internal;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Xunit;

namespace LettuceEncrypt.UnitTests;

public sealed class AcmeCertificateFactoryTest
{
    private static readonly byte[] TestBytes1 = { 0x01, 0x01, 0x01, 0x01, 0x01 };
    private static readonly byte[] TestBytes2 = { 0x02, 0x02, 0x02 };
    private static readonly byte[] TestBytes3 = { 0x03 };
    private static readonly byte[] TestBytes4 = { 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04 };

    [Theory]
    [MemberData(nameof(AdditionalIssuerTestData))]
    public void PassedConfiguredAdditionalValidIssuers(
        LettuceEncryptOptions options,
        ICertificateAuthorityConfiguration certificateAuthority,
        IReadOnlyCollection<byte[]> expectedAdditionalIssuers)
    {
        var pfxBuilderStub = new PfxBuilderStub();
        var acmeCertificateFactory = CreateAcmeCertificateFactory(options, certificateAuthority, pfxBuilderStub);

        // This test verifies if the configured issuers are passed to the builder.
        // The rest of the data does not impact the test and is therefore nulled or stubbed out.
        _ = acmeCertificateFactory.CreatePfxBuilder(certificateChain: null!, certKey: null!);

        Assert.Equal(expectedAdditionalIssuers, pfxBuilderStub.Issuers);
    }

    public static TheoryData<LettuceEncryptOptions, ICertificateAuthorityConfiguration, IReadOnlyCollection<byte[]>> AdditionalIssuerTestData()
        => new()
        {
            {
                new LettuceEncryptOptions() { AdditionalIssuers = new[] { Encoding.UTF8.GetString(TestBytes1), Encoding.UTF8.GetString(TestBytes2), Encoding.UTF8.GetString(TestBytes3) } },
                new DefaultCertificateAuthorityConfiguration(new HostingEnvironment(), Options.Create(new LettuceEncryptOptions())),
                ImmutableArray.Create(TestBytes1, TestBytes2, TestBytes3)
            },
            {
                new LettuceEncryptOptions(),
                new StubCertificateAuthorityConfiguration(new[] { Encoding.UTF8.GetString(TestBytes1), Encoding.UTF8.GetString(TestBytes2), Encoding.UTF8.GetString(TestBytes3) }),
                ImmutableArray.Create(TestBytes1, TestBytes2, TestBytes3)
            },
            {
                new LettuceEncryptOptions { AdditionalIssuers = new[] { Encoding.UTF8.GetString(TestBytes1), Encoding.UTF8.GetString(TestBytes3) } },
                new StubCertificateAuthorityConfiguration(new[] { Encoding.UTF8.GetString(TestBytes2), Encoding.UTF8.GetString(TestBytes4) }),
                ImmutableArray.Create(TestBytes1, TestBytes3, TestBytes2, TestBytes4)
            },
        };

    private static AcmeCertificateFactory CreateAcmeCertificateFactory(
        LettuceEncryptOptions options,
        ICertificateAuthorityConfiguration certificateAuthority,
        IPfxBuilder pfxBuilder)
    {
        return new AcmeCertificateFactory(
            acmeClientFactory: null!,
            tosChecker: null!,
            options: Options.Create(options),
            challengeStore: null!,
            logger: NullLogger<AcmeCertificateFactory>.Instance,
            appLifetime: new ApplicationLifetime(NullLogger<ApplicationLifetime>.Instance),
            tlsAlpnChallengeResponder: null!,
            dnsChallengeProvider: new NoOpDnsChallengeProvider(),
            certificateAuthority: certificateAuthority,
            pfxBuilderFactory: new PfxBuilderFactoryStub(pfxBuilder));
    }

    private sealed class PfxBuilderFactoryStub : IPfxBuilderFactory
    {
        private readonly IPfxBuilder _stub;

        public PfxBuilderFactoryStub(IPfxBuilder stub)
        {
            _stub = stub;
        }

        public IPfxBuilder FromChain(CertificateChain certificateChain, IKey certKey)
            => _stub;
    }

    private sealed class PfxBuilderStub : IPfxBuilder
    {
        public IList<byte[]> Issuers { get; } = new List<byte[]>();

        public void AddIssuer(byte[] certificate)
            => Issuers.Add(certificate);

        public byte[] Build(string friendlyName, string password)
            => throw new NotSupportedException();
    }

    private sealed class StubCertificateAuthorityConfiguration : ICertificateAuthorityConfiguration
    {
        public StubCertificateAuthorityConfiguration(string[] issuerCertificates)
        {
            IssuerCertificates = issuerCertificates;
        }

        public Uri AcmeDirectoryUri => WellKnownServers.LetsEncryptStagingV2;

        public string[] IssuerCertificates { get; }
    }
}
