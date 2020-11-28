using System;
using System.Threading.Tasks;
using Certes.Acme;
using LettuceEncrypt.Accounts;
using LettuceEncrypt.Acme;
using LettuceEncrypt.Internal;
using LettuceEncrypt.Internal.AcmeStates;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Moq;
using Xunit;

namespace LettuceEncrypt.UnitTests
{
    public class CreateAcmeAccountStateTests
    {
        [Fact]
        public async Task ItSavesAccount()
        {
            var emailAddress = "alice@example.com";
            var services = Mock.Of<IServiceProvider>(s =>
                s.GetService(typeof(GenerateCertificateState)) == default(GenerateCertificateState));
            var context = new AcmeStateMachineContext(services);
            var options = Options.Create(new LettuceEncryptOptions
            {
                EmailAddress = emailAddress,
                AcceptTermsOfService = true,
            });
            var acmeClient = new Mock<IAcmeClient>();
            var accountContext = Mock.Of<IAccountContext>(
                a => a.Location == new Uri("https://localhost/account/123"));
            var acmeClientFactory = new Mock<IAcmeClientFactory>();
            var certificateAuthority = Mock.Of<ICertificateAuthorityConfiguration>();
            var accountStore = new Mock<IAccountStore>();
            var state = new CreateAcmeAccountState(
                context,
                NullLogger<CreateAcmeAccountState>.Instance,
                options,
                acmeClientFactory.Object,
                Mock.Of<ITermsOfServiceChecker>(),
                certificateAuthority,
                accountStore.Object);

            acmeClient
                .Setup(c => c.CreateAccountAsync(emailAddress))
                .ReturnsAsync(accountContext);
            acmeClientFactory
                .Setup(a => a.Create(It.IsAny<Certes.IKey>()))
                .Returns(acmeClient.Object);
            accountStore.Setup(a => a.SaveAccountAsync(It.Is<AccountModel>(m => m.Id == 123), default));

            var nextState = await state.MoveNextAsync(default);

            Assert.IsType<GenerateCertificateState>(nextState);
            acmeClient.VerifyAll();
            acmeClientFactory.VerifyAll();
            accountStore.VerifyAll();
        }
    }
}
