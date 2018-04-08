using System.Security.Cryptography.X509Certificates;

namespace McMaster.AspNetCore.LetsEncrypt.Internal
{
    public interface ICertificateStore
    {
        X509Certificate2 GetCertificate(string hostName);
        void Save(string hostName, X509Certificate2 certificate);
    }
}
