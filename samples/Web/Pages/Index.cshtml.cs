using System.Security.Cryptography.X509Certificates;
using McMaster.AspNetCore.LetsEncrypt.Diagnostics;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace Web.Pages
{
    public class IndexModel : PageModel
    {
        private readonly CertificateInspector _certificateInspector;
        private X509Certificate2 _cert;

        public IndexModel(CertificateInspector certificateInspector)
        {
            _certificateInspector = certificateInspector;
        }

        public string DomainName { get; set; }

        public X509Certificate2 Cert => _cert;

        public void OnGet()
        {
            DomainName = HttpContext.Request.Host.Host;
            _certificateInspector.TryGetCertByDomainName(DomainName, out _cert);
        }
    }
}
