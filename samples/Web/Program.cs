using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Hosting;

namespace Web
{
    public class Program
    {
        public static void Main(string[] args)
        {
            CreateHostBuilder(args).Build().Run();
        }

        public static IHostBuilder CreateHostBuilder(string[] args) =>
            Host.CreateDefaultBuilder(args)
                .ConfigureWebHostDefaults(webBuilder =>
                {
                    webBuilder.UseStartup<Startup>();
                })
                .UseLetsEncrypt(o =>
                {
                    // The domain names for which to generate certificates
                    o.HostNames = new[] { "example.com" };

                    // Set this to automatically accept Let's Encrypt's terms of service
                    o.AcceptTermsOfService = true;

                    // The email address to register with your application
                    o.EmailAddress = "admin@example.com";

                    // Use the staging server when developing your app
                    // to avoid rate limits until you're app is ready for production
                    // if you omit this setting, the staging server will be used by default when
                    // the host environment name is 'Development', but otherwise uses Let's Encrypt
                    // production servers.
                    o.UseStagingServer = true;
                });

    }
}
