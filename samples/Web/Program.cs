using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;

namespace Web
{
    public class Program
    {
        public static void Main(string[] args)
        {
            CreateWebHostBuilder(args).Build().Run();
        }

        public static IWebHostBuilder CreateWebHostBuilder(string[] args) =>
            WebHost.CreateDefaultBuilder(args)
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
                       o.UseStagingServer = true;
                   })
                   .UseStartup<Startup>();
    }
}
