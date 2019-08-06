using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace Web
{
    public class Startup
    {
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddLetsEncrypt(o =>
                {
                    o.DomainName = "example.com";

                    // If this server hosts multiple sites, specify them here.
                    o.AdditionalDomainNames.Add("www.example.com");
                    o.AdditionalDomainNames.Add("www2.example.com");

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

        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }

            app.UseRouting();

            app.UseEndpoints(endpoints =>
            {
                endpoints.MapGet("/", async context =>
                {
                    await context.Response.WriteAsync("Hello World!");
                });
            });
        }
    }
}
