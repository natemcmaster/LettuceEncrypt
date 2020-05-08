using McMaster.AspNetCore.LetsEncrypt;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Configuration;
using System;
namespace Web
{
    public class Startup
    {
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddLetsEncrypt();
        }

        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }
            app.UseHttpsRedirection();

            app.UseRouting();

            app.UseEndpoints(endpoints =>
            {
                endpoints.MapGet("/", async context =>
                {
                     await context.Response.WriteAsync("<h1>Hello World!</h1>"+"<h4>BUILT FROM COMMIT: "+Environment.GetEnvironmentVariable("commitSHA")+"</h4>"+"<img src='https://camo.githubusercontent.com/cb1052f5d3a491516ed9b081c3849582dd636fa1/68747470733a2f2f6c657473656e63727970742e6f72672f696d616765732f6c652d6c6f676f2d776964652e706e67' alt='Let's Encrypt'>");
                });
            });
        }
    }
}
