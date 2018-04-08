ASP.NET Core + Let's Encrypt
============================

The goal of this project is to make setting up HTTPS made easy.

[Let's Encrypt](https://letsencrypt.org/) is a free, automated, and open Certificate Authority.
This project provides API for ASP.NET Core projects to use Let's Encrypt.

When configured correctly, this API will automatically contact the <https://letsencrypt.org> CA and generate an TLS/SSL certificate. It then automatically configures Kestrel to use this certificate for all HTTPs traffic.

## Installation

Install this API using NuGet.
```
PM> Install-Package McMaster.AspNetCore.LetsEncrypt
```
```
dotnet add package McMaster.AspNetCore.LetsEncrypt
```

## Usage

The primary API usage is to call `IWebHostBuilder.UseLetsEncrypt` and set a few required options.

```csharp
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
                o.HostNames = new[] { "example.com" };
                o.AcceptTermsOfService = true;
                o.EmailAddress = "admin@example.com";
            })
            .UseStartup<Startup>();
}
```
