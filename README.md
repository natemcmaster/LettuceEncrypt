ASP.NET Core + Let's Encrypt
============================

The goal of this project is to make setting up HTTPS made easy.

[Let's Encrypt](https://letsencrypt.org/) is a free, automated, and open Certificate Authority.
This project provides API for ASP.NET Core projects to use Let's Encrypt.

When configured correctly, this API will automatically contact the <https://letsencrypt.org> CA and generate an TLS/SSL certificate. It then automatically configures Kestrel to use this certificate for all HTTPs traffic.

## Usage

The primary API usage is to call `IServiceColleciton.AddLetsEncrypt` and set a few required options.

```csharp
public class Startup
{
    public void ConfigureServices(IServiceCollection services)
    {
        services.AddLetsEncrypt(o =>
            {
                // Must be set.
                o.DomainName = "example.com";

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
```

## Testing in development

See the [developer docs](./CONTRIBUTING.md) for details on how to test Let's Encrypt in a non-production environment.
