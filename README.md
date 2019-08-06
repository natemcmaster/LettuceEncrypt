ASP.NET Core + Let's Encrypt
============================

The goal of this project is to make setting up HTTPS made easy.

[Let's Encrypt](https://letsencrypt.org/) is a free, automated, and open Certificate Authority.
This project provides API for ASP.NET Core projects to use Let's Encrypt.

When configured correctly, this API will automatically contact the <https://letsencrypt.org> CA and generate an TLS/SSL certificate. It then automatically configures Kestrel to use this certificate for all HTTPs traffic.

## Usage

The primary API usage is to call `IServiceColleciton.AddLetsEncrypt` in the `Startup` class `ConfigureServices` method.

```csharp
public class Startup
{
    public void ConfigureServices(IServiceCollection services)
    {
        services.AddLetsEncrypt();
    }
}
```

A few required options should be set, typically via the appsettings.json file.

```jsonc
// appsettings.json
{
    "LetsEncrypt": {
        // Set this to automatically accept Let's Encrypt's terms of service.
        // If you don't set this in config, you will need to press "y" whenever the application starts
        "AcceptTermsOfService": true,

        // You must at least one domain name
        "DomainNames": [ "example.com", "www.example.com" ],

        // You must specify an email address to register with letsencrypt.org
        "EmailAddress": "it-admin@example.com"
    }
}
```

## Testing in development

See the [developer docs](./CONTRIBUTING.md) for details on how to test Let's Encrypt in a non-production environment.
