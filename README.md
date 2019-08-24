ASP.NET Core + Let's Encrypt
============================

<div>
   <p align="center"><img src="https://letsencrypt.org/images/le-logo-wide.png" width="300" /></p>
   <p align="center">
HTTPS made easy.
    </p>
</div>

---------------------------

[![Build Status][azdo-badge]][azdo-url] [![Nuget][nuget-badge]][nuget-url]

[azdo-badge]: https://dev.azure.com/natemcmaster/github/_apis/build/status/LetsEncrypt?branchName=master
[azdo-url]: https://dev.azure.com/natemcmaster/github/_build/latest?definitionId=10&branchName=master
[nuget-badge]: https://img.shields.io/nuget/v/McMaster.AspNetCore.LetsEncrypt?color=blue
[nuget-url]: https://nuget.org/packages/McMaster.AspNetCore.LetsEncrypt

[Let's Encrypt](https://letsencrypt.org/) is a free, automated, and open Certificate Authority.
This project provides API for ASP.NET Core projects to use Let's Encrypt.

When enabled, your web server will use the Let's Encrypt certificate authority
and **automatically** generate an HTTPS certificate when the server starts up. It then configures Kestrel to use this certificate for all HTTPs traffic.

## Usage

> :warning: This only works with [Kestrel](https://docs.microsoft.com/en-us/aspnet/core/fundamentals/servers/kestrel), which is the default server configuration for ASP.NET Core projects. Other servers, such as IIS and nginx, are not supported.

The primary API usage is to call `IServiceCollection.AddLetsEncrypt` in the `Startup` class `ConfigureServices` method.

```csharp
using Microsoft.Extensions.DependencyInjection;

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
