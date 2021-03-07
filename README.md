<h1>
<img src="./src/icon.png" width="42" height="42"/>
LettuceEncrypt for ASP.NET Core
</h1>

[![Build Status][ci-badge]][ci] [![Code Coverage][codecov-badge]][codecov]
[![NuGet][nuget-badge] ![NuGet Downloads][nuget-download-badge]][nuget]

[ci]: https://github.com/natemcmaster/LettuceEncrypt/actions?query=workflow%3ACI+branch%3Amain
[ci-badge]: https://github.com/natemcmaster/LettuceEncrypt/workflows/CI/badge.svg
[codecov]: https://codecov.io/gh/natemcmaster/LettuceEncrypt
[codecov-badge]: https://codecov.io/gh/natemcmaster/LettuceEncrypt/branch/main/graph/badge.svg?token=l6uSsHZ8nA
[nuget]: https://www.nuget.org/packages/LettuceEncrypt/
[nuget-badge]: https://img.shields.io/nuget/v/LettuceEncrypt.svg?style=flat-square
[nuget-download-badge]: https://img.shields.io/nuget/dt/LettuceEncrypt?style=flat-square
[ACME]: https://en.wikipedia.org/wiki/Automated_Certificate_Management_Environment
[Let's Encrypt]: https://letsencrypt.org/

LettuceEncrypt provides API for ASP.NET Core projects to integrate with a certificate authority (CA), such as
[Let's Encrypt], for free, automatic HTTPS (SSL/TLS) certificates using the [ACME] protocol.

When enabled, your web server will **automatically** generate an HTTPS certificate during start up.
It then configures Kestrel to use this certificate for all HTTPS traffic.
See [usage instructions below](#usage) to get started.

Created and developed by [@natemcmaster](https://github.com/natemcmaster) with ❤️ from Seattle ☕️.
This project was formerly known as "McMaster.AspNetCore.LetsEncrypt", but [has been renamed for
trademark reasons](https://github.com/natemcmaster/LettuceEncrypt/issues/99). This project is **not an official
offering** from Let's Encrypt® or ISRG™.

This project is 100% organic and best served cold with ranch and carrots. 🥬

### Project status 

This project is in maintenance mode. I lost interest in developing features. I will make a patch if there is a security issue. I'll also consider an update if a new .NET major version breaks and the patch fix required is small. Please see https://github.com/natemcmaster/LettuceEncrypt/security/policy if you wish to report a security concern.

## Will this work for me?

That depends on [which kind of web server you are using](#web-server-scenarios). This library only works with
[Kestrel](https://docs.microsoft.com/aspnet/core/fundamentals/servers/kestrel), which is the default server
configuration for ASP.NET Core projects. Other servers, such as IIS and HTTP.sys, are not supported.
Furthermore, this only works when Kestrel is the edge server.

Not sure? [Read "Web Server Scenarios" below for more details.](#web-server-scenarios)

Using :cloud: Azure App Services (aka WebApps)? This library isn't for you, but you can still get free HTTPS certificates.
See ["Securing An Azure App Service with Let's Encrypt"](https://www.hanselman.com/blog/SecuringAnAzureAppServiceWebsiteUnderSSLInMinutesWithLetsEncrypt.aspx) by Scott Hanselman for more details.

## Usage

Install this package into your project using NuGet ([see details here][nuget-url]).

The primary API usage is to call `IServiceCollection.AddLettuceEncrypt` in the `Startup` class `ConfigureServices` method.

```csharp
using Microsoft.Extensions.DependencyInjection;

public class Startup
{
    public void ConfigureServices(IServiceCollection services)
    {
        services.AddLettuceEncrypt();
    }
}
```

A few required options should be set, typically via the appsettings.json file.

```jsonc
// appsettings.json
{
    "LettuceEncrypt": {
        // Set this to automatically accept the terms of service of your certificate authority.
        // If you don't set this in config, you will need to press "y" whenever the application starts
        "AcceptTermsOfService": true,

        // You must at least one domain name
        "DomainNames": [ "example.com", "www.example.com" ],

        // You must specify an email address to register with the certificate authority
        "EmailAddress": "it-admin@example.com"
    }
}
```

## Additional options

### Kestrel configuration

If your code is using the `.UseKestrel()` method to configure IP addresses, ports, or HTTPS settings,
you will also need to call `UseLettuceEncrypt`. This is required to make Lettuce Encrypt work.

#### Example: ConfigureHttpsDefaults

If calling `ConfigureHttpsDefaults`, use `UseLettuceEncrypt` like this:

```c#
webBuilder.UseKestrel(k =>
{
    var appServices = k.ApplicationServices;
    k.ConfigureHttpsDefaults(h =>
    {
        h.ClientCertificateMode = ClientCertificateMode.RequireCertificate;
        h.UseLettuceEncrypt(appServices);
    });
});
```

#### Example: Listen + UseHttps
If using `Listen` + `UseHttps` to manually configure Kestrel's address binding, use `UseLettuceEncrypt` like this:

```c#
webBuilder.UseKestrel(k =>
{
    var appServices = k.ApplicationServices;
    k.Listen(
        IPAddress.Any, 443,
        o => o.UseHttps(h =>
        {
            h.UseLettuceEncrypt(appServices);
        }));
});
```

### Customizing storage

Certificates are stored to the machine's X.509 store by default. Certificates can be stored in additional
locations by using extension methods after calling `AddLettuceEncrypt()` in the `Startup` class.

Multiple storage locations can be configured.

### Save generated certificates and account information to a directory

This will save and load certificate files (PFX format) using the specified directory.
It will also save your certificate authority account key into the same directory.

```c#
using LettuceEncrypt;
using Microsoft.Extensions.DependencyInjection;

public void ConfigureServices(IServiceCollection services)
{
    services
        .AddLettuceEncrypt()
        .PersistDataToDirectory(new DirectoryInfo("C:/data/LettuceEncrypt/"), "Password123");
}
```

### Save generated certificates to Azure Key Vault

Install [LettuceEncrypt.Azure](https://nuget.org/packages/LettuceEncrypt.Azure).
This will save and load certificate files using an Azure Key Vault.
It will also save your certificate authority account key as a secret in the same vault.

```c#
using LettuceEncrypt;
using Microsoft.Extensions.DependencyInjection;

public void ConfigureServices(IServiceCollection services)
{
    services
        .AddLettuceEncrypt()
        .PersistCertificatesToAzureKeyVault();
}
```

```jsonc
// appsettings.json
{
    "LettuceEncrypt": {
        "AzureKeyVault": {
            // Required - specify the name of your key vault
            "AzureKeyVaultEndpoint": "https://myaccount.vault.azure.net/"

            // Optional - specify the secret name used to store your account info (used for cert rewewals)
            // If not specified, name defaults to "le-encrypt-${ACME server URL}"
            "AccountKeySecretName": "my-lets-encrypt-account"
        }
    }
}
```

### Customizing how the certs are saved and loaded

Create a class that implements `ICertificateRepository` to customize how to save your certificates.

Create a class that implements `ICertificateSource` to customize where pre-existing certificates are
found when the server starts.

```c#
using LettuceEncrypt;
using Microsoft.Extensions.DependencyInjection;

public void ConfigureServices(IServiceCollection services)
{
    services.AddLettuceEncrypt();
    services.AddSingleton<ICertificateRepository, MyCertRepo>();
    services.AddSingleton<ICertificateSource, MyCertSource>();
}

class MyCertRepo : ICertificateRepository
{
    public async Task SaveAsync(X509Certificate2 certificate, CancellationToken cancellationToken)
    {
        byte[] certData = certificate.Export(X509ContentType.Pfx, "optionallySetPfxPassword");
        // save this data somehow
    }
}

class MyCertSource : ICertificateSource
{
    public async Task<IEnumerable<X509Certificate2>> GetCertificatesAsync(CancellationToken cancellationToken);
    {
        // find and return certificate objects. Return an empty enumerable if none are found
    }
}
```

### Customizing saving your account key

Your interactions with the certificate authority are encrypted with a private
key which is generated automatically on first-use. To ensure you can renew certificates
later using the same account, this account key is saved to disk by default.
You can customize where this account information is shared by adding your own implementation
of `IAccountStore`.

```c#
using LettuceEncrypt;
using LettuceEncrypt.Accounts;


public void ConfigureServices(IServiceCollection services)
{
    services.AddLettuceEncrypt();
    services.AddSingleton<IAccountStore, MyAccountStore>();
}


class MyAccountStore: IAccountStore
{
    public Task SaveAccountAsync(AccountModel account, CancellationToken cancellationToken)
    {
        // save the account object somewhere
    }

    // add #nullable enable if using c#, or remove the question mark for older versions of C#
    public Task<AccountModel?> GetAccountAsync(CancellationToken cancellationToken)
    {
        // return null if there is no account and one will be created for you
    }
}
```

## Testing in development

See the [developer docs](./test/Integration/) for details on how to test in a non-production environment.

## Web Server Scenarios

I recommend also reading [Microsoft's official documentation on hosting and deploying ASP.NET Core](https://docs.microsoft.com/aspnet/core/host-and-deploy/).

### ASP.NET Core with Kestrel

:white_check_mark: supported

![Diagram of Kestrel on the edge with Kestrel](https://i.imgur.com/vhQTgUe.png)

In this scenario, ASP.NET Core is hosted by the Kestrel server (the default, in-process HTTP server) and that web server exposes its ports directly to the internet. This library will configure Kestrel with an auto-generated certificate.

### ASP.NET Core with IIS

:x: NOT supported

![Diagram of Kestrel on the edge with IIS](https://i.imgur.com/PmrcLkN.png)

In this scenario, ASP.NET Core is hosted by IIS and that web server exposes its ports directly to the internet. IIS does not support dynamically configuring HTTPS certificates, so this library cannot support this scenario, but you can still configure cert automation using a different tool. See ["Using Let's Encrypt with IIS On Windows"](https://weblog.west-wind.com/posts/2016/feb/22/using-lets-encrypt-with-iis-on-windows) for details.

Azure App Service uses this for ASP.NET Core 2.2 and newer, which is why this library cannot support that scenario.. Older versions of ASP.NET Core on Azure App Service run with IIS as the reverse proxy (see below), which is also an unsupported scenario.


### ASP.NET Core with Kestrel Behind a TCP Load Balancer (aka SSL pass-thru)

:white_check_mark: supported

![Diagram of TCP Load Balancer](https://i.imgur.com/txqLTv5.png)

In this scenario, ASP.NET Core is hosted by the Kestrel server (the default, in-process HTTP server) and that web server exposes its ports directly to a local network. A TCP load balancer such as nginx forwards traffic without decrypting it to the host running Kestrel. This library will configure Kestrel with an auto-generated certificate.

### ASP.NET Core with Kestrel Behind a Reverse Proxy

:x: NOT supported

![Diagram of reverse proxy](https://i.imgur.com/LA4jms7.png)

In this scenario, HTTPS traffic is decrypted by a different web server that is beyond the control of ASP.NET Core. This library cannot support this scenario because HTTPS certificates must be configured by the reverse proxy server.

This is commonly done by web hosting providers. For example, :cloud: Azure App Services (aka WebApps) often runs older versions of ASP.NET Core in a reverse proxy.

If you are running the reverse proxy, you can still get free HTTPS certificates, but you'll need to use a different method. [Try Googling this](https://www.google.com/search?q=let%27s%20encrypt%20nginx).
