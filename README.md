# Microsoft.Owin.Security.ApiKey [![Build status](https://ci.appveyor.com/api/projects/status/uxemt6d3ygjronab/branch/master?svg=true)](https://ci.appveyor.com/project/jamesharling/microsoft-owin-security-apikey/branch/master)
Lets an OWIN-enabled application use API keys for authentication. 

## Getting started
Grab the package from NuGet, which will install all dependencies.

`Install-Package Microsoft.Owin.Security.ApiKey`

## Usage
Extension methods for `IAppBuilder` will enable the middleware. Your custom delegates can be passed to `ApiKeyAuthenticationProvider`; at a minimum, you must implement `OnValidateIdentity` to validate the incoming API keys.
`OnGenerateClaims` is optional; the middleware will always construct an identity with a claim denoting the authentication type, but you have the option of fleshing out the identity with further custom claims if you wish.

```csharp
public void Configuration(IAppBuilder app)
{
    app.UseApiKeyAuthentication(new ApiKeyAuthenticationOptions()
    {
        Provider = new ApiKeyAuthenticationProvider()
        {
            OnValidateIdentity = ValidateIdentity,
            OnGenerateClaims = GenerateClaims
        }
    });
}

private async Task ValidateIdentity(ApiKeyValidateIdentityContext context)
{
    if (context.ApiKey == "123")
    {
        context.Validate();
    }
}

private async Task<IEnumerable<Claim>> GenerateClaims(ApiKeyGenerateClaimsContext context)
{
    return new[] { new Claim(ClaimTypes.Name, "Fred") };
}
```

### Customising Header Values
The format of the expected header containing the API key is completely customisable. By default, it expects a header in the following format:

```
Authorization: ApiKey {key}
```

If you wish to override this format, override the default values when passing in your `ApiKeyAuthenticationOptions`. For example:

```
// Authorization: MyType {key}

new ApiKeyAuthenticationOptions()
{
    Header = "Authentication", // is the default
    HeaderKey = "MyType"
}

// X-API-KEY: {key}

new ApiKeyAuthenticationOptions()
{
    Header = "X-API-KEY",
    HeaderKey = String.Empty
}
```

### Custom Status Codes
If you do not validate the context when validating the incoming identity then the middleware will default to an HTTP status code of 401. If you wish to return a different status code (e.g. a client's subscription has expired) then you can set a custom status code in the validation context:

```csharp
private async Task ValidateIdentity(ApiKeyValidateIdentityContext context)
{
    if (context.ApiKey == "123")
    {
        context.Validate();
    }
    
    if (subscription.IsExpired)
    {
	content.RewriteStatusCode = true;
        context.StatusCode = 402;
    }
}
```
