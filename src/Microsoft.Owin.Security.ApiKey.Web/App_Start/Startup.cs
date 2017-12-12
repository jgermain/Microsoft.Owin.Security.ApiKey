using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Security.Claims;
using System.Threading.Tasks;
using System.Web.Http;
using Microsoft.Owin;
using Microsoft.Owin.Security.ApiKey.Contexts;
using Owin;

[assembly: OwinStartup(typeof(Microsoft.Owin.Security.ApiKey.Web.Startup))]

namespace Microsoft.Owin.Security.ApiKey.Web
{
    public class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            app.UseApiKeyAuthentication(new ApiKeyAuthenticationOptions
            {
                Provider = new ApiKeyAuthenticationProvider
                {
                    OnValidateIdentity = ValidateIdentity,
                    OnGenerateClaims = GenerateClaims
                }
            });

            var config = new HttpConfiguration();

            config.MapHttpAttributeRoutes();

            app.UseWebApi(config);
        }

        private static Task ValidateIdentity(ApiKeyValidateIdentityContext context)
        {
            if (context.ApiKey == "123")
            {
                context.Validate();
            }
            else if (context.ApiKey == "789")
            {
                context.RewriteStatusCode = true;
                context.StatusCode = HttpStatusCode.UpgradeRequired;
            }

            return Task.FromResult(0);
        }

        private static Task<IEnumerable<Claim>> GenerateClaims(ApiKeyGenerateClaimsContext context)
            => Task.FromResult(new[] { new Claim(ClaimTypes.Name, "Fred") }.AsEnumerable());
    }
}
