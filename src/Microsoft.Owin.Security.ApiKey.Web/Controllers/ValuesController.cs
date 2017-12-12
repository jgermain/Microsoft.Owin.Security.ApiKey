using System.Collections.Generic;
using System.Web.Http;

namespace Microsoft.Owin.Security.ApiKey.Web.Controllers
{
    public class ValuesController : ApiController
    {
        [HttpGet, Route("api/authenticated/values")]
        [Authorize]
        public IEnumerable<string> Auth()
        {
            return new string[] { "value1", "value2" };
        }

        [HttpGet, Route("api/anonymous/values")]
        public IEnumerable<string> Anon()
        {
            return new string[] { "value1", "value2" };
        }
    }
}
