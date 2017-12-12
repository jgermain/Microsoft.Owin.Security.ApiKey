using System.Net;
using System.Threading.Tasks;
using FluentAssertions;
using Microsoft.Owin.Security.ApiKey.Web;
using Microsoft.Owin.Testing;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Microsoft.Owin.Security.ApiKey.Tests
{
    [TestClass]
    public class AuthenticationTests
    {
        private TestServer api;

        [TestInitialize]
        public void Initialize()
        {
            this.api = TestServer.Create<Startup>();
        }

        [TestCleanup]
        public void Cleanup()
        {
            this.api.Dispose();
        }

        [TestMethod]
        public async Task Access_Anonymous_Resource_Using_Anonymous_Authentication_Should_Yield_200()
        {
            var response = await this.api.HttpClient.GetAsync("/api/anonymous/values");

            response.StatusCode.Should().Be(HttpStatusCode.OK);
        }

        [TestMethod]
        public async Task Access_Anonymous_Resource_Using_Valid_ApiKey_Authentication_Should_Yield_200()
        {
            var response = await this.api.CreateRequest("/api/anonymous/values").AddHeader("Authorization", "ApiKey 123").GetAsync();

            response.StatusCode.Should().Be(HttpStatusCode.OK);
        }

        [TestMethod]
        public async Task Access_Anonymous_Resource_Using_Invalid_ApiKey_Authentication_Should_Yield_401()
        {
            var response = await this.api.CreateRequest("/api/anonymous/values").AddHeader("Authorization", "ApiKey 456").GetAsync();

            response.StatusCode.Should().Be(HttpStatusCode.OK);
        }
        [TestMethod]
        public async Task Access_Protected_Resource_Using_Anonymous_Authentication_Should_Yield_401()
        {
            var response = await this.api.HttpClient.GetAsync("/api/authenticated/values");

            response.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
        }

        [TestMethod]
        public async Task Access_Protected_Resource_Using_Valid_ApiKey_Authentication_Should_Yield_200()
        {
            var response = await this.api.CreateRequest("/api/authenticated/values").AddHeader("Authorization", "ApiKey 123").GetAsync();

            response.StatusCode.Should().Be(HttpStatusCode.OK);
        }

        [TestMethod]
        public async Task Access_Protected_Resource_Using_Invalid_ApiKey_Authentication_Should_Yield_401()
        {
            var response = await this.api.CreateRequest("/api/authenticated/values").AddHeader("Authorization", "ApiKey 456").GetAsync();

            response.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
        }

        [TestMethod]
        public async Task Access_Protected_Resource_Using_Custom_Failure_Criteria_Should_Yield_Custom_Status_Code()
        {
            var response = await this.api.CreateRequest("/api/authenticated/values").AddHeader("Authorization", "ApiKey 789").GetAsync();

            response.StatusCode.Should().Be(HttpStatusCode.UpgradeRequired);
        }
    }
}
