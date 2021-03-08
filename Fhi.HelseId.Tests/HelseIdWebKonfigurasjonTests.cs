using Fhi.HelseId.Common;
using Fhi.HelseId.Web;
using Fhi.HelseId.Worker;
using Microsoft.Extensions.Configuration;
using NUnit.Framework;

namespace Fhi.HelseId.Tests
{
    public class HelseIdWebKonfigurasjonTests : BaseConfigTests
    {
        [SetUp]
        public void Init() => base.Init();


        [Test]
        public void HelseIdWebConfigurationTest()
        {
            var sut = Config?.GetWebKonfigurasjon();
            Assert.That(sut, Is.Not.Null, "Can't load appsettings.test.json");
            Assert.Multiple(() =>
            {
                Assert.That(sut?.Authority, Does.Contain("helseid-sts"), "1");
                Assert.That(sut?.AuthUse, Is.True, "2");
                Assert.That(sut?.UseHttps, Is.True, "3");
                Assert.That(sut?.UseHprNumber, Is.False, "4");
                Assert.That(sut?.AllScopes.Count, Is.GreaterThan(7), "5");
            });
        }
    }

    public class HelseIdClientKonfigurasjonTests : BaseConfigTests
    {
        [SetUp]
        public void Init() => Init("clientappsettings.test.json");

        [Test]
        public void HelseIdWorkerConfigurationTest()
        {
            var sut = Config?.GetWorkerKonfigurasjon();
            Assert.That(sut, Is.Not.Null, $"Can't load {ConfigFilename}");
            Assert.Multiple(() =>
            {
                Assert.That(sut?.Authority, Does.Contain("helseid-sts"), "1");
                Assert.That(sut?.AuthUse, Is.True, "2");
                Assert.That(sut?.UseHttps, Is.True, "3");
                Assert.That(sut?.ClientId.Length, Is.GreaterThan(1));
                Assert.That(sut?.AllScopes.Count, Is.GreaterThanOrEqualTo(1), "4");
                Assert.That(sut?.Apis.Length, Is.EqualTo(1), "5");
            });
            var api = sut?.Apis[0];
            Assert.Multiple(() =>
            {
                Assert.That(api.Name, Is.EqualTo("Personoppslag"));
                Assert.That(api.Url, Is.EqualTo("https://test-personoppslag.fhi.no"));
                Assert.That(api.Scope, Is.EqualTo("fhi:personoppslag/api"));
            });
        }
    }
}