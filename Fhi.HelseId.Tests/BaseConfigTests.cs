using Microsoft.Extensions.Configuration;
using NUnit.Framework;

namespace Fhi.HelseId.Tests
{
    public abstract class BaseConfigTests
    {
        protected IConfigurationRoot? Config { get; private set; }
        protected string ConfigFilename { get; private set; } = "";

        /// <summary>
        /// Call from SetUp in implementation class
        /// </summary>
        /// <param name="configfilename"></param>
        public void Init(string configfilename= "appsettings.test.json")
        {
            ConfigFilename = configfilename;
            Config = GetIConfigurationRoot(TestContext.CurrentContext.TestDirectory);
        }


        public IConfigurationRoot GetIConfigurationRoot(string outputPath)
        {
            return new ConfigurationBuilder()
                .SetBasePath(outputPath)
                .AddJsonFile(ConfigFilename, optional: true)
                .Build();
        }
    }
}