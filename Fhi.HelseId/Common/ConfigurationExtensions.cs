using Fhi.HelseId.Api;
using Fhi.HelseId.Web;
using Microsoft.Extensions.Configuration;

namespace Fhi.HelseId.Common
{
    public static class ConfigurationExtensions
    {
        public static T GetConfig<T>(this IConfiguration root,string name)
        {
            var section = root.GetSection(name);
            var config =  section.Get<T>();
            return config;
        }

        public static HelseIdWebKonfigurasjon GetWebKonfigurasjon(this IConfiguration root) =>
            root.GetConfig<HelseIdWebKonfigurasjon>(nameof(HelseIdWebKonfigurasjon));
        public static HelseIdApiKonfigurasjon GetApiKonfigurasjon(this IConfiguration root) =>
            root.GetConfig<HelseIdApiKonfigurasjon>(nameof(HelseIdApiKonfigurasjon));

        

    }
}
