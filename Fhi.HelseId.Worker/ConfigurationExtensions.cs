using Fhi.HelseId.Common;
using Microsoft.Extensions.Configuration;

namespace Fhi.HelseId.Worker
{
    public static class ConfigurationExtensions
    {
        public static HelseIdWorkerKonfigurasjon GetWorkerKonfigurasjon(this IConfiguration root) =>
            root.GetConfig<HelseIdWorkerKonfigurasjon>(nameof(HelseIdWorkerKonfigurasjon));

    }
}
