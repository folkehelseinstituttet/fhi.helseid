using Microsoft.Extensions.DependencyInjection;
using System;
using System.Collections.Generic;
using System.Text;

namespace Fhi.HelseId.Altinn
{
    public static class IServiceCollectionExtensions
    {
        /// <summary>
        /// Set up an <see cref="IAltinnServiceOwnerClient"/> for dependency injection using the provided <see cref="AltinnOptions"/>.
        /// </summary>
        /// <param name="services">The service collection instance to add the <see cref="IAltinnServiceOwnerClient" /> to.</param>
        /// <param name="options">The <see cref="AltinnOptions" /> to use.</param>
        public static void ConfigureAltinnServiceClient(this IServiceCollection services, AltinnOptions options)
        {
            services
                .AddHttpClient<IAltinnServiceOwnerClient, AltinnServiceOwnerClient>(options.ConfigureHttpClient)
                .ConfigurePrimaryHttpMessageHandler(options.CreateHttpMessageHandler);
        }
    }
}
