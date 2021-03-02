using Fhi.HelseId.Altinn.Authorization;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.DependencyInjection;

namespace Fhi.HelseId.Altinn
{
    public static class HelseIdOptionsExtensions
    {
        public static void AddAltinnAuthorizationPolicy(this IServiceCollection services, string policyName, string altinnServiceCode, int altinnServiceEditionCode)
        {
            services.AddAuthorization(
                config =>
                {
                    var altinnAccessPolicy = new AuthorizationPolicyBuilder()
                        .RequireAuthenticatedUser()
                        .AddRequirements(new AltinnServiceAuthorizationRequirement(altinnServiceCode, altinnServiceEditionCode))
                        .Build();
                    config.AddPolicy(policyName, altinnAccessPolicy);
                });
        }
    }
}
