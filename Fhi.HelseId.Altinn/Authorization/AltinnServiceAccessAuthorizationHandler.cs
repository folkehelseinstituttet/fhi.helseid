using System.Linq;
using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using System.Threading.Tasks;

namespace Fhi.HelseId.Altinn.Authorization
{
    /// <summary>
    /// Handler for Altinn service authorization requirements. The handler verifies against Altinn that the user has
    /// been delegated access to the service given in the requirement for an organization given by the application-local
    /// organization claim.
    /// </summary>
    /// <see cref="IAltinnServiceOwnerClient"/>
    /// <see cref="LocalClaims.AppLocalOrganization"/>
    public class AltinnServiceAuthorizationHandler : AuthorizationHandler<AltinnServiceAuthorizationRequirement>
    {
        private readonly IAltinnServiceOwnerClient serviceOwnerClient;

        public AltinnServiceAuthorizationHandler(IAltinnServiceOwnerClient serviceOwnerClient)
        {
            this.serviceOwnerClient = serviceOwnerClient;
        }

        protected override async Task HandleRequirementAsync(AuthorizationHandlerContext context, AltinnServiceAuthorizationRequirement requirement)
        {
            var subject = context.User.Pid();
            if (subject == null)
            {
                context.Fail();
            }

            var reportee = context.User.Organization();
            if (reportee == null)
            {
                context.Fail();
            }

            var hasDelegation = await serviceOwnerClient.HasDelegation(subject, reportee, requirement.AltinnServiceCode, requirement.AltinnServiceEditionCode);
            if (!hasDelegation)
            {
                context.Fail();
            }

            context.Succeed(requirement);
        }
    }


    public static class IdentityClaims
    {
        private const string Prefix = HelseIdUriPrefixes.Claims + "identity/";

        public const string AssuranceLevel = Prefix + "assurance_level";
        public const string Pid = Prefix + "pid";
        public const string PidPseudonym = Prefix + "pid_pseudonym";
        public const string SecurityLevel = Prefix + "security_level";
        public const string Network = Prefix + "network";
        public const string Name = "name";

    }

    public static class HelseIdUriPrefixes
    {
        public const string Claims = "helseid://claims/";
    }

    public static class HprClaims
    {
        private const string Prefix = HelseIdUriPrefixes.Claims + "hpr/";
        public const string HprNummer = Prefix + "hpr_number";

        public static string? HprNumber(this ClaimsPrincipal user) =>
            user.Claims.FirstOrDefault(x => x.Type == HprClaims.HprNummer)?.Value;
        public static string? Id(this ClaimsPrincipal user) =>
            user.Claims.FirstOrDefault(x => x.Type == IdentityClaims.Pid)?.Value;
        public static string? Name(this ClaimsPrincipal user) =>
            user.Claims.FirstOrDefault(x => x.Type == IdentityClaims.Name)?.Value;
        public static string? PidPseudonym(this ClaimsPrincipal user) =>
            user.Claims.FirstOrDefault(x => x.Type == IdentityClaims.PidPseudonym)?.Value;
        public static string? Pid(this ClaimsPrincipal user) =>
            user.Claims.FirstOrDefault(x => x.Type == IdentityClaims.Pid)?.Value;
    }
}
