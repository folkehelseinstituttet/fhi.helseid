using System.Linq;
using System.Security.Claims;

namespace Fhi.HelseId.Altinn
{
    /// <summary>
    /// Adds local claims for supporting various application-local aspects of authorization, e.g. Altinn authorization.
    /// </summary>
    public static class LocalClaims
    {
        /// <summary>
        /// Represents an organization that the application knows that the user is part of in some way, through application-local means.
        /// </summary>
        public const string AppLocalOrganization = "fhi://app-local/organization";

        /// <summary>
        /// Retrieves the app-local organization, if any.
        /// </summary>
        /// <param name="user">The principal</param>
        /// <returns>The app-local organization as defined in the application.</returns>
        /// <see cref="ClaimsPrincipal"/>
        public static string? Organization(this ClaimsPrincipal user) => 
            user.Claims.FirstOrDefault(x => x.Type == AppLocalOrganization)?.Value;

        /// <summary>
        /// Adds a local identity to the principal containing the given claims.
        /// </summary>
        /// <param name="user">The principal</param>
        /// <param name="claims">The claims to add to the new identity.</param>
        /// <see cref="ClaimsIdentity"/>
        /// <see cref="ClaimsPrincipal"/>
        public static void AddLocalIdentityWithClaims(this ClaimsPrincipal user, params Claim[] claims)
            => user.AddIdentity(new ClaimsIdentity(claims));
    }
}
