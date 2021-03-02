using Microsoft.AspNetCore.Authorization;

namespace Fhi.HelseId.Altinn.Authorization
{  /// <summary>
   /// Authorization requirement specifying that access should be verified against the given Altinn service.
   /// </summary>
   /// <see cref="IAltinnServiceOwnerClient"/>
    public class AltinnServiceAuthorizationRequirement : IAuthorizationRequirement
    {
        public string AltinnServiceCode { get; }
        public int AltinnServiceEditionCode { get; }

        public AltinnServiceAuthorizationRequirement(string altinnServiceCode, int altinnServiceEditionCode)
        {
            AltinnServiceCode = altinnServiceCode;
            AltinnServiceEditionCode = altinnServiceEditionCode;
        }
    }
}