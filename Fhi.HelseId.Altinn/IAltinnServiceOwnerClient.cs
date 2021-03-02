using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace Fhi.HelseId.Altinn
{
    public interface IAltinnServiceOwnerClient
    {
        IAsyncEnumerable<Organization> GetOrganizations(IEnumerable<string> orgNumbers, CancellationToken cancellationToken = default);
        IAsyncEnumerable<Organization> GetOrganizationsOfTypes(CancellationToken cancellationToken = default, params string[] organizationStructureCodes);

        IAsyncEnumerable<Organization> GetOrganizationsNotOfTypes(
            CancellationToken cancellationToken = default,
            params string[] types
        );

        Task<Organization?> GetOrganization(string orgNo, CancellationToken cancellationToken = default);
        IAsyncEnumerable<Reportee> GetReportees(string subject, string serviceCode, int serviceEditionCode, CancellationToken cancellationToken = default);
        IAsyncEnumerable<Right> GetRights(string subject, string reportee, CancellationToken cancellationToken = default);
        Task<Reportee[]?> GetReportees(string subject, string serviceCode, int serviceEditionCode, int skip, int take, CancellationToken cancellationToken = default);
        Task<RightsResponse> GetRights(string subject, string reportee, int skip, int take, CancellationToken cancellationToken = default);
        Task<bool> HasDelegation(string subject, string reportee, string serviceCode, int serviceEditionCode, CancellationToken cancellationToken = default);
    }

}
