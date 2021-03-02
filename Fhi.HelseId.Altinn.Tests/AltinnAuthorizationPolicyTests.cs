using System;
using System.Collections.Generic;
using System.Security.Claims;
using System.Threading;
using System.Threading.Tasks;
using Fhi.HelseId.Altinn.Authorization;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.DependencyInjection;
using NUnit.Framework;

namespace Fhi.HelseId.Altinn.Tests
{
    public class AltinnAuthorizationPolicyTests
    {
        private readonly string authorizingServiceCode;
        private readonly int authorizingServiceEditionCode;
        private readonly string subjectWithAuthorization;
        private readonly string organizationForWhichSubjectIsAuthorized;
        private readonly IAuthorizationService authorizationService;

        /// <summary>
        /// Simple fake service that reports that a given subject has access for a given organization.
        /// </summary>
        class FakeAltinnServiceOwnerClient : IAltinnServiceOwnerClient
        {
            private readonly string subject;
            private readonly string organization;
            private readonly string serviceCode;
            private readonly int serviceEditionCode;

            public FakeAltinnServiceOwnerClient(string subject, string organization, string serviceCode, int serviceEditionCode)
            {
                this.subject = subject;
                this.organization = organization;
                this.serviceCode = serviceCode;
                this.serviceEditionCode = serviceEditionCode;
            }

            public Task<Organization?> GetOrganization(string orgNo, CancellationToken cancellationToken = default)
            {
                throw new NotImplementedException();
            }

            public IAsyncEnumerable<Organization> GetOrganizations(IEnumerable<string> orgNumbers, CancellationToken cancellationToken = default)
            {
                throw new NotImplementedException();
            }

            public IAsyncEnumerable<Organization> GetOrganizationsNotOfTypes(CancellationToken cancellationToken = default, params string[] types)
            {
                throw new NotImplementedException();
            }

            public IAsyncEnumerable<Organization> GetOrganizationsOfTypes(CancellationToken cancellationToken = default, params string[] organizationStructureCodes)
            {
                throw new NotImplementedException();
            }

            public IAsyncEnumerable<Reportee> GetReportees(string subject, string serviceCode, int serviceEditionCode, CancellationToken cancellationToken = default)
            {
                throw new NotImplementedException();
            }

            public Task<Reportee[]?> GetReportees(string subject, string serviceCode, int serviceEditionCode, int skip, int take, CancellationToken cancellationToken = default)
            {
                throw new NotImplementedException();
            }

            public IAsyncEnumerable<Right> GetRights(string subject, string reportee, CancellationToken cancellationToken = default)
            {
                throw new NotImplementedException();
            }

            public Task<RightsResponse> GetRights(string subject, string reportee, int skip, int take, CancellationToken cancellationToken = default)
            {
                throw new NotImplementedException();
            }

            public Task<bool> HasDelegation(string subject, string reportee, string serviceCode, int serviceEditionCode, CancellationToken cancellationToken = default)
            {
                return Task.FromResult(
                    this.subject == subject &&
                    organization == reportee &&
                    this.serviceCode == serviceCode &&
                    this.serviceEditionCode == serviceEditionCode
                );
            }
        }

        public AltinnAuthorizationPolicyTests()
        {
            authorizingServiceCode = "1234";
            authorizingServiceEditionCode = 1;
            subjectWithAuthorization = "01010101010";
            organizationForWhichSubjectIsAuthorized = "987654321";

            var services = new ServiceCollection();
            services.AddAuthorization();
            services.AddLogging();
            services.AddOptions();
            services.AddScoped<IAltinnServiceOwnerClient>(
                serviceProvider => new FakeAltinnServiceOwnerClient(
                    subjectWithAuthorization, organizationForWhichSubjectIsAuthorized,
                    authorizingServiceCode, authorizingServiceEditionCode
                ));
            services.AddScoped<IAuthorizationHandler, AltinnServiceAuthorizationHandler>();
            services.AddAltinnAuthorizationPolicy("Altinn", authorizingServiceCode, authorizingServiceEditionCode);
            authorizationService = services.BuildServiceProvider().GetRequiredService<IAuthorizationService>();
        }

        [Test]
        public async Task AuthorizationPolicyAllowsUserWithDelegation()
        {
            var principal = new ClaimsPrincipal(
                new ClaimsIdentity(
                    new[]
                    {
                        new Claim(IdentityClaims.Pid, subjectWithAuthorization),
                        new Claim(LocalClaims.AppLocalOrganization, organizationForWhichSubjectIsAuthorized)
                    },
                    "FakeAuthentication"
                )
            );

            var authorizationResult = await authorizationService.AuthorizeAsync(principal, "Altinn");
            Assert.IsTrue(authorizationResult.Succeeded);
        }

        [Test]
        public async Task AuthorizationPolicyAllowsUserWithDelegationThroughMultipleIdentities()
        {
            var principal = new ClaimsPrincipal(
                new ClaimsIdentity(
                    new[]
                    {
                        new Claim(IdentityClaims.Pid, subjectWithAuthorization),
                    },
                    "FakeAuthentication"
                ));

            principal.AddLocalIdentityWithClaims(new Claim(LocalClaims.AppLocalOrganization, organizationForWhichSubjectIsAuthorized));

            var authorizationResult = await authorizationService.AuthorizeAsync(principal, "Altinn");
            Assert.IsTrue(authorizationResult.Succeeded);
        }

        [Test]
        public async Task AuthorizationPolicyForbidsUserWithoutDelegation()
        {
            var principal = new ClaimsPrincipal(
                new ClaimsIdentity(
                    new[]
                    {
                        new Claim(IdentityClaims.Pid, "02020202020"),
                        new Claim(LocalClaims.AppLocalOrganization, organizationForWhichSubjectIsAuthorized)
                    }
                ));

            var authorizationResult = await authorizationService.AuthorizeAsync(principal, "Altinn");
            Assert.IsFalse(authorizationResult.Succeeded);
        }

        [Test]
        public async Task AuthorizationPolicyForbidsUserWithWrongOrganization()
        {
            var principal = new ClaimsPrincipal(
                new ClaimsIdentity(
                    new[]
                    {
                        new Claim(IdentityClaims.Pid, "01010101010"),
                        new Claim(LocalClaims.AppLocalOrganization, "999999999")
                    }
                ));

            var authorizationResult = await authorizationService.AuthorizeAsync(principal, "Altinn");
            Assert.IsFalse(authorizationResult.Succeeded);
        }

        [Test]
        public async Task AuthorizationPolicyForbidsUserWithoutOrganization()
        {
            var principal = new ClaimsPrincipal(
                new ClaimsIdentity(
                    new[]
                    {
                        new Claim(IdentityClaims.Pid, "01010101010")
                    }
                ));

            var authorizationResult = await authorizationService.AuthorizeAsync(principal, "Altinn");
            Assert.IsFalse(authorizationResult.Succeeded);
        }
    }
}
