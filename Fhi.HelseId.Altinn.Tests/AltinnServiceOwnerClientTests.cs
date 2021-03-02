using System;
using System.Linq;
using System.Net.Http;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using NUnit.Framework;

namespace Fhi.HelseId.Altinn.Tests
{
    [Ignore("Requires setup")]
    public class AltinnServiceOwnerClientTests
    {
        // Service URI and API key for Altinn
        const string ServiceUri = "https://tt02.altinn.no/api/serviceowner/";
        const string ApiKey = "";
        // Service code and service edition code for the service to use during testing of rights/reportees
        const string ServiceCode = "";
        const int ServiceEditionCode = 1;
        
        // This PID here must be delegated rights to the service above for the organization below
        const string Pid = "";
        const string Organization = "";

        // Store name, location and thumbprint for the enterprise certificate to use during testing
        const string CertificateStoreName = "My";
        const string CertificateLocation = "CurrentUser";
        const string CertificateThumbprint = "";

#pragma warning disable
        private AltinnServiceOwnerClient serviceClient;

        [SetUp]
        public void SetUp() 
        {
            var options = new AltinnOptions
            {
                AuthenticationCertificateStoreName = Enum.Parse<StoreName>(CertificateStoreName),
                AuthenticationCertificateLocation = Enum.Parse<StoreLocation>(CertificateLocation),
                AuthenticationCertificateThumbprint = CertificateThumbprint,
                ServiceOwnerServiceUri = ServiceUri,
                ServiceOwnerApiKey = ApiKey
            };

            var httpClient = new HttpClient(options.CreateHttpMessageHandler());
            options.ConfigureHttpClient(httpClient);

            serviceClient = new AltinnServiceOwnerClient(httpClient);
        }

        [Test]
        public async Task SubUnitsExist()
        {
            var subUnits = serviceClient.GetOrganizationsOfTypes(CancellationToken.None, "BEDR", "AAFY");
            Assert.NotNull(await subUnits.FirstOrDefaultAsync());
        }

        [Test]
        public async Task UnitsExist()
        {
            var subUnits = serviceClient.GetOrganizationsNotOfTypes(CancellationToken.None, "BEDR", "AAFY");
            Assert.NotNull(await subUnits.FirstOrDefaultAsync());
        }

        [Test]
        public async Task KnownOrganizationIsPresent()
        {
            var organization = await serviceClient.GetOrganization(Organization);
            Assert.NotNull(organization);
        }

        [Test]
        public async Task MunicipalitiesExist()
        {
            var municipalities = serviceClient.GetOrganizationsOfTypes(CancellationToken.None, "KOMM");
            Assert.NotNull(await municipalities.FirstOrDefaultAsync());
        }

        [Test]
        public async Task KnownDelegationIsPresent()
        {
            var hasDelegation = await serviceClient.HasDelegation(Pid, Organization, ServiceCode, ServiceEditionCode);
            Assert.True(hasDelegation);
        }

        [Test]
        public async Task KnownReporteesArePresent()
        {
            var reportees = serviceClient.GetReportees(Pid, ServiceCode, ServiceEditionCode);
            Assert.NotNull(await reportees.FirstOrDefaultAsync());
        }

        [Test]
        public async Task RightsAreRetrievedForKnownSubjectAndReportee()
        {
            var rights = serviceClient.GetRights(Pid, Organization);
            var any = await rights.AnyAsync();
            Assert.True(any);
        }

        [Test]
        public async Task PagingWorksForKnownReportees()
        {
            var both = await serviceClient.GetReportees(Pid, ServiceCode, ServiceEditionCode, 0, 2);
            var first = await serviceClient.GetReportees(Pid, ServiceCode, ServiceEditionCode, 0, 1);
            var second = await serviceClient.GetReportees(Pid, ServiceCode, ServiceEditionCode, 1, 1);

            Assert.NotNull(both);
            Assert.AreEqual(2, both!.Length);
            Assert.NotNull(first.Single());
            Assert.NotNull(second.Single());

            var firstReporteeFromBoth = both[0];
            var secondReporteeFromBoth = both[1];
            var firstReporteeAlone = first![0];
            var secondReporteeAlone = second![0];

            Assert.AreNotEqual(firstReporteeAlone.Name, secondReporteeAlone.Name);
            Assert.AreEqual(firstReporteeFromBoth.Name, firstReporteeAlone.Name);
            Assert.AreEqual(secondReporteeFromBoth.Name, secondReporteeAlone.Name);
        }

        [Test]
        public async Task PagingWorksForKnownRights()
        {
            var both = await serviceClient.GetRights(Pid, Organization, 0, 2);
            var first = await serviceClient.GetRights(Pid, Organization, 0, 1);
            var second = await serviceClient.GetRights(Pid, Organization, 1, 1);

            Assert.AreEqual(2, both.Rights.Length);
            Assert.NotNull(first.Rights.Single());
            Assert.NotNull(second.Rights.Single());

            var firstRightFromBoth = both.Rights[0];
            var secondRightFromBoth = both.Rights[1];
            var firstRightAlone = first.Rights[0];
            var secondRightAlone = second.Rights[0];

            Assert.AreNotEqual(firstRightAlone.RightID, secondRightAlone.RightID);
            Assert.AreEqual(firstRightFromBoth.RightID, firstRightAlone.RightID);
            Assert.AreEqual(secondRightFromBoth.RightID, secondRightAlone.RightID);
        }
    }
}
