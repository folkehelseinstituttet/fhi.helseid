using System;
using System.ComponentModel.DataAnnotations;
using System.Net.Http;
using System.Security.Cryptography.X509Certificates;

namespace Fhi.HelseId.Altinn
{
    /// <summary>
    /// Configuration options for <see cref="AltinnServiceOwnerClient"/>.
    /// </summary>
    public class AltinnOptions
    {
        /// <summary>
        /// Gets or sets the store in which the certificate to use for TLS client authentication against Altinn is located.         
        /// </summary>
        /// <remarks>
        /// Use this in conjunction with <see cref="AuthenticationCertificateStoreName"/> and 
        /// <see cref="AuthenticationCertificateThumbprint"/> if the TLS 
        /// client certificate is located in one of the Windows certificate stores.
        /// </remarks>
        /// <seealso cref="AuthenticationCertificatePath"/>
        /// <seealso cref="AuthenticationCertificatePassword"/>
        public StoreLocation AuthenticationCertificateLocation { get; set; } = StoreLocation.CurrentUser;

        /// <summary>
        /// Gets or sets the store in which the certificate to use for TLS client authentication against Altinn is located.         
        /// </summary>
        /// <remarks>
        /// Use this in conjunction with <see cref="AuthenticationCertificateLocation"/> and 
        /// <see cref="AuthenticationCertificateThumbprint"/> if the TLS 
        /// client certificate is located in one of the Windows certificate stores.
        /// </remarks>
        /// <seealso cref="AuthenticationCertificatePath"/>
        /// <seealso cref="AuthenticationCertificatePassword"/>
        public StoreName AuthenticationCertificateStoreName { get; set; } = StoreName.My;

        /// <summary>
        /// Gets or sets the thumbprint for the TLS client authentication to use against Altinn.         
        /// </summary>
        /// <remarks>
        /// Use this in conjunction with <see cref="AuthenticationCertificateLocation"/> and 
        /// <see cref="AuthenticationCertificateStoreName"/> if the TLS 
        /// client certificate is located in one of the Windows certificate stores.
        /// </remarks>
        /// <seealso cref="AuthenticationCertificatePath"/>
        /// <seealso cref="AuthenticationCertificatePassword"/>
        public string? AuthenticationCertificateThumbprint { get; set; }

        /// <summary>
        /// Gets or sets the path to a file containing the TLS client authentication certificate 
        /// to use against Altinn.
        /// </summary>
        /// <remarks>
        /// Use this in conjuction with <see cref="AuthenticationCertificatePassword"/> if the TLS
        /// client certificate is located in a file.
        /// </remarks>
        /// <seealso cref="AuthenticationCertificateLocation"/>
        /// <seealso cref="AuthenticationCertificateStoreName"/>
        /// <seealso cref="AuthenticationCertificateThumbprint"/>
        public string? AuthenticationCertificatePath { get; set; }

        /// <summary>
        /// Gets or sets the password protecting the file containing the TLS client authentication certificate 
        /// to use against Altinn.
        /// </summary>
        /// <remarks>
        /// Use this in conjuction with <see cref="AuthenticationCertificatePath"/> if the TLS
        /// client certificate is located in a file.
        /// </remarks>
        /// <seealso cref="AuthenticationCertificateLocation"/>
        /// <seealso cref="AuthenticationCertificateStoreName"/>
        /// <seealso cref="AuthenticationCertificateThumbprint"/>
        public string? AuthenticationCertificatePassword { get; set; }

        /// <summary>
        /// Gets or sets the base URI for the ServiceOwner API endpoints, e.g. https://tt02.altinn.no/api/serviceowner/.
        /// </summary>
        [Required]
        public string ServiceOwnerServiceUri { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets the API key to use when calling the ServiceOwner API.
        /// </summary>
        [Required]
        public string ServiceOwnerApiKey { get; set; } = string.Empty;

        public void ConfigureHttpClient(HttpClient httpClient)
        {
            httpClient.BaseAddress = new Uri(ServiceOwnerServiceUri);
            httpClient.DefaultRequestHeaders.Accept.Clear();
            httpClient.DefaultRequestHeaders.Accept.ParseAdd("application/json");
            httpClient.DefaultRequestHeaders.Add("ApiKey", ServiceOwnerApiKey);
        }

        public HttpMessageHandler CreateHttpMessageHandler()
        {
            var cert = FindCertificate();
            var clientHandler = new HttpClientHandler { ClientCertificateOptions = ClientCertificateOption.Manual };
            clientHandler.ClientCertificates.Add(cert);
            return clientHandler;
        }

        private X509Certificate2 FindCertificate()
        {
            if (!string.IsNullOrWhiteSpace(AuthenticationCertificatePath))
            {
                return new X509Certificate2(AuthenticationCertificatePath, AuthenticationCertificatePassword);
            }

            if (!string.IsNullOrWhiteSpace(AuthenticationCertificateThumbprint))
            {
                var store = new X509Store(AuthenticationCertificateStoreName, AuthenticationCertificateLocation);
                store.Open(OpenFlags.ReadOnly);

                var certs = store.Certificates.Find(
                    X509FindType.FindByThumbprint,
                    AuthenticationCertificateThumbprint,
                    true
                );

                if (certs.Count <= 0)
                {
                    throw new AltinnException(
                        $"Could not find the enterprise certificate with thumbprint {AuthenticationCertificateThumbprint}"
                    );
                }

                return certs[0];
            }

            throw new AltinnException(
                $"Either {nameof(AuthenticationCertificatePath)} or {nameof(AuthenticationCertificateThumbprint)} must be set"
            );
        }
    }
}
