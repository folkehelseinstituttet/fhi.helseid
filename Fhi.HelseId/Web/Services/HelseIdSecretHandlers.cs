using Fhi.HelseId.Common;
using Fhi.HelseId.Common.Identity;
using IdentityModel.Client;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using System;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using ClientAssertion = Fhi.HelseId.Common.Identity.ClientAssertion;

namespace Fhi.HelseId.Web.Services
{
    public interface IHelseIdSecretHandler
    {
        void AddSecretConfiguration(IHelseIdClientKonfigurasjon configAuth, OpenIdConnectOptions options);
        void AddSecretConfiguration(IHelseIdClientKonfigurasjon configAuth, ClientCredentialsTokenRequest tokenRequest);
    }

    public abstract class HelseIdAsymmetricSecretHandler : IHelseIdSecretHandler
    {
        public virtual void AddSecretConfiguration(IHelseIdClientKonfigurasjon configAuth, OpenIdConnectOptions options)
        {
            var jwkSecurityKey = GetSecurityKey(configAuth);

            options.Events.OnAuthorizationCodeReceived = ctx =>
            {
                ctx.TokenEndpointRequest.ClientAssertionType = IdentityModel.OidcConstants.ClientAssertionTypes.JwtBearer;
                ctx.TokenEndpointRequest.ClientAssertion = ClientAssertion.Generate(configAuth, GetSecurityKey(configAuth));

                return Task.CompletedTask;
            };
        }

        public virtual void AddSecretConfiguration(IHelseIdClientKonfigurasjon configAuth, ClientCredentialsTokenRequest tokenRequest)
        {
            tokenRequest.ClientAssertion = new IdentityModel.Client.ClientAssertion
            {
                Type = IdentityModel.OidcConstants.ClientAssertionTypes.JwtBearer,
                Value = ClientAssertion.Generate(configAuth, GetSecurityKey(configAuth))
            };
        }

        protected abstract SecurityKey GetSecurityKey(IHelseIdClientKonfigurasjon configAuth);
    }

    public class HelseIdJwkSecretHandler : HelseIdAsymmetricSecretHandler
    {
        private SecurityKey? _securityKey = null;

        protected override SecurityKey GetSecurityKey(IHelseIdClientKonfigurasjon configAuth)
        {
            if (_securityKey == null)
            {
                var jwk = File.ReadAllText(configAuth.ClientSecret);
                _securityKey = new JsonWebKey(jwk);
            }
            return _securityKey;
        }
    }

    public class HelseIdRsaXmlSecretHandler : HelseIdAsymmetricSecretHandler
    {
        private SecurityKey? _securityKey = null;

        protected override SecurityKey GetSecurityKey(IHelseIdClientKonfigurasjon configAuth)
        {
            if (_securityKey == null)
            {
                var xml = File.ReadAllText(configAuth.ClientSecret);
                var rsa = RSA.Create();
                rsa.FromXmlString(xml);
                _securityKey = new RsaSecurityKey(rsa);
            }
            return _securityKey;
        }
    }

    public class HelseIdEnterpriseCertificateSecretHandler : HelseIdAsymmetricSecretHandler
    {
        private SecurityKey? _securityKey = null;

        protected override SecurityKey GetSecurityKey(IHelseIdClientKonfigurasjon configAuth)
        {
            if (_securityKey == null)
            {
                var secretParts = configAuth.ClientSecret.Split(':');
                if (secretParts.Length != 2)
                {
                    throw new InvalidEnterpriseCertificateSecretException(configAuth.ClientSecret);
                }

                var storeLocation = (StoreLocation)Enum.Parse(typeof(StoreLocation), secretParts[0]);
                var thumprint = secretParts[1];

                var store = new X509Store(storeLocation);
                store.Open(OpenFlags.ReadOnly);

                var certificates = store.Certificates.Find(X509FindType.FindByThumbprint, thumprint, true);

                if (certificates.Count == 0)
                {
                    throw new Exception($"No certificate with thumbprint {configAuth.ClientSecret} found in store LocalMachine");
                }

                _securityKey = new X509SecurityKey(certificates[0]);
            }
            return _securityKey;
        }

        public class InvalidEnterpriseCertificateSecretException : Exception
        {
            private const string StandardMessage = "For enterprise certificates we expect secret in the format STORE:Thumbprint. For example: 'LocalMachine:1234567890'";

            public InvalidEnterpriseCertificateSecretException(string secret) : base(StandardMessage)
            {
                Secret = secret;
            }

            public string Secret { get; }
        }
    }

    public class HelseIdSharedSecretHandler : IHelseIdSecretHandler
    {
        public void AddSecretConfiguration(IHelseIdClientKonfigurasjon configAuth, OpenIdConnectOptions options)
        {
            options.ClientSecret = configAuth.ClientSecret;
        }

        public void AddSecretConfiguration(IHelseIdClientKonfigurasjon configAuth, ClientCredentialsTokenRequest tokenRequest)
        {
            tokenRequest.ClientSecret = configAuth.ClientSecret;
        }
    }
}
