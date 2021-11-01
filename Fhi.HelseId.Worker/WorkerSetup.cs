using System;
using Fhi.HelseId.Web.Services;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace Fhi.HelseId.Worker
{
    public class WorkerSetup
    {
        public IConfiguration Config { get; }
        public IHelseIdSecretHandler HelseIdSecretHandler { get; }
        private HelseIdWorkerKonfigurasjon HelseIdConfig { get; }

        public WorkerSetup(IConfiguration config, IHelseIdSecretHandler helseIdSecretHandler)
        {
            Config = config;
            HelseIdSecretHandler = helseIdSecretHandler;
            HelseIdConfig = Config.GetWorkerKonfigurasjon();
        }

        public void ConfigureServices(IServiceCollection services, string name)
        {
            var api = HelseIdConfig.Apis[0];
            var scope = api.Scope;

            var tokenRequest = new IdentityModel.Client.ClientCredentialsTokenRequest
            {
                Address = HelseIdConfig.Authority,
                ClientId = HelseIdConfig.ClientId,
                Scope = scope
            };

            HelseIdSecretHandler.AddSecretConfiguration(HelseIdConfig, tokenRequest);

            services.AddAccessTokenManagement(options =>
                {
                    options.Client.Clients.Add(name, tokenRequest);
                });

            services.AddClientAccessTokenClient(api.Name, configureClient: client =>
            {
                client.BaseAddress = new Uri(api.Url);
            }).AddClientAccessTokenHandler();
        }

    }
}
