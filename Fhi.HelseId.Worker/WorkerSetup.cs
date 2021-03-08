using System;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace Fhi.HelseId.Worker
{
    public class WorkerSetup
    {
        public IConfiguration Config { get; }
        private HelseIdWorkerKonfigurasjon HelseIdConfig { get; }

        public WorkerSetup(IConfiguration config)
        {
            Config = config;
            HelseIdConfig = Config.GetWorkerKonfigurasjon();
        }

        public void ConfigureServices(IServiceCollection services, string name)
        {
            var api = HelseIdConfig.Apis[0];
            var scope = api.Scope;
            services.AddAccessTokenManagement(options =>
                {
                    options.Client.Clients.Add(name, new IdentityModel.Client.ClientCredentialsTokenRequest
                    {
                        Address = HelseIdConfig.Authority,
                        ClientId = HelseIdConfig.ClientId,
                        ClientSecret = HelseIdConfig.ClientSecret,
                        Scope = scope
                    });
                });

            services.AddClientAccessTokenClient(api.Name, configureClient: client =>
            {
                client.BaseAddress = new Uri(api.Url);
            }).AddClientAccessTokenHandler();
        }

    }
}
