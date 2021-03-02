using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using Fhi.HelseId.Common;

namespace Fhi.HelseId.Web
{
    public interface IHelseIdHprFeatures
    {
        bool UseHprNumber { get; }
    }

    public interface IHelseIdWebKonfigurasjon : IAutentiseringkonfigurasjon, IHelseIdHprFeatures
    {
        bool UseHttps { get; }
        string Authority { get; }
        string ClientId { get; }
        string ClientSecret { get; }
        string[] SecurityLevels { get; }
        bool Debug { get; }
        List<string> AllScopes { get; }
        string JsonWebKeySecret { get; }
        string RsaKeySecret { get; }
    }


    [SuppressMessage("Microsoft.Performance", "CA1819:PropertiesShouldNotReturnArrays")]
    public class HelseIdWebKonfigurasjon :  IHelseIdWebKonfigurasjon
    {
        public bool AuthUse { get; set; } = true;

        public bool UseHttps { get; set; } = true;

        public bool UseHprNumber { get; set; } = true;
        public string Authority { get; set; } = "";

        public string ClientId { get; set; } = "";

        public string ClientSecret { get; set; } = "";
        public string[] Scopes { get; set; } = Array.Empty<string>();

        public string[] SecurityLevels { get; set; } = Array.Empty<string>();

        public bool Debug { get; set; } = false;

        private List<string>? allScopes;


        public List<string> AllScopes
        {
            get
            {
                if (allScopes == null)
                {
                    allScopes = new List<string>();
                    allScopes.AddRange(fixedScopes);
                    allScopes.AddRange(Scopes);
                    allScopes = allScopes.Distinct().ToList();
                }
                return allScopes;
            }
        }

        public string JsonWebKeySecret { get; set; } = "";
        public string RsaKeySecret { get; set; } = "";

        private readonly List<string> fixedScopes = new List<string>
        {
            "openid",
            "profile",
            "offline_access",
            "helseid://scopes/identity/pid",
            "helseid://scopes/identity/pid_pseudonym",
            "helseid://scopes/identity/security_level",
            "helseid://scopes/hpr/hpr_number"
        };
    }
}
