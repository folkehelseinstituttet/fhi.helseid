using System;
using System.Collections.Generic;
using System.Linq;

namespace Fhi.HelseId.Common
{
    public interface IHelseIdClientKonfigurasjon
    {
        bool AuthUse { get; set; }
        bool UseHttps { get; set; }
        string Authority { get; set; }
        string ClientId { get; set; }
        string ClientSecret { get; set; }
        string[] Scopes { get; set; }
        bool Debug { get; set; }
        List<string> AllScopes { get; }
        string JsonWebKeySecret { get; set; }
        string RsaKeySecret { get; set; }
    }

    public abstract class HelseIdClientKonfigurasjon : IHelseIdClientKonfigurasjon
    {
        private List<string>? allScopes;
        public bool AuthUse { get; set; } = true;
        public bool UseHttps { get; set; } = true;
        public string Authority { get; set; } = "";
        public string ClientId { get; set; } = "";
        public string ClientSecret { get; set; } = "";
        public string[] Scopes { get; set; } = Array.Empty<string>();
        public bool Debug { get; set; } = false;

        public List<string> AllScopes
        {
            get
            {
                if (allScopes != null)
                    return allScopes;
                allScopes = new List<string>();
                allScopes.AddRange(FixedScopes);
                allScopes.AddRange(Scopes);
                allScopes = allScopes.Distinct().ToList();
                return allScopes;
            }
        }

        protected virtual IEnumerable<string> FixedScopes => new List<string>
        {
            "offline_access"
        };

        public string JsonWebKeySecret { get; set; } = "";
        public string RsaKeySecret { get; set; } = "";
    }
}