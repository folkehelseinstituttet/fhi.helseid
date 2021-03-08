using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
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
    public class HelseIdWebKonfigurasjon : HelseIdClientKonfigurasjon, IHelseIdWebKonfigurasjon
    {
        public bool UseHprNumber { get; set; } = true;

        public string[] SecurityLevels { get; set; } = Array.Empty<string>();
        
        protected override IEnumerable<string> FixedScopes
        {
            get
            {
                var list =  new List<string>
                {
                    "openid",
                    "profile",
                    "helseid://scopes/identity/pid",
                    "helseid://scopes/identity/pid_pseudonym",
                    "helseid://scopes/identity/security_level",
                    "helseid://scopes/hpr/hpr_number"
                };
                list.AddRange(base.FixedScopes);
                return list;
            }
        }
    }
}
