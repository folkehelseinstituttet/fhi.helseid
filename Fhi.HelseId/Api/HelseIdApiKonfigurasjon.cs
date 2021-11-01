
using Fhi.HelseId.Common;

namespace Fhi.HelseId.Api
{
    public interface IHelseIdApiFeatures
    {
        public bool UseHttps { get; }
        public bool AuthUse { get; }
    }

    public interface IHelseIdApiKonfigurasjon : IAutentiseringkonfigurasjon
    {
        string Authority { get;  }
        string ApiName { get;  }
        string ApiScope { get;  }
        bool UseHttps { get;  }
        bool RequireContextIdentity { get;  }
    }

    public class HelseIdApiKonfigurasjon :  IHelseIdApiFeatures, IHelseIdApiKonfigurasjon
    {
        public string Authority { get; set; } = "";

        public string ApiName { get; set; } = "";
        public string ApiScope { get; set; } = "";

        public bool AuthUse { get; set; } = true;
        public bool UseHttps { get; set; } = true;

        public bool RequireContextIdentity { get; set; } = false;
    }
}
