using System;
using Fhi.HelseId.Common;

namespace Fhi.HelseId.Worker
{
    public class HelseIdApiKonfigurasjon
    {
        public string Name { get; set; } = "";
        public string Url { get; set; } = "";
        public string Scope { get; set; } = "";

        public Uri Uri => new Uri(Url);
    }

    public class HelseIdWorkerKonfigurasjon : HelseIdClientKonfigurasjon
    {
        public HelseIdApiKonfigurasjon[] Apis { get; set; } = Array.Empty<HelseIdApiKonfigurasjon>();
    }
}