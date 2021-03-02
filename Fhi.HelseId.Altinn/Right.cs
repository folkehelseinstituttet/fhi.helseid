namespace Fhi.HelseId.Altinn
{
    public class Right
    {
        public int RightID { get; set; }
        public string? RightType { get; set; }
        public string? ServiceCode { get; set; }
        public int ServiceEditionCode { get; set; }
        public string? Action { get; set; }
        public string? RightSourceType { get; set; }
        public bool IsDelegatable { get; set; }
    }

}
