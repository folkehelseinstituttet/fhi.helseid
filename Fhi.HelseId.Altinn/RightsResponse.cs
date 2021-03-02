namespace Fhi.HelseId.Altinn
{
    public class RightsResponse
    {
        public Subject? Subject { get; set; }
        public Reportee? Reportee { get; set; }

        public Right[] Rights { get; set; } = new Right[0];
    }

}
