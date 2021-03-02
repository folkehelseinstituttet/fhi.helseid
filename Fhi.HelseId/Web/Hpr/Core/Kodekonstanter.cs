// ReSharper disable UnusedMember.Global
// ReSharper disable InconsistentNaming
namespace Fhi.HelseId.Web.Hpr.Core
{

    public class OId9060
    {
        public string Description { get; }

        public string Value { get; }
    
        internal OId9060(string value,string description="")
        {
            Value = value;
            Description = description;
        }
        public override string ToString() => Value;
    }

    public static partial class Kodekonstanter
    {
        public const string OId1102Ja = "1";

        public const string OId9051Her = "HER";

        public const string HprNhn = "112374";
        public const string HprFhi = "85217";
        public const string NhnOrgNavn = "NHN";
        public const string FhiOrgNavn = "FHI";

        public const string IkkeSatt = "N/A";
        public const string UkjentOrgIdent = "-1";

        
        public const string OId3101Mann = "1";
        public const string OId3101MannBeskrivelse = "Mann";
        public const string OId3101Kvinne = "2";
        public const string OId3101KvinneBeskrivelse = "Kvinne";

        public const string OId8116Hpr = "HPR";
        public const string OId8116HprBeskrivelse = "HPR-nummer";
        public const string OId8116Fnr = "FNR";
        public const string OId8116FnrBeskrivelse = "Norsk fødselsnummer";
        public const string OId8116Dnr = "DNR";
        public const string OId8116DnrBeskrivelse = "D-nummer";
        public const string OId8116Fhnr = "FHN";
        public const string OId8116FhnrBeskrivelse = "Felles hjelpenummer";
        public const string OId8116Hnr = "HNR";
        public const string OId8116Her = "HER";
        public const string OId8116Pnr = "PNR";
        public const string OId8116Sef = "SEF";
        public const string OId8116Dkf = "DKF";
        public const string OId8116Ssn = "SSN";
        public const string OId8116Fpn = "FPN";
        public const string OId8116Uid = "UID";
        public const string OId8116Duf = "DUF";
        public const string OId8116Fhn = "FHN";
        public const string OId8116Xxx = "XXX";
        public const string OId8116HnrBeskrivelse = "H-nummer";
        public const string OId8116HerBeskrivelse = "HER-id";
        public const string OId8116HerBeskrivelseUtvidet = "Rollebasert id i NHN Adresseregister";
        public const string OId8116PnrBeskrivelse = "Passnummer";
        public const string OId8116SefBeskrivelse = "Svensk 'personnummer'";
        public const string OId8116DkfBeskrivelse = "Dansk 'personnummer'";
        public const string OId8116SsnBeskrivelse = "Sosial security number";
        public const string OId8116FpnBeskrivelse = "Forsikringspolise nummer";
        public const string OId8116UidBeskrivelse = "Utenlandsk identifikasjon";
        public const string OId8116UidBeskrivelseUtvidet = "Annet enn svensk- og dansk personnummer";
        public const string OId8116DufBeskrivelse = "DUF-nummer";
        public const string OId8116DufBeskrivelseUtvidet = "Database for utlendingsforvaltningen";
        public const string OId8116FhnBeskrivelse = "Felles hjelpenummer";
        public const string OId8116XxxBeskrivelse = "Annet";

    }
}
