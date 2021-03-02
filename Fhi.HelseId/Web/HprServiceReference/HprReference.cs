using System;


namespace HprServiceReference
{
    public partial class Periode
    {
        public bool Aktiv() => Fra < DateTime.Now && (Til == null || Til > DateTime.Now);
    }
}