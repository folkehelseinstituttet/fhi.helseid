using System;
using HprServiceReference;

namespace Fhi.HelseId.Tests.Hpr
{
    internal class TestSykePleier : Person
    {
        internal TestSykePleier(int hprnummer)
        {
            HPRNummer = hprnummer;
            FysiskeAdresser =
                new[] { new FysiskAdresse { Gateadresse = "Hovedgata 23", Postkode = "1234", Poststed = "Oslo" } };
            Godkjenninger = new[]
            {
                new Godkjenning
                {
                    Autorisasjon = new Kode {Aktiv = true,},
                    Helsepersonellkategori = new Kode {Verdi = "SP"},
                    Gyldig = new Periode {Fra = DateTime.Today.AddDays(-1), Til = null},
                    Suspensjonsperioder = Array.Empty<Suspensjonsperiode>()
                }

            };
        }
    }
}