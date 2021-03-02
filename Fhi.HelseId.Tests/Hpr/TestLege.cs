using System;
using System.Linq;
using HprServiceReference;

namespace Fhi.HelseId.Tests.Hpr
{
    internal class TestLege : Person
    {
        internal TestLege(int hprnummer)
        {
            HPRNummer = hprnummer;
            FysiskeAdresser =
                new[] { new FysiskAdresse { Gateadresse = "Hovedgata 23", Postkode = "1234", Poststed = "Oslo" } };
            Godkjenninger = new[]
            {
                new Godkjenning
                {
                    Autorisasjon = new Kode {Aktiv = true,},
                    Helsepersonellkategori = new Kode {Verdi = "LE"},
                    Gyldig = new Periode {Fra = DateTime.Today.AddDays(-1), Til = null},
                    Suspensjonsperioder = Array.Empty<Suspensjonsperiode>()
                }

            };
        }

        internal TestLege Suspender()
        {
            var suspensjonsperiode = new Suspensjonsperiode { Periode = new Periode { Fra = DateTime.Today.AddDays(-1), Til = null } };
            Godkjenninger[0].Suspensjonsperioder = new[] { suspensjonsperiode };
            return this;
        }

        internal TestLege EndreTilUgyldig()
        {
            Godkjenninger[0].Gyldig = new Periode { Fra = DateTime.Today.AddDays(1), Til = null };
            return this;
        }

        internal TestLege SuspenderTillegg()
        {
            var godkjenninger = Godkjenninger.ToList();
            var suspensjonsperiode = new Suspensjonsperiode { Periode = new Periode { Fra = DateTime.Today.AddDays(-1), Til = null } };
            godkjenninger.Add(new Godkjenning
            {
                Autorisasjon = new Kode { Aktiv = true, },
                Helsepersonellkategori = new Kode { Verdi = "LE" },
                Gyldig = new Periode { Fra = DateTime.Today.AddDays(-1), Til = null },
                Suspensjonsperioder = new[] { suspensjonsperiode }
            });
            return this;
        }

    }
}