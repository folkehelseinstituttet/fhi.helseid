using System;
using HprServiceReference;

namespace Fhi.HelseId.Tests.Hpr
{
    public class StubPersonAnnet
    {
        internal static Person CreateStubPersonAnnet(int hpr)
        {
            var person = new Person
            {
                HPRNummer = hpr,
                FysiskeAdresser =
                    new[] { new FysiskAdresse { Gateadresse = "Hovedgata 23", Postkode = "1234", Poststed = "Oslo" } },
                Godkjenninger = new[]
                {
                    new Godkjenning
                    {
                        Autorisasjon = new Kode {Aktiv = true, },
                        Helsepersonellkategori = new Kode {Verdi= "XX"},
                        Gyldig = new Periode { Fra = DateTime.Today.AddDays(-1), Til=null},
                        Suspensjonsperioder = Array.Empty<Suspensjonsperiode>()
                    },

                }
            };
            return person;
        }
    }
}