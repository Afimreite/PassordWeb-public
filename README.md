# PassordWeb

PassordWeb lar brukere identifisere seg med ID-porten og endre passordet til sin lokale Active Directory-konto.
Løsningen er laget med tanke på mulig gjenbruk i norske kommuner og bygger på ASP.NET Framework 4.8.

## Hovedfunksjoner

- Innlogging via ID-porten på høyt sikkerhetsnivå.
- Oppslag av én entydig, aktiv AD-konto.
- Passordbytte med bekreftelse, engangstoken og AD-passordpolicy.
- Visning av kontoopplysninger og siste passordtidspunkt.
- Manuell utlogging og automatisk øktutløp etter ti minutter.
- Auditlogging av innlogging og forsøk på passordbytte.

## ID-porten og Active Directory

Hver kommune må ha egen ID-porten-klient og egne tjenestekontoer i AD.
Personidentifikatoren fra den autentiserte identiteten kobles til et lokalt valgt AD-attributt.
Attributtet må være eksplisitt tillatt og inneholde korrekt, entydig identitetsinformasjon.
Manglende kobling eller flere aktive kontotreff gir ikke tilgang til passordbytte.

Passordet endres direkte i AD.
Eventuell synkronisering til Microsoft 365 håndteres av kommunens eksisterende identitetsløsning.

## Systemkrav

| Område | Krav |
| --- | --- |
| Drift | Windows Server, IIS med ASP.NET og .NET Framework 4.8 |
| Integrasjoner | Active Directory og egen ID-porten-klient |
| Nettverk | Eget DNS-navn, gyldig HTTPS-sertifikat og nødvendig AD-/HTTPS-tilgang |
| Bygging | Moderne .NET SDK eller kompatible Visual Studio Build Tools og NuGet-tilgang |

`dotnet build` henter NuGet-pakkene automatisk ved behov. Det krever ingen separat NuGet-installasjon.

## Hurtigstart

1. Opprett [egen ID-porten-integrasjon](docs/IDPORTEN.md), og klargjør identitetskoblingen i AD.
2. Bygg på en egnet Windows-byggemaskin.

```powershell
dotnet build .\PassordWeb.csproj -c Release
```

3. Kopier [appsettings.example.json](appsettings.example.json) til `appsettings.json` i nettstedroten. Følg [IIS-veiledningen](docs/INSTALLASJON.md) for oppsett og filrettigheter.
4. Bekreft innlogging, passordbytte og utlogging med en testkonto.

## Full dokumentasjon

- [Installasjon, AD, bygging, konfigurasjon, IIS, testing og feilsøking](docs/INSTALLASJON.md)
- [ID-porten: Digdir-registrering, klientinnstillinger, claims og returadresser](docs/IDPORTEN.md)

## Kjente begrensninger

- Bare ID-portens produksjonsmiljø og identifikatorer med elleve ASCII-sifre støttes.
- Økter ligger i serverminnet; lastbalansering og resirkulering må vurderes.
- Ingen direkte Microsoft 365-integrasjon eller garanti for synkroniseringstid.
- Kommuneprofilering tilpasses i lokal konfigurasjon; se [profilinnstillingene](docs/INSTALLASJON.md#kommuneprofilering).

## Lisensstatus

Programvarelisens er ikke valgt.
