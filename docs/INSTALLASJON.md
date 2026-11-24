# Installere PassordWeb på IIS

## 1. Klargjør Windows og IIS

Kjør Windows PowerShell som administrator på IIS-serveren.

~~~powershell
Get-WindowsFeature Web-Server, Web-Asp-Net45, Web-Filtering, Web-Mgmt-Console |
    Format-Table Name, InstallState
~~~

Installer funksjonene som mangler.

~~~powershell
Install-WindowsFeature Web-Server, Web-Asp-Net45, Web-Filtering -IncludeManagementTools
~~~

PassordWeb kjører på .NET Framework 4.8 i IIS. Bygg på en Windows-maskin med [.NET SDK](https://dotnet.microsoft.com/download/dotnet/8.0). .NET 8 SDK for Windows x64 kan brukes. SDK-en trengs på byggemaskinen. Du kan også bygge direkte på IIS-serveren.

## 2. Last ned kildekoden og bygg

Last ned kildekoden fra **Code → Download ZIP** på GitHub. Pakk ut ZIP-filen. Bytt ut eksempelstien med mappen som inneholder PassordWeb.csproj.

~~~powershell
Set-Location 'C:\temp\PassordWeb-single-appsettings'
Get-Item .\PassordWeb.csproj
dotnet --list-sdks
~~~

Hvis PowerShell ikke finner dotnet etter installasjonen, åpne et nytt vindu. Du kan også sjekke SDK-en med & 'C:\Program Files\dotnet\dotnet.exe' --list-sdks og bruke samme fullstendige sti i byggekommandoen.

~~~powershell
dotnet build .\PassordWeb.csproj -c Release
Get-Item .\bin\Release\net48\PassordWeb.TestAuth.dll
~~~

Byggekommandoen kjører NuGet-restore. Se etter at bygget fullfører, og at DLL-en finnes i bin\Release\net48.

## 3. Klargjør nettstedmappen og IIS

Kjør dette fra den utpakkede kildemappen i administrativ PowerShell på IIS-serveren hvis du bygde der. Ved bygging på en separat maskin overfører du de samme nettstedfilene og DLL-ene til tilsvarende mapper på IIS-serveren.

~~~powershell
$sitePath = 'C:\inetpub\PassordWeb'
$binPath = Join-Path $sitePath 'Bin'
New-Item -ItemType Directory -Path $binPath -Force | Out-Null

Copy-Item -Path .\Default.aspx, .\Content, .\Images, .\Scripts -Destination $sitePath -Recurse
Copy-Item .\bin\Release\net48\*.dll -Destination $binPath
Copy-Item .\examples\Web.config.example -Destination (Join-Path $sitePath 'Web.config')

Get-ChildItem $sitePath | Select-Object Name
Get-Item (Join-Path $binPath 'PassordWeb.TestAuth.dll')
~~~

Opprett en egen applikasjonspool med .NET CLR v4.0 og integrert pipeline i IIS Manager. Opprett et nettsted med fysisk sti `C:\inetpub\PassordWeb`, velg den nye poolen og aktiver anonym IIS-tilgang. Sett opp HTTPS-binding med kommunens DNS-navn og sertifikat. Kontroller binding redirects i Web.config mot byggutdataene. Bruk [IIS-malen](../examples/Web.config.example), som inkluderer UTF-8 og sperren for appsettings.json. Hold nettstedet stoppet frem til lokal konfigurasjon er klar.

## 4. Konfigurer og start PassordWeb

1. Kopier JSON-malen til appsettings.json ved siden av Web.config. Bruk Copy-Item .\appsettings.example.json -Destination 'C:\inetpub\PassordWeb\appsettings.json' fra kildemappen. Begrens filrettighetene før du fyller inn hemmeligheter. Kjør dette i administrativ PowerShell fra nettstedroten med ditt poolnavn. [JSON-mal](../appsettings.example.json)

   ~~~powershell
   $pool = 'PassordWebPool'
   $principal = 'IIS AppPool\' + $pool
   icacls.exe .\appsettings.json /setowner '*S-1-5-32-544'
   icacls.exe .\appsettings.json /inheritance:r /grant:r '*S-1-5-32-544:F' '*S-1-5-18:F' "$($principal):R"
   icacls.exe .\appsettings.json
   ~~~

   Bekreft at kun Administratorer og SYSTEM har full tilgang og at poolidentiteten har lesetilgang. Begrens også retten til å erstatte filer via nettstedmappen til administratorer. Web.config sperrer HTTP-tilgang til konfigurasjonsfilen med IIS Request Filtering.
2. Fyll inn egen klient og offentlig HTTPS-adresse i idPorten. Ved TLS-terminering på en proxy, angi proxyens faktiske IP-adresser i proxy.trustedAddresses. Sett bare assumeHttpsFromTrustedProxy til true når proxyen utelukkende videresender ekstern HTTPS til denne bindingen. [ID-porten-integrasjon](IDPORTEN.md)
3. Fyll inn LDAP-sti og pålogging for adLookup og adReset. Bruk én lesekonto og en separat konto med avgrenset delegering for passordbytte. Sett identity.attribute til det godkjente AD-attributtet og ta det med i identity.allowedAttributes. Sett auditPath til en absolutt filsti utenfor nettstedroten og gi poolidentiteten rett til å skrive loggen.
4. Start applikasjonen. Ugyldig konfigurasjon stopper oppstarten, og oppstartsfeilen oppgir feltnavn uten verdier. Kontroller at forsiden åpner over HTTPS, at norske tegn og logo vises riktig, og at /appsettings.json gir 404 uten filinnhold. Bekreft innlogging, visning av egen AD-konto, passordbytte, auditlogging og utlogging med en dedikert testkonto.

## Kommuneprofilering

Rediger branding i nettstedets lokale appsettings.json. Angi municipalityName, serviceName, supportText, passwordSyncHelpText, logoPath og faviconPath. Standardfilene er /Images/logo.svg og /Images/favicon.ico. Legg egne bilder i Images og bruk stier som /Images/kommune-logo.svg. Tom logosti viser kommunenavnet som tekst. Tom faviconsti utelater faviconlenken. Resirkuler IIS-poolen etter endring i JSON for å lese de nye verdiene. Resirkulering avslutter aktive økter.

Hold produksjonsfilen, lokale profilbilder og sikkerhetskopier utenfor kildekoden som skal deles. Den delbare konfigurasjonen ligger i appsettings.example.json.
