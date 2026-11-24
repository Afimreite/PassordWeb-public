# ID-porten

[Til oversikten](../README.md) · [Installasjon](INSTALLASJON.md)

## Opprette integrasjon mot ID-porten

Hver kommune må opprette sin egen integrasjon hos Digdir. Klient-ID og klienthemmelighet fra en annen installasjon skal ikke gjenbrukes.

### Protokoll og krav fra applikasjonen

Koden bruker OpenID Connect med autorisasjonskodeflyt, PKCE, `scope=openid` og `response_mode=query`. Den ber om ny autentisering med `prompt=login`. Klienten autentiseres ved tokenendepunktet med `client_secret_basic`. Tokenets signatur, utsteder, målgruppe, levetid og nonce valideres; koden tillater signaturalgoritmen RS256.

| Claim | Hvordan løsningen bruker den |
| --- | --- |
| `sub` | Identifiserer innlogget subjekt og binder den lokale økten til det |
| `acr` | Må være `idporten-loa-high` |
| `auth_time` | Må være fersk: ikke eldre enn fem minutter eller mer enn ett minutt frem i tid ved validering |
| `pid` | Må være én personidentifikator med elleve ASCII-sifre for at AD-oppslag og passordbytte skal kunne utføres |
| `sid` | Brukes til kobling mot leverandørens økt ved front-channel logout når claimen er tilgjengelig |

Uten et gyldig `pid` kan løsningen ikke finne brukerens AD-konto. Kommunen må avklare nødvendig tilgang til personidentifikator hos Digdir; ikke anta at klientregistreringen automatisk gir alle nødvendige claims.

### Adresser og klientverdier

Eksempelnavnet nedenfor skal erstattes med kommunens eget DNS-navn.

| Verdi | Eksempel / krav |
| --- | --- |
| Offentlig adresse, `publicOrigin` | `https://passord.eksempelkommune.no` |
| Klient-ID, `clientId` | Egen verdi fra klientregistreringen |
| Klienthemmelighet, `clientSecret` | Egen hemmelighet, kun i lokal konfigurasjon |
| Redirect URI | `https://passord.eksempelkommune.no/auth/callback/idporten` |
| Retur etter utlogging | `https://passord.eksempelkommune.no/auth/logged-out` |
| Front-channel logout URI | `https://passord.eksempelkommune.no/auth/frontchannel-logout` |
| Discovery-adresse | `https://idporten.no/.well-known/openid-configuration` |

`publicOrigin` må være HTTPS med DNS-navn og uten brukerinfo, ekstra sti, spørringsparametere, fragment eller egendefinert port. Callback og retur etter utlogging utledes av denne verdien; det finnes ingen egne konfigurasjonsnøkler for disse adressene.

Applikasjonens utloggingsside er `/auth/logout`. Selve utloggingen bekreftes med POST og et serverbundet token. Deretter brukes ID-portens faste utloggingsendepunkt `https://login.idporten.no/logout`, klient-ID, registrert returadresse og en kontrollert returtilstand. Front-channel logout-ruten validerer `iss` og `sid` og kan ugyldiggjøre tilknyttede lokale økter. Andre tjenester i samme ID-porten-økt kan også bli påvirket av utlogging.

**Dagens kode er begrenset til ID-portens produksjonsmiljø.** Flere issuer- og endepunktverdier er låst i koden. Test-ID-porten kan ikke aktiveres bare ved å endre discovery-adressen.

### Opprette klienten i Digdirs selvbetjening

Fremgangsmåten og eksempelverdiene nedenfor bygger på et eksisterende klientoppsett. Feltnavn og tilgjengelige valg i portalen må kontrolleres ved registrering; portalbildene er ikke uavhengig verifisert her.

1. Gå til [Digdirs selvbetjeningsportal](https://sjolvbetjening.samarbeid.digdir.no/).
2. Logg inn med nødvendig tilgang til egen organisasjon. Ha klart kommunens tjenestenavn, offentlig HTTPS-adresse, returadresser og avklart behov for identitetsinformasjon.
3. Velg å [opprette en ny ID-porten-klient](https://sjolvbetjening.samarbeid.digdir.no/clients/add/idporten). Sørg for at integrasjonen gjelder produksjonsmiljøet, som dagens kode krever.
4. Angi et visningsnavn, for eksempel «PassordWeb», og en beskrivelse av kommunens tjeneste.
5. Fyll ut klientinnstillingene etter tabellen. Skill krav i applikasjonen fra eksempelvalg i registreringen.

| Innstilling | Verdi | Betydning for PassordWeb |
| --- | --- | --- |
| Applikasjonstype | `web` | Serverbasert webapplikasjon med hemmelig klientautentisering |
| Autentiseringsmetode | `client_secret_basic` | Kreves av koden |
| Tillatt grant type | `authorization_code` | Flyten applikasjonen bruker |
| PKCE (`code_challenge_method`) | `S256` | PKCE er aktivert i applikasjonen |
| ID-token signeringsalgoritme | `RS256` | Kreves av tokenvalideringen |
| Refresh token grant | Ikke aktivert | Applikasjonen ber ikke om refresh tokens |
| Refresh token bruk | Engangs | Eksempelvalg; uten praktisk bruk når refresh token grant er deaktivert |
| Access token levetid | 120 sekunder | Eksempelverdi, ikke et fast krav i koden |
| Refresh token levetid | 600 sekunder | Eksempelverdi; ikke brukt av dagens flyt |
| Autorisasjon levetid | 7200 sekunder | Eksempelverdi, ikke lokal øktlevetid |
| Single sign-on | Aktivert | Eksempelvalg; applikasjonen sender likevel `prompt=login` |

Tokenlevetidene er eksempelverdier fra et eksisterende oppsett og må vurderes ved egen registrering. De overstyrer ikke applikasjonens lokale øktgrense på ti minutter eller kontrollen av fersk autentisering. Ikke aktiver refresh token grant for å få tabellens refresh-felter i bruk. Koden ber bare om `openid`, ikke `offline_access`, og lagrer ikke tokenene i innloggingsbilletten.

### Generere og oppbevare klienthemmeligheten

1. Velg autentiseringsmetoden `client_secret_basic`.
2. Trykk «Generer client secret» i klientregistreringen.
3. Kopier hemmeligheten og oppbevar den i kommunens godkjente løsning for hemmeligheter. Etabler ansvar og rutine for rotasjon.
4. Kopier Client ID fra klientregistreringen.
5. Legg verdiene i `clientId` og `clientSecret` i gruppen `idPorten` i nettstedets lokale `appsettings.json`.

**Client Secret skal aldri lagres i GitHub, README eller eksempelkonfigurasjonene.** Bruk bare kommunens egne klientverdier i installasjonen.

### Registrere returadresser og utlogging

Erstatt eksempelnavnet med eget DNS-navn, og registrer:

| Portalinnstilling | Adresse |
| --- | --- |
| Redirect URI | `https://passord.eksempelkommune.no/auth/callback/idporten` |
| Post logout redirect URI | `https://passord.eksempelkommune.no/auth/logged-out` |
| Frontchannel logout URI | `https://passord.eksempelkommune.no/auth/frontchannel-logout` |

Disse adressene må samsvare med `publicOrigin` og applikasjonens offentlige HTTPS-adresse. Backchannel logout URI er ikke konfigurert i eksempeloppsettet; applikasjonen har ingen backchannel logout-rute.

Aktiver «Frontchannel logout krever sesjons-id», som i eksempeloppsettet. Koden krever én `iss`-verdi lik produksjonsutstederen og én ikke-tom `sid` på maksimalt 512 tegn i frontchannel-kallet. Under innlogging knyttes den lokale økten til `sid` dersom tokenet inneholder én gyldig slik claim. Uten denne koblingen kan frontchannel-kallet ikke finne og ugyldiggjøre den lokale økten. Verifiser derfor både mottak av `sid` og faktisk utlogging i egen integrasjon; URI-registrering alene er ikke tilstrekkelig.

### Koble klienten til PassordWeb

Kopier [JSON-malen](../appsettings.example.json) til nettstedroten som `appsettings.json`. Angi `idPorten.clientId`, `idPorten.clientSecret` og `idPorten.publicOrigin` for egen klient. Behold produksjonsverdiene for discovery, sikkerhetsnivå og autentiseringsmetode i malen. Konfigurer eventuell proxy i gruppen `proxy`, og følg stegene for IIS og tilgangskontroll. [Installasjonsveiledning](INSTALLASJON.md)

### Identitetsinformasjon som må avklares ved registrering

Koden ber uttrykkelig om `scope=openid`; den angir ingen andre scopes. Det må likevel bekreftes at egen klient får `pid` som kreves for AD-koblingen, samt øvrige claims i tabellen ovenfor. Ikke legg til et antatt scope for personidentifikator uten å avklare det med Digdir. Høyt autentiseringsnivå alene garanterer ikke tilgang til identitetsopplysningene.

Personidentifikatoren kobles til AD via kommunens lokalt konfigurerte og eksplisitt tillatte attributt, ikke via Client ID eller `sub`. Det kreves ett entydig aktivt kontotreff. Opplysninger om portalens gjeldende claim-tilganger og hvordan disse tildeles, må bekreftes ved egen registrering. Frontchannel-øktkoblingen og eksempelverdiene for levetider/SSO må også testes lokalt.
