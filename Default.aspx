<%@ Page Language="VB" %>
<!doctype html>
<html lang="nb">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <meta name="referrer" content="strict-origin" />
  <title><%: PassordWeb.TestAuth.Branding.PageTitle("Tilbakestill passord") %></title>
  <%= PassordWeb.TestAuth.Branding.FaviconHtml() %>
  <link rel="stylesheet" href="/Content/passord.css?v=ansatte" />
</head>
<body>
  <a class="skip-link" href="#main">Hopp til innhold</a>
  <header class="site-header landing-header">
    <a class="brand" href="/"><%= PassordWeb.TestAuth.Branding.BrandHtml() %></a>
    <div class="header-actions"><%= PassordWeb.TestAuth.LogoutUi.CurrentForm() %></div>
  </header>
  <main id="main" class="page landing landing-redesign" tabindex="-1">
    <section class="intro">
      <p class="eyebrow"><%: PassordWeb.TestAuth.Branding.ServiceName %> – FOR ANSATTE</p>
      <h1>Tilbakestill passord</h1>
      <p class="lead">Denne tjenesten er for ansatte i <%: PassordWeb.TestAuth.Branding.MunicipalityName %> som trenger å opprette et nytt passord til sin kommunale brukerkonto.</p>
    </section>
    <section class="employee-notice" aria-labelledby="employee-notice-title">
      <h2 id="employee-notice-title">Kun for ansatte</h2>
      <p>Du må være ansatt i <%: PassordWeb.TestAuth.Branding.MunicipalityName %> og ha en kommunal brukerkonto for å bruke tjenesten.</p>
    </section>
    <section class="card login-panel" aria-label="Tilbakestill passord">
      <div class="process-panel">
        <h2>Slik tilbakestiller du passordet</h2>
        <ol class="process-steps">
          <li><span class="step-number" aria-hidden="true">1</span><div><h3>Logg inn med ID-porten</h3><p>Bekreft identiteten din med BankID eller annen elektronisk ID.</p></div></li>
          <li><span class="step-number" aria-hidden="true">2</span><div><h3>Opprett nytt passord</h3><p>Velg et nytt og sikkert passord til din kommunale brukerkonto.</p></div></li>
        </ol>
      </div>
      <div class="signin-panel">
        <div class="signin-heading">
          <span class="signin-icon" aria-hidden="true"><svg viewBox="0 0 24 24" width="24" height="24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"><rect x="5" y="10" width="14" height="11" rx="2" /><path d="M8 10V7a4 4 0 0 1 8 0v3" /><path d="M12 14v3" /></svg></span>
          <h2>Sikker innlogging</h2>
        </div>
        <p>Vi bruker ID-porten for å bekrefte at du er den du utgir deg for å være.</p>
        <a class="button" href="/auth/login">Logg inn med ID-porten <span aria-hidden="true">→</span></a>
      </div>
    </section>
  </main>
  <footer><%= PassordWeb.TestAuth.Branding.FooterHtml() %></footer>
</body>
</html>
