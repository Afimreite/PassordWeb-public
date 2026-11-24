using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Web;
using Microsoft.Owin;
using Microsoft.Owin.Extensions;
using Microsoft.Owin.Logging;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Cookies;
using Microsoft.Owin.Security.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using Owin;

namespace PassordWeb.TestAuth
{
    public sealed class Settings
    {
        public string Origin;
        public bool AssumeHttpsFromTrustedProxy;
        public string[] TrustedProxyAddresses = new string[0];
        public static string SiteOrigin { get { return Load().Origin; } }
        public string ClientId, ClientSecret, DiscoveryUrl, RedirectUri, SecurityLevel, AuthMethod, PostLogoutRedirectUri;
        public static string ValidateOrigin(string value)
        {
            Uri uri;
            if (!Uri.TryCreate(value, UriKind.Absolute, out uri) || uri.Scheme != "https" || !uri.IsDefaultPort || uri.HostNameType != UriHostNameType.Dns || !String.IsNullOrEmpty(uri.UserInfo) || uri.AbsolutePath != "/" || !String.IsNullOrEmpty(uri.Query) || !String.IsNullOrEmpty(uri.Fragment)) throw new InvalidOperationException("Invalid public origin.");
            return uri.GetLeftPart(UriPartial.Authority);
        }
        public static Settings Load() { return LocalConfiguration.Current.IdPorten; }
    }
    // Katana normally posts ClientSecret. Only this fixed HTTPS token endpoint receives Basic credentials.
    public sealed class BasicTokenHandler : DelegatingHandler
    {
        private readonly Settings settings;
        public BasicTokenHandler(Settings s, HttpMessageHandler inner) : base(inner) { settings = s; }
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            if (request.Method == HttpMethod.Post)
            {
                if (request.RequestUri.AbsoluteUri != "https://idporten.no/token") throw new InvalidOperationException("Unexpected token endpoint.");
                var form = HttpUtility.ParseQueryString(await request.Content.ReadAsStringAsync());
                form.Remove("client_secret");
                request.Content = new FormUrlEncodedContent(form.AllKeys.Select(k => new KeyValuePair<string,string>(k, form[k])));
                var credentials = HttpUtility.UrlEncode(settings.ClientId) + ":" + HttpUtility.UrlEncode(settings.ClientSecret);
                request.Headers.Authorization = new AuthenticationHeaderValue("Basic", Convert.ToBase64String(Encoding.ASCII.GetBytes(credentials)));
            }
            return await base.SendAsync(request, cancellationToken);
        }
    }
    public sealed class SilentLoggerFactory : ILoggerFactory
    {
        private sealed class SilentLogger : ILogger
        {
            public bool WriteCore(System.Diagnostics.TraceEventType eventType, int eventId, object state, Exception exception, Func<object, Exception, string> formatter) { return false; }
        }
        public ILogger Create(string name) { return new SilentLogger(); }
    }
    public sealed class Startup
    {
        private const string CookieType = "PassordWeb.TestCookie";
        private const string OidcType = "PassordWeb.IdPorten";
        internal static Task Reply(IOwinContext ctx, int status, string text)
        {
            ctx.Response.StatusCode = status;
            ctx.Response.ContentType = "text/html; charset=utf-8";
            ctx.Response.Headers.Set("Cache-Control", "no-store");
            ctx.Response.Headers.Set("Pragma", "no-cache");
            ctx.Response.Headers.Set("Referrer-Policy", "strict-origin");
            ctx.Response.Headers.Set("X-Content-Type-Options", "nosniff");
            ctx.Response.Headers.Set("Content-Security-Policy", "default-src 'none'; style-src 'self'; img-src 'self'; script-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self' https://login.idporten.no/logout");
            if (HttpContext.Current != null) { HttpContext.Current.Response.TrySkipIisCustomErrors = true; HttpContext.Current.Response.SuppressFormsAuthenticationRedirect = true; }
            return ctx.Response.WriteAsync(text);
        }
        public void Configuration(IAppBuilder app)
        {
            // Do not allow Katana exceptions (including invalid raw tokens) into diagnostics.
            app.SetLoggerFactory(new SilentLoggerFactory());
            Microsoft.IdentityModel.Logging.IdentityModelEventSource.ShowPII = false;
            var config = Settings.Load();
            // Normalize transport before cookies and OpenID Connect inspect the request.
            app.Use(async (ctx, next) => {
                ProxyTransport.Apply(ctx, config);
                await next();
            });
            app.Use(async (ctx, next) => {
                if (String.Equals(ctx.Request.Path.Value, "/reset.aspx", StringComparison.OrdinalIgnoreCase)) { ctx.Response.Redirect("/auth/success"); return; }
                if (!ctx.Request.Path.StartsWithSegments(new PathString("/auth"))) { await next(); return; }
                ctx.Response.Headers.Set("Cache-Control", "no-store");
                ctx.Response.Headers.Set("Referrer-Policy", "no-referrer");
                try {
                    if (!ctx.Request.IsSecure || !String.Equals(ctx.Request.Host.Value, new Uri(config.Origin).Authority, StringComparison.OrdinalIgnoreCase)) { await Reply(ctx, 400, "Ugyldig adresse."); return; }
                    await next();
                } catch { ctx.Set("PassordWeb.AuthFailed", true); }
                if (ctx.Get<bool>("PassordWeb.AuthFailed")) await Reply(ctx, 400, "Innloggingen kunne ikke bekreftes. Start innloggingen pa nytt.");
            });
            LogoutHttp.Initialize(config);
            app.SetDefaultSignInAsAuthenticationType(CookieType);
            app.UseCookieAuthentication(new CookieAuthenticationOptions {
                AuthenticationType = CookieType, CookieName = "__Host-PassordWebTestAuth", CookiePath = "/", CookieHttpOnly = true,
                CookieSecure = CookieSecureOption.Always, CookieSameSite = Microsoft.Owin.SameSiteMode.Lax,
                ExpireTimeSpan = TimeSpan.FromMinutes(10), SlidingExpiration = false,
                Provider = new CookieAuthenticationProvider {
                    OnResponseSignIn = n => {
                        // Only log a completed ID-porten callback when the validated session cookie is issued.
                        if(n.OwinContext.Get<bool>("PassordWeb.IdPortenValidated")) PasswordResetAudit.WriteLogin(AccountSession.Get(n.Identity));
                    },
                    OnValidateIdentity = n => {
                    if (n.Identity == null || n.Identity.FindAll("acr").Count() != 1 || n.Identity.FindFirst("acr").Value != config.SecurityLevel || AccountSession.Get(n.Identity) == null) { n.RejectIdentity(); n.OwinContext.Authentication.SignOut(CookieType); }
                    return Task.FromResult(0);
                } }
            });
            var options = new OpenIdConnectAuthenticationOptions(OidcType) {
                AuthenticationMode = AuthenticationMode.Passive, SignInAsAuthenticationType = CookieType,
                Authority = "https://idporten.no", MetadataAddress = config.DiscoveryUrl,
                ClientId = config.ClientId, RedirectUri = config.RedirectUri, CallbackPath = new PathString("/auth/callback/idporten"),
                ResponseType = "code", ResponseMode = "query", Scope = "openid", UsePkce = true, RedeemCode = true, SaveTokens = false,
                RequireHttpsMetadata = true, UseTokenLifetime = false, BackchannelTimeout = TimeSpan.FromSeconds(15),
                BackchannelHttpHandler = new BasicTokenHandler(config, new HttpClientHandler { AllowAutoRedirect = false }),
                SecurityTokenValidator = new JwtSecurityTokenHandler { MapInboundClaims = false },
                TokenValidationParameters = new TokenValidationParameters {
                    AuthenticationType = CookieType, ValidateIssuer = true, ValidIssuer = "https://idporten.no", ValidateAudience = true, ValidAudience = config.ClientId,
                    ValidateLifetime = true, RequireExpirationTime = true, RequireSignedTokens = true, ValidateIssuerSigningKey = true,
                    ValidAlgorithms = new [] { "RS256" }, ClockSkew = TimeSpan.FromSeconds(60)
                },
                Notifications = new OpenIdConnectAuthenticationNotifications {
                    RedirectToIdentityProvider = n => {
                        n.ProtocolMessage.SetParameter("acr_values", config.SecurityLevel);
                        n.ProtocolMessage.SetParameter("prompt", "login");
                        return Task.FromResult(0);
                    },
                    SecurityTokenValidated = n => {
                        var identity = n.AuthenticationTicket.Identity;
                        if (identity.FindAll("acr").Count() != 1 || identity.FindFirst("acr").Value != config.SecurityLevel || String.IsNullOrEmpty(identity.FindFirst("sub") == null ? null : identity.FindFirst("sub").Value)) throw new SecurityTokenValidationException("Required assurance missing.");
                        AuthenticationFreshness.Ensure(identity, DateTimeOffset.UtcNow);
                        var accountSession = AccountSession.Create(identity);
                        var minimal = identity.Claims.Where(c => c.Type == "sub" || c.Type == "acr" || c.Type == "auth_time").Concat(new [] { new Claim(AccountSession.ClaimName, accountSession) }).ToArray();
                        n.AuthenticationTicket = new AuthenticationTicket(new ClaimsIdentity(minimal, CookieType), new AuthenticationProperties { IsPersistent = false, IssuedUtc = DateTimeOffset.UtcNow, ExpiresUtc = DateTimeOffset.UtcNow.AddMinutes(10), RedirectUri = "/auth/success" });
                        n.OwinContext.Set("PassordWeb.IdPortenValidated", true);
                        return Task.FromResult(0);
                    },
                    AuthenticationFailed = async n => { n.HandleResponse(); await Reply(n.OwinContext, 400, "Innloggingen kunne ikke bekreftes. Start innloggingen pa nytt."); }
                }
            };
            options.ProtocolValidator.RequireNonce = true;
            options.ProtocolValidator.NonceLifetime = TimeSpan.FromMinutes(10);
            app.UseOpenIdConnectAuthentication(options);
            app.Use(async (ctx, next) => {
                var path = ctx.Request.Path.Value;
                if (path == "/" || String.Equals(path, "/Default.aspx", StringComparison.OrdinalIgnoreCase)) {
                    ctx.Response.Headers.Set("Cache-Control", "no-store");
                    var signedIn = await ctx.Authentication.AuthenticateAsync(CookieType);
                    if (signedIn != null && signedIn.Identity.IsAuthenticated && signedIn.Identity.FindAll("acr").Count() == 1 && signedIn.Identity.FindFirst("acr").Value == config.SecurityLevel && AccountSession.Get(signedIn.Identity) != null) {
                        ctx.Response.Redirect("/auth/success"); return;
                    }
                    await next(); return;
                }
                if (!path.StartsWith("/auth/", StringComparison.OrdinalIgnoreCase)) { await next(); return; }
                if (path == "/auth/login" && ctx.Request.Method == "GET") {
                    var signedIn = await ctx.Authentication.AuthenticateAsync(CookieType);
                    if (signedIn != null && signedIn.Identity.IsAuthenticated && signedIn.Identity.FindAll("acr").Count() == 1 && signedIn.Identity.FindFirst("acr").Value == config.SecurityLevel && AccountSession.Get(signedIn.Identity) != null) { ctx.Response.Redirect("/auth/success"); return; }
                    ctx.Authentication.Challenge(new AuthenticationProperties { RedirectUri = "/auth/success", IsPersistent = false }, OidcType);
                    await Reply(ctx, 401, "Starter innlogging."); return;
                }
                if (path == "/auth/timeout") { await TimeoutLogout.Handle(ctx, config, CookieType); return; }
                if (path == "/auth/logged-out") { await LogoutReturn.Handle(ctx, CookieType); return; }
                if (path == "/auth/logout") { await LogoutHttp.Handle(ctx, config, CookieType); return; }
                if (path == "/auth/frontchannel-logout") { await LogoutHttp.FrontChannel(ctx); return; }
                if (path == "/auth/reset") { await ResetHttp.Handle(ctx, CookieType, config.SecurityLevel); return; }
                if (path == "/auth/success" && ctx.Request.Method == "GET") {
                    var auth = await ctx.Authentication.AuthenticateAsync(CookieType);
                    if (auth == null || !auth.Identity.IsAuthenticated || auth.Identity.FindFirst("acr") == null || auth.Identity.FindFirst("acr").Value != config.SecurityLevel) { await Reply(ctx, 401, AccountPages.Expired()); return; }
                    var accountSession = AccountSession.Get(auth.Identity);
                    if (accountSession == null) { ctx.Authentication.SignOut(CookieType); await Reply(ctx, 401, AccountPages.Expired()); return; }
                    await Reply(ctx, 200, AccountPages.Accounts(accountSession.Accounts(), accountSession.TakeResetNotice(), accountSession.ResetCompleted)); return;
                }
                await Reply(ctx, path == "/auth/callback/idporten" ? 400 : 404, "Ugyldig autentiseringsforesporsel.");
            });
            app.UseStageMarker(PipelineStage.Authenticate);
        }
    }
}
