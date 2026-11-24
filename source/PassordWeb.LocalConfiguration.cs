using System;
using System.Configuration;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;
using System.Web.Hosting;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace PassordWeb.TestAuth
{
    public sealed class LocalConfiguration
    {
        private static readonly Lazy<LocalConfiguration> Instance =
            new Lazy<LocalConfiguration>(Load);
        internal static LocalConfiguration Current { get { return Instance.Value; } }

        internal readonly Settings IdPorten;
        internal readonly ResetSettings AdLookup;
        internal readonly ResetSettings AdReset;
        internal readonly string AuditPath, MunicipalityName, ServiceName, SupportText, PasswordSyncHelpText, LogoPath, FaviconPath;
        private readonly string identityAttribute;

        private static LocalConfiguration Load()
        {
            const string file = "appsettings.json";
            JObject root;
            try
            {
                using (var stream = File.OpenRead(Path.Combine(HostingEnvironment.ApplicationPhysicalPath, file)))
                using (var reader = new JsonTextReader(new StreamReader(stream)))
                {
                    if (stream.Length > 65536) throw Invalid(file);
                    reader.MaxDepth = 12;
                    reader.DateParseHandling = DateParseHandling.None;
                    root = JObject.Load(reader, new JsonLoadSettings { DuplicatePropertyNameHandling = DuplicatePropertyNameHandling.Error });
                    if (reader.Read()) throw Invalid(file);
                }
            }
            catch (JsonException) { throw Invalid(file); }
            catch (IOException) { throw Invalid(file); }
            catch (UnauthorizedAccessException) { throw Invalid(file); }

            return new LocalConfiguration(root);
        }

        private LocalConfiguration(JObject root)
        {
            var idPorten = Section(root, "idPorten");
            var proxy = Section(root, "proxy");
            IdPorten = ReadIdPorten(idPorten, proxy);

            AdLookup = ReadDirectory(Section(root, "adLookup"), "adLookup");
            AdReset = ReadDirectory(Section(root, "adReset"), "adReset");
            if (String.Equals(AdLookup.UserName.Trim(), AdReset.UserName.Trim(), StringComparison.OrdinalIgnoreCase))
                throw Invalid("adLookup.userName / adReset.userName");

            var identity = Section(root, "identity");
            identityAttribute = Required(identity, "attribute", "identity.");
            if (!IsAdAttributeName(identityAttribute)) throw Invalid("identity.attribute");
            var allowed = Array(identity, "allowedAttributes", "identity.", 32);
            if (allowed.Any(value => value.Type != JTokenType.String || !IsAdAttributeName((string)value)))
                throw Invalid("identity.allowedAttributes");
            if (!allowed.Values<string>().Contains(identityAttribute, StringComparer.OrdinalIgnoreCase))
                throw Invalid("identity.attribute / identity.allowedAttributes");

            AuditPath = Required(root, "auditPath", "");
            try
            {
                if (!Regex.IsMatch(AuditPath, @"\A(?:[A-Za-z]:[\\/]|\\\\[^\\/]+[\\/][^\\/]+[\\/])"))
                    throw Invalid("auditPath");
                AuditPath = Path.GetFullPath(AuditPath);
                if (String.IsNullOrEmpty(Path.GetFileName(AuditPath))) throw Invalid("auditPath");
            }
            catch (ArgumentException) { throw Invalid("auditPath"); }
            catch (NotSupportedException) { throw Invalid("auditPath"); }
            catch (PathTooLongException) { throw Invalid("auditPath"); }

            var branding = Section(root, "branding");
            MunicipalityName = Profile(branding, "municipalityName", "Kommune", 150, false);
            ServiceName = Profile(branding, "serviceName", "Passordhjelp", 150, false);
            SupportText = Profile(branding, "supportText", "Trenger du hjelp? Kontakt kommunens brukerstøtte.", 500);
            PasswordSyncHelpText = Profile(branding, "passwordSyncHelpText",
                "Eventuell synkronisering av passord avhenger av kommunens identitetsløsning.", 1000);
            LogoPath = Asset(branding, "logoPath", "/Images/logo.svg", "png|jpe?g|gif|webp|svg");
            FaviconPath = Asset(branding, "faviconPath", "/Images/favicon.ico", "ico|png|svg");
        }

        private static Settings ReadIdPorten(JObject idPorten, JObject proxy)
        {
            var settings = new Settings
            {
                ClientId = Required(idPorten, "clientId", "idPorten."),
                ClientSecret = Required(idPorten, "clientSecret", "idPorten."),
                DiscoveryUrl = Required(idPorten, "discoveryUrl", "idPorten."),
                SecurityLevel = Required(idPorten, "securityLevel", "idPorten."),
                AuthMethod = Required(idPorten, "tokenEndpointAuthMethod", "idPorten.")
            };
            try { settings.Origin = Settings.ValidateOrigin(Required(idPorten, "publicOrigin", "idPorten.")); }
            catch (InvalidOperationException) { throw Invalid("idPorten.publicOrigin"); }
            if (settings.DiscoveryUrl != "https://idporten.no/.well-known/openid-configuration") throw Invalid("idPorten.discoveryUrl");
            if (settings.SecurityLevel != "idporten-loa-high") throw Invalid("idPorten.securityLevel");
            if (settings.AuthMethod != "client_secret_basic") throw Invalid("idPorten.tokenEndpointAuthMethod");
            settings.RedirectUri = settings.Origin + "/auth/callback/idporten";
            settings.PostLogoutRedirectUri = settings.Origin + "/auth/logged-out";

            var addresses = Array(proxy, "trustedAddresses", "proxy.", 16);
            if (addresses.Any(value => value.Type != JTokenType.String)) throw Invalid("proxy.trustedAddresses");
            try { settings.TrustedProxyAddresses = addresses.Values<string>().Select(ProxyTransport.NormalizeAddress).ToArray(); }
            catch (InvalidOperationException) { throw Invalid("proxy.trustedAddresses"); }
            var assumeHttps = proxy["assumeHttpsFromTrustedProxy"];
            if (assumeHttps == null || assumeHttps.Type != JTokenType.Boolean) throw Invalid("proxy.assumeHttpsFromTrustedProxy");
            settings.AssumeHttpsFromTrustedProxy = (bool)assumeHttps;
            if (settings.AssumeHttpsFromTrustedProxy && settings.TrustedProxyAddresses.Length == 0)
                throw Invalid("proxy.trustedAddresses");
            return settings;
        }

        private static ResetSettings ReadDirectory(JObject section, string name)
        {
            string prefix = name + ".";
            var path = Required(section, "ldapPath", prefix);
            if (!path.StartsWith("LDAP://", StringComparison.OrdinalIgnoreCase) || path.Length <= 7 || path.Contains("FILL_IN_") || path.Any(Char.IsControl))
                throw Invalid(prefix + "ldapPath");
            return new ResetSettings
            {
                LdapPath = path,
                UserName = Required(section, "userName", prefix),
                Password = Required(section, "password", prefix)
            };
        }

        internal static bool IsAdAttributeName(string value)
        {
            return value != null && Regex.IsMatch(value, @"\A[A-Za-z][A-Za-z0-9-]{0,63}\z", RegexOptions.CultureInvariant);
        }

        public static string AdIdentityAttribute() { return Current.identityAttribute; }

        private static JObject Section(JObject root, string name)
        {
            var result = root[name] as JObject;
            if (result == null) throw Invalid(name);
            return result;
        }

        private static JArray Array(JObject root, string name, string prefix, int maximum)
        {
            var result = root[name] as JArray;
            if (result == null || result.Count > maximum) throw Invalid(prefix + name);
            return result;
        }

        private static string Required(JObject section, string key, string prefix)
        {
            var token = section[key];
            var value = token != null && token.Type == JTokenType.String ? (string)token : null;
            if (String.IsNullOrWhiteSpace(value) || value.StartsWith("FILL_IN_", StringComparison.Ordinal))
                throw Invalid(prefix + key);
            return value;
        }

        private static string Profile(JObject section, string key, string fallback, int maximum, bool allowEmpty = true)
        {
            var token = section[key];
            if (token == null) return fallback;
            if (token.Type != JTokenType.String) throw Invalid("branding." + key);
            var value = (string)token;
            if (value.Length > maximum || value.Any(Char.IsControl) || (!allowEmpty && String.IsNullOrWhiteSpace(value)))
                throw Invalid("branding." + key);
            return value.Trim();
        }

        private static string Asset(JObject section, string key, string fallback, string extensions)
        {
            var value = Profile(section, key, fallback, 200);
            if (value.Length != 0 && !Regex.IsMatch(value, @"\A/Images/[A-Za-z0-9][A-Za-z0-9._-]*\.(?:" + extensions + @")\z",
                RegexOptions.CultureInvariant | RegexOptions.IgnoreCase)) throw Invalid("branding." + key);
            return value;
        }

        private static ConfigurationErrorsException Invalid(string field)
        {
            return new ConfigurationErrorsException("PassordWeb appsettings.json: Ugyldig eller manglende felt: " + field);
        }
    }
}
