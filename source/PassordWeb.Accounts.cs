using System;
using System.Collections.Generic;
using System.Configuration;
using System.DirectoryServices;
using System.Globalization;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Web;
using System.Web.Caching;

namespace PassordWeb.TestAuth
{
    public sealed class MatchedAccount
    {
        public string UserName, DisplayName, PrincipalName;
        public Guid AccountId;
        public DateTime? PasswordChangedUtc; public bool PasswordTimeEstimated;
    }
    public sealed class AccountResult
    {
        public string Status;
        public IList<MatchedAccount> Accounts = new List<MatchedAccount>();
    }
    public static class AccountDirectory
    {
        public static bool IsPid(string value) { return value != null && Regex.IsMatch(value, @"\A[0-9]{11}\z", RegexOptions.CultureInvariant); }
        public static string FilterForPid(string pid)
        {
            return FilterForPid(pid, LocalConfiguration.AdIdentityAttribute());
        }
        internal static string FilterForPid(string pid, string identityAttribute)
        {
            if (!IsPid(pid)) throw new ArgumentException("Invalid identity format.");
            if (!LocalConfiguration.IsAdAttributeName(identityAttribute)) throw new ConfigurationErrorsException("Invalid identity.attribute.");
            // Exactly eleven ASCII digits; the attribute is validated and explicitly approved locally.
            return "(&(objectCategory=person)(objectClass=user)(" + identityAttribute + "=" + pid + ")(!(userAccountControl:1.2.840.113556.1.4.803:=2)))";
        }
        private static string Value(SearchResult result, string name)
        {
            return result.Properties.Contains(name) && result.Properties[name].Count == 1 ? Convert.ToString(result.Properties[name][0], CultureInfo.InvariantCulture) : "";
        }
        public static AccountResult Find(string pid)
        {
            if (!IsPid(pid)) return new AccountResult { Status = "missing-pid" };
            try
            {
                var filter = FilterForPid(pid);
                var directory = LocalConfiguration.Current.AdLookup;
                using (var root = new DirectoryEntry(directory.LdapPath, directory.UserName, directory.Password, AuthenticationTypes.Secure | AuthenticationTypes.Signing | AuthenticationTypes.Sealing))
                using (var search = new DirectorySearcher(root))
                {
                    search.Filter = filter;
                    search.SearchScope = SearchScope.Subtree;
                    search.ReferralChasing = ReferralChasingOption.None;
                    search.SizeLimit = 21;
                    search.ClientTimeout = TimeSpan.FromSeconds(10);
                    search.ServerTimeLimit = TimeSpan.FromSeconds(8);
                    search.PropertiesToLoad.AddRange(new [] { "sAMAccountName", "displayName", "userPrincipalName", "objectGUID", "pwdLastSet" });
                    using (var results = search.FindAll())
                    {
                        if (results.Count > 20) return new AccountResult { Status = "error" };
                        var found = new AccountResult { Status = "ok" };
                        foreach (SearchResult result in results)
                        {
                            var name = Value(result, "sAMAccountName");
                            if (String.IsNullOrWhiteSpace(name)) continue;
                            found.Accounts.Add(new MatchedAccount { AccountId = new Guid((byte[])result.Properties["objectGUID"][0]), PasswordChangedUtc = PasswordTimestamp.FromAd(result.Properties.Contains("pwdLastSet") ? result.Properties["pwdLastSet"][0] : null), UserName = name, DisplayName = Value(result,"displayName"), PrincipalName = Value(result,"userPrincipalName") });
                        }
                        found.Accounts = found.Accounts.OrderBy(a => a.UserName, StringComparer.OrdinalIgnoreCase).ToList();
                        return found;
                    }
                }
            }
            catch (ConfigurationErrorsException) { return new AccountResult { Status = "configuration-error" }; }
            catch { return new AccountResult { Status = "error" }; }
        }
    }
    public sealed partial class AccountSession
    {
        public const string ClaimName = "passordweb:account-session";
        private string pid; private readonly string subject;
        private AccountResult result;
        private DateTime refreshAfter;
        private AccountSession(string person, string sub) { pid = person; subject = sub; }
        public static string Create(ClaimsIdentity identity)
        {
            var subjects = identity.FindAll("sub").ToArray();
            if (subjects.Length != 1 || String.IsNullOrEmpty(subjects[0].Value)) throw new InvalidOperationException();
            var persons = identity.FindAll("pid").ToArray();
            var person = persons.Length == 1 && AccountDirectory.IsPid(persons[0].Value) ? persons[0].Value : null;
            var bytes = new byte[32]; using (var rng = RandomNumberGenerator.Create()) rng.GetBytes(bytes);
            var key = Convert.ToBase64String(bytes).TrimEnd('=').Replace('+','-').Replace('/','_');
            var created = new AccountSession(person, subjects[0].Value);
            created.Register(key, identity);
            created.RegisterTimeout();
            HttpRuntime.Cache.Insert("PassordWeb.Identity." + key, created, null, created.ExpiresAt, Cache.NoSlidingExpiration, CacheItemPriority.Normal, (removedKey, value, reason) => ((AccountSession)value).Invalidate());
            return key;
        }
        public static AccountSession Get(ClaimsIdentity identity)
        {
            var key = identity.FindAll(ClaimName).ToArray();
            var sub = identity.FindAll("sub").ToArray();
            if (key.Length != 1 || sub.Length != 1 || !Regex.IsMatch(key[0].Value, @"\A[A-Za-z0-9_-]{43}\z")) return null;
            var session = HttpRuntime.Cache["PassordWeb.Identity." + key[0].Value] as AccountSession;
            if (session == null) return null;
            lock(session) { return !session.revoked && DateTime.UtcNow < session.identityExpires && String.Equals(session.subject, sub[0].Value, StringComparison.Ordinal) ? session : null; }
        }
        public AccountResult Accounts()
        {
            lock (this)
            {
                if (revoked || DateTime.UtcNow >= identityExpires) return new AccountResult { Status = "expired" };
                if (result == null || DateTime.UtcNow >= refreshAfter)
                {
                    result = AccountDirectory.Find(pid);
                    refreshAfter = DateTime.UtcNow.AddSeconds(result.Status == "error" ? 10 : 120);
                }
                ApplyPasswordChange(result);
                return result;
            }
        }
    }
    public static partial class AccountPages
    {
        private static string E(string value) { return HttpUtility.HtmlEncode(value ?? ""); }
        public static string Shell(string title, string content)
        {
            return "<!doctype html><html lang=\"nb\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"><title>" + E(Branding.PageTitle(title)) + "</title>" + Branding.FaviconHtml() + "<link rel=\"stylesheet\" href=\"/Content/passord.css\"><script src=\"/Scripts/passord-session.js\" defer></script></head><body data-session-expired-title=\"" + E(Branding.PageTitle("Økten er utløpt")) + "\"><header class=\"site-header\"><a class=\"brand\" href=\"/\">" + Branding.BrandHtml() + "</a><div class=\"header-actions\">" + LogoutUi.CurrentForm() + "</div></header><main id=\"main\" class=\"page\">" + content + AccountSession.CurrentTimeoutForm() + "</main><footer>" + Branding.FooterHtml() + "</footer></body></html>";
        }
        public static string Expired()
        {
            return Shell("Logg inn", "<section class=\"card narrow\"><p class=\"eyebrow\">SIKKER INNLOGGING</p><h1>Logg inn for å fortsette</h1><p>Logg inn på nytt for å se brukerkontoen som er knyttet til deg.</p><a class=\"button\" href=\"/auth/login\">Logg inn med ID-porten <span aria-hidden=\"true\">→</span></a></section>");
        }
    }
}
