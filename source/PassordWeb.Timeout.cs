using System;
using System.Collections.Specialized;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using System.Web;
using System.Web.Caching;
using Microsoft.Owin;
using Microsoft.IdentityModel.Tokens;
namespace PassordWeb.TestAuth {
 public static class AuthenticationFreshness {
  public static void Ensure(ClaimsIdentity identity,DateTimeOffset now){
   var values=identity.FindAll("auth_time").ToArray();long seconds;
   if(values.Length!=1||!Int64.TryParse(values[0].Value,NumberStyles.None,CultureInfo.InvariantCulture,out seconds))throw new SecurityTokenValidationException("Fresh authentication required.");
   var current=now.ToUnixTimeSeconds();
   if(seconds<current-300||seconds>current+60)throw new SecurityTokenValidationException("Fresh authentication required.");
  }
 }
 public sealed partial class AccountSession {
  private string timeoutToken;
  public DateTime ExpiresAt {get{return identityExpires;}}
  private void RegisterTimeout(){timeoutToken=RandomToken();TimeoutLogout.Register(timeoutToken,storeKey,identityExpires,this);}
  public string TimeoutForm(){lock(this){
   if(revoked||DateTime.UtcNow>=identityExpires||timeoutToken==null)return "";
   var left=Math.Max(0,Math.Ceiling((identityExpires-DateTime.UtcNow).TotalMilliseconds));
   return "<aside class=\"session-clock\"><span data-session-clock>Innloggingen utløper automatisk etter 10 minutter.</span><form method=\"post\" action=\"/auth/timeout\" data-session-timeout data-left-ms=\""+left.ToString(CultureInfo.InvariantCulture)+"\"><input type=\"hidden\" name=\"csrf\" value=\""+HttpUtility.HtmlEncode(timeoutToken)+"\"><noscript><p>Automatisk videresending krever JavaScript. Tilgangen stenges uansett etter 10 minutter. Bruk Logg ut når du er ferdig.</p></noscript></form></aside>";
  }}
  public static string CurrentTimeoutForm(){
   if(HttpContext.Current==null)return "";
   var principal=HttpContext.Current.GetOwinContext().Authentication.User;
   var identity=principal==null?null:principal.Identity as ClaimsIdentity;
   var session=identity==null?null:Get(identity);return session==null?"":session.TimeoutForm();
  }
  public void CancelTimeout(){if(timeoutToken!=null)TimeoutLogout.Cancel(timeoutToken);}
 }
 public static class TimeoutLogout {
  private sealed class Grant {
   public string SessionKey;
   public DateTime Expires;
   public WeakReference<AccountSession> Session;
   public bool Consumed;
  }
  public static void Register(string token,string key,DateTime expires,AccountSession session){
   HttpRuntime.Cache.Insert("PassordWeb.Timeout."+token,new Grant{SessionKey=key,Expires=expires,Session=new WeakReference<AccountSession>(session)},null,expires.AddHours(2),Cache.NoSlidingExpiration);
  }
  public static void Cancel(string token){HttpRuntime.Cache.Remove("PassordWeb.Timeout."+token);}
  // No account/identity access is granted. Only a due, one-use logout capability is accepted.
  public static string Consume(string token,string activeSessionKey,DateTime now){
   if(token==null||token.Length!=43)return "invalid";
   var grant=HttpRuntime.Cache["PassordWeb.Timeout."+token] as Grant;
   if(grant==null)return "invalid";
   lock(grant){
    if(grant.Consumed||now>grant.Expires.AddHours(2))return "invalid";
    if(activeSessionKey!=null&&!String.Equals(activeSessionKey,grant.SessionKey,StringComparison.Ordinal))return "new-session";
    if(now<grant.Expires)return "early";
    grant.Consumed=true;HttpRuntime.Cache.Remove("PassordWeb.Timeout."+token);
    AccountSession session;if(grant.Session.TryGetTarget(out session))session.Invalidate();
    return "success";
   }
  }
  public static async Task Handle(IOwinContext ctx,Settings settings,string cookieType){
   if(ctx.Request.Method!="POST"){ctx.Response.Headers.Set("Allow","POST");await Startup.Reply(ctx,405,"Ugyldig metode.");return;}
   var origin=ctx.Request.Headers.Get("Origin");
   if((origin!=null&&origin!=Settings.SiteOrigin)||ctx.Request.Query.Any()||ctx.Request.ContentType==null||!ctx.Request.ContentType.Split(';')[0].Trim().Equals("application/x-www-form-urlencoded",StringComparison.OrdinalIgnoreCase)){await Startup.Reply(ctx,403,"Ugyldig utloggingsforespørsel.");return;}
   string token=null;
   try{
    var b=new char[257];int count=0;
    using(var reader=new StreamReader(ctx.Request.Body,Encoding.UTF8,false,1024,true)){while(count<b.Length){int n=await reader.ReadAsync(b,count,b.Length-count);if(n==0)break;count+=n;}}
    if(count<=256){var form=HttpUtility.ParseQueryString(new string(b,0,count));if(form.Count==1&&form.GetValues("csrf")!=null&&form.GetValues("csrf").Length==1)token=form["csrf"];}
   }catch{}
   var auth=await ctx.Authentication.AuthenticateAsync(cookieType);
   var active=auth==null?null:AccountSession.Get(auth.Identity);
   var claim=active==null?null:auth.Identity.FindFirst(AccountSession.ClaimName);
   var result=Consume(token,claim==null?null:claim.Value,DateTime.UtcNow);
   if(result=="new-session"){ctx.Response.StatusCode=303;ctx.Response.Headers.Set("Location","/auth/success");return;}
   if(result=="early"){await Startup.Reply(ctx,409,AccountPages.Shell("Innloggingen er fortsatt aktiv","<section class=\"card narrow\"><h1>Innloggingen er fortsatt aktiv</h1><p>Utløpstiden er ikke nådd. Gå tilbake til kontoen din.</p><a href=\"/auth/success\">Din konto</a></section>"));return;}
   if(result!="success"){await Startup.Reply(ctx,403,AccountPages.Shell("Økten er utløpt","<section class=\"card narrow\"><h1>Økten er utløpt</h1><p>Utloggingsforespørselen er utløpt eller allerede brukt.</p><a href=\"/\">Til forsiden</a></section>"));return;}
   ctx.Authentication.SignOut(cookieType);
   await LogoutHttp.RedirectProvider(ctx,settings);
  }
 }
}
