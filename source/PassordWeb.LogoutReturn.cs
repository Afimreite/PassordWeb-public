using System;
using System.Linq;
using System.Security.Cryptography;
using System.Threading.Tasks;
using System.Web;
using System.Web.Caching;
using Microsoft.Owin;
namespace PassordWeb.TestAuth {
 public static class LogoutReturn {
  public static string ReturnUri { get { return Settings.SiteOrigin + "/auth/logged-out"; } }
  public const string CookiePrefix="__Host-PassordWebLogout.";
  private sealed class Pending {public DateTime Expires;public bool Used;}
  private static CookieOptions Options(){return new CookieOptions{Path="/",Secure=true,HttpOnly=true,SameSite=Microsoft.Owin.SameSiteMode.Lax,Expires=DateTime.UtcNow.AddMinutes(5)};}
  public static string Begin(IOwinContext ctx){
   var bytes=new byte[32];using(var rng=RandomNumberGenerator.Create())rng.GetBytes(bytes);
   var state=Convert.ToBase64String(bytes).TrimEnd('=').Replace('+','-').Replace('/','_');
   HttpRuntime.Cache.Insert("PassordWeb.LogoutReturn."+state,new Pending{Expires=DateTime.UtcNow.AddMinutes(5)},null,DateTime.UtcNow.AddMinutes(5),Cache.NoSlidingExpiration);
   ctx.Response.Cookies.Append(CookiePrefix+state,state,Options());return state;
  }
  public static bool Complete(IOwinContext ctx,string state){
   if(state==null||state.Length!=43||state.Any(c=>!(c>='A'&&c<='Z'||c>='a'&&c<='z'||c>='0'&&c<='9'||c=='_'||c=='-')))return false;
   var cookie=ctx.Request.Cookies[CookiePrefix+state];
   if(cookie==null||cookie.Length!=43)return false;
   int difference=0;for(int n=0;n<43;n++)difference|=cookie[n]^state[n];if(difference!=0)return false;
   var pending=HttpRuntime.Cache["PassordWeb.LogoutReturn."+state] as Pending;if(pending==null)return false;
   lock(pending){
    if(pending.Used||pending.Expires<=DateTime.UtcNow)return false;
    pending.Used=true;HttpRuntime.Cache.Remove("PassordWeb.LogoutReturn."+state);
   }
   ctx.Response.Cookies.Delete(CookiePrefix+state,Options());return true;
  }
  public static async Task Handle(IOwinContext ctx,string cookieType){
   if(ctx.Request.Method!="GET"){ctx.Response.Headers.Set("Allow","GET");await Startup.Reply(ctx,405,"Ugyldig metode.");return;}
   var values=ctx.Request.Query.GetValues("state");
   if(ctx.Request.Query.Any()){
    if(values==null||values.Count!=1||ctx.Request.Query.Count()!=1||!Complete(ctx,values[0])){
     await Startup.Reply(ctx,400,AccountPages.Shell("Utlogging kunne ikke bekreftes","<section class=\"card narrow\"><h1>Utloggingen kunne ikke bekreftes</h1><p>Returlenken er utløpt, allerede brukt eller tilhører en annen nettleser.</p><a class=\"button\" href=\"/\">Til forsiden →</a></section>"));return;
    }
    ctx.Response.StatusCode=303;ctx.Response.Headers.Set("Location","/auth/logged-out");return;
   }
   var current=await ctx.Authentication.AuthenticateAsync(cookieType);
   if(current!=null&&AccountSession.Get(current.Identity)!=null){ctx.Response.Redirect("/auth/success");return;}
   await Startup.Reply(ctx,200,AccountPages.Shell("Du er logget ut","<section class=\"card narrow\"><p class=\"eyebrow\">"+HttpUtility.HtmlEncode(Branding.ServiceName)+"</p><h1>Du er logget ut</h1><p>Innloggingen er avsluttet. Du må logge inn på nytt for å se kontoen din eller endre passord.</p><a class=\"button\" href=\"/\">Til forsiden <span aria-hidden=\"true\">→</span></a></section>"));
  }
 }
}
