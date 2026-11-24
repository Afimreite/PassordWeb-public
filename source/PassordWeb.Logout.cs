using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Web;
using System.Web.Caching;
using Microsoft.Owin;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
namespace PassordWeb.TestAuth {
 public sealed partial class AccountSession {
  private bool revoked;
  private string storeKey,providerSid,logoutToken;
  private sealed class SidSessions { public readonly List<WeakReference<AccountSession>> Sessions=new List<WeakReference<AccountSession>>(); }
  private static readonly object sidLock=new object();
  private void Register(string key,ClaimsIdentity identity){
   storeKey=key;
   var sid=identity.FindAll("sid").ToArray();
   if(sid.Length!=1||String.IsNullOrEmpty(sid[0].Value)||sid[0].Value.Length>512)return;
   providerSid=sid[0].Value;
   lock(sidLock){
    var cacheKey="PassordWeb.IdpSid."+providerSid;
    var sessions=HttpRuntime.Cache[cacheKey] as SidSessions ?? new SidSessions();
    sessions.Sessions.RemoveAll(w=>{AccountSession target;return !w.TryGetTarget(out target)||target.revoked||target.identityExpires<=DateTime.UtcNow;});
    sessions.Sessions.Add(new WeakReference<AccountSession>(this));
    HttpRuntime.Cache.Insert(cacheKey,sessions,null,DateTime.UtcNow.AddMinutes(10),Cache.NoSlidingExpiration);
   }
  }
  public string IssueLogoutToken(){lock(this){
   if(revoked||DateTime.UtcNow>=identityExpires)return null;
   if(logoutToken==null)logoutToken=RandomToken();return logoutToken;
  }}
  private static bool TokenEquals(string expected,string actual){
   if(expected==null||actual==null||expected.Length!=43||actual.Length!=43)return false;
   int difference=0;for(int i=0;i<43;i++)difference|=expected[i]^actual[i];return difference==0;
  }
  public bool TryLogout(string token){lock(this){
   if(revoked||DateTime.UtcNow>=identityExpires||!TokenEquals(logoutToken,token))return false;
   Invalidate();return true;
  }}
  public void Invalidate(){lock(this){
   revoked=true;resetForms.Clear();logoutToken=null;notice=null;result=null;pid=null;
   if(storeKey!=null)HttpRuntime.Cache.Remove("PassordWeb.Identity."+storeKey);
  }}
  public static bool InvalidateProviderSession(string issuer,string sid){
   if(issuer!="https://idporten.no"||String.IsNullOrEmpty(sid)||sid.Length>512)return false;
   AccountSession[] targets;
   lock(sidLock){
    var key="PassordWeb.IdpSid."+sid;var sessions=HttpRuntime.Cache[key] as SidSessions;
    if(sessions==null)return false;
    targets=sessions.Sessions.Select(w=>{AccountSession s;return w.TryGetTarget(out s)?s:null;}).Where(s=>s!=null).ToArray();
    HttpRuntime.Cache.Remove(key);
   }
   foreach(var target in targets){target.CancelTimeout();target.Invalidate();}return true;
  }
 }
 public static class LogoutUi {
  public static string Form(ClaimsIdentity identity){
   if(identity==null||!identity.IsAuthenticated||identity.AuthenticationType!="PassordWeb.TestCookie"||identity.FindAll("acr").Count()!=1||identity.FindFirst("acr").Value!="idporten-loa-high")return "";
   var session=AccountSession.Get(identity);var token=session==null?null:session.IssueLogoutToken();
   if(token==null)return "";
   return "<form class=\"logout-form\" method=\"post\" action=\"/auth/logout\"><input type=\"hidden\" name=\"csrf\" value=\""+HttpUtility.HtmlEncode(token)+"\"><button type=\"submit\" class=\"logout-button\">Logg ut</button></form>";
  }
  public static string CurrentForm(){
   if(HttpContext.Current==null)return "";
   var principal=HttpContext.Current.GetOwinContext().Authentication.User;
   return principal==null ? "" : Form(principal.Identity as ClaimsIdentity);
  }
 }
 public static class LogoutHttp {
  private static ConfigurationManager<OpenIdConnectConfiguration> manager;
  public static void Initialize(Settings settings){manager=new ConfigurationManager<OpenIdConnectConfiguration>(settings.DiscoveryUrl,new OpenIdConnectConfigurationRetriever(),new HttpDocumentRetriever{RequireHttps=true});}
  public static string RedirectUrl(string endpoint,string clientId){
   if(endpoint!="https://login.idporten.no/logout")throw new InvalidOperationException();
   return endpoint+"?client_id="+HttpUtility.UrlEncode(clientId);
  }
  public static string RedirectUrl(string endpoint,string clientId,string returnUri,string state){
   if(returnUri!=LogoutReturn.ReturnUri||state==null||state.Length!=43)throw new InvalidOperationException();
   return RedirectUrl(endpoint,clientId)+"&post_logout_redirect_uri="+HttpUtility.UrlEncode(returnUri)+"&state="+HttpUtility.UrlEncode(state);
  }
  public static async Task Handle(IOwinContext ctx,Settings settings,string cookieType){
   var auth=await ctx.Authentication.AuthenticateAsync(cookieType);
   var session=auth==null||!auth.Identity.IsAuthenticated||auth.Identity.FindAll("acr").Count()!=1||auth.Identity.FindFirst("acr").Value!=settings.SecurityLevel?null:AccountSession.Get(auth.Identity);
   if(session==null){ctx.Authentication.SignOut(cookieType);await Startup.Reply(ctx,401,AccountPages.Expired());return;}
   if(ctx.Request.Method=="GET"){
    await Startup.Reply(ctx,200,AccountPages.Shell("Logg ut","<section class=\"card narrow\"><h1>Logg ut</h1><p>Du blir logget ut her og sendt til ID-porten for å avslutte innloggingen der. Andre tjenester i samme ID-porten-sesjon kan også bli logget ut.</p>"+LogoutUi.Form(auth.Identity)+"</section>"));return;
   }
   if(ctx.Request.Method!="POST"){ctx.Response.Headers.Set("Allow","GET, POST");await Startup.Reply(ctx,405,"Ugyldig metode.");return;}
   var origin=ctx.Request.Headers.Get("Origin");string token=null;
   if((origin==null||origin==Settings.SiteOrigin)&&ctx.Request.ContentType!=null&&ctx.Request.ContentType.Split(';')[0].Trim().Equals("application/x-www-form-urlencoded",StringComparison.OrdinalIgnoreCase)){
    try{
     var buffer=new char[257];int count=0;
     using(var reader=new StreamReader(ctx.Request.Body,Encoding.UTF8,false,1024,true)){while(count<buffer.Length){int n=await reader.ReadAsync(buffer,count,buffer.Length-count);if(n==0)break;count+=n;}}
     if(count<=256){var form=HttpUtility.ParseQueryString(new string(buffer,0,count));if(form.Count==1&&form.GetValues("csrf")!=null&&form.GetValues("csrf").Length==1)token=form["csrf"];}
    }catch{}
   }
   if(!session.TryLogout(token)){await Startup.Reply(ctx,403,"Utloggingen kunne ikke bekreftes. Åpne siden på nytt og prøv igjen.");return;}
   session.CancelTimeout();
   ctx.Authentication.SignOut(cookieType);
   await RedirectProvider(ctx,settings);
  }
  public static async Task RedirectProvider(IOwinContext ctx,Settings settings){
   string destination=null;
   try{var metadata=await manager.GetConfigurationAsync(CancellationToken.None);RedirectUrl(metadata.EndSessionEndpoint,settings.ClientId);var state=LogoutReturn.Begin(ctx);destination=RedirectUrl(metadata.EndSessionEndpoint,settings.ClientId,settings.PostLogoutRedirectUri,state);}catch{}
   if(destination==null){await Startup.Reply(ctx,200,AccountPages.Shell("Logget ut","<section class=\"card narrow\"><h1>Du er logget ut her</h1><p>Vi kunne ikke åpne utloggingen hos ID-porten. Avslutt innloggingen der før du forlater en delt maskin.</p><a class=\"button\" href=\"https://login.idporten.no/logout\">Fortsett til ID-porten →</a></section>"));return;}
   ctx.Response.StatusCode=303;ctx.Response.Headers.Set("Location",destination);
  }
  public static async Task FrontChannel(IOwinContext ctx){
   if(ctx.Request.Method!="GET"){await Startup.Reply(ctx,405,"");return;}
   var issuer=ctx.Request.Query.GetValues("iss");var sid=ctx.Request.Query.GetValues("sid");
   if(issuer==null||issuer.Count!=1||issuer[0]!="https://idporten.no"||sid==null||sid.Count!=1||String.IsNullOrEmpty(sid[0])||sid[0].Length>512){await Startup.Reply(ctx,400,"");return;}
   AccountSession.InvalidateProviderSession(issuer[0],sid[0]);
   await Startup.Reply(ctx,200,"");
   ctx.Response.Headers.Set("Content-Security-Policy","default-src 'none'; frame-ancestors https://login.idporten.no; base-uri 'none'");
  }
 }
}
