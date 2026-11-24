using System;
using System.Collections.Specialized;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Web;
using Microsoft.Owin;
namespace PassordWeb.TestAuth {
 public static partial class AccountPages {
  public static string Accounts(AccountResult result,string notice=null,bool completed=false){
   var h=new StringBuilder("<section class=\"overview-heading\"><p class=\"eyebrow\">"+E(Branding.ServiceName)+"</p><div class=\"verified\"><span aria-hidden=\"true\">✓</span> Identiteten din er bekreftet med ID-porten</div><h1>Din brukerkonto</h1></section>");
   if(!String.IsNullOrEmpty(notice))h.Append("<div class=\"success-notice\" role=\"status\">"+E(notice)+"</div>");
   if(result.Status=="missing-pid")h.Append("<section class=\"card empty\"><h2>Vi kunne ikke identifisere kontoen din</h2><p>Innloggingen inneholdt ikke en norsk personidentifikator. "+E(Branding.SupportText)+"</p></section>");
   else if(result.Status=="configuration-error")h.Append("<section class=\"card empty\" role=\"alert\"><h2>AD-oppslag er ikke riktig konfigurert</h2><p>Administrator må kontrollere lokal AD-konfigurasjon, inkludert identity.attribute og identity.allowedAttributes.</p></section>");
   else if(result.Status!="ok")h.Append("<section class=\"card empty\" role=\"alert\"><h2>Vi får ikke hentet kontoen akkurat nå</h2><p>Prøv igjen om litt. "+E(Branding.SupportText)+"</p><a class=\"text-link\" href=\"/auth/success\">Prøv igjen →</a></section>");
   else if(result.Accounts.Count==0)h.Append("<section class=\"card empty\"><h2>Ingen aktiv brukerkonto funnet</h2><p>Vi fant ingen aktiv konto knyttet til deg. "+E(Branding.SupportText)+"</p></section>");
   else if(result.Accounts.Count!=1)h.Append("<section class=\"card empty\" role=\"alert\"><h2>Kontoen må kontrolleres</h2><p>Vi kunne ikke knytte identiteten din til én entydig konto. "+E(Branding.SupportText)+"</p></section>");
   else {
    var a=result.Accounts[0];
    h.Append("<article class=\"card account single-account\"><div class=\"account-icon\" aria-hidden=\"true\">●</div><div class=\"account-detail\"><h2>"+E(String.IsNullOrWhiteSpace(a.DisplayName)?a.UserName:a.DisplayName)+"</h2><dl><div><dt>AD-brukernavn</dt><dd>"+E(a.UserName)+"</dd></div><div><dt>365-brukernavn</dt><dd>"+E(String.IsNullOrEmpty(a.PrincipalName)?"Ikke registrert":a.PrincipalName)+"</dd></div><div><dt>Sist byttet passord</dt><dd>"+E(PasswordTimestamp.Display(a.PasswordChangedUtc,a.PasswordTimeEstimated))+"</dd></div></dl></div><div class=\"account-action\"><span class=\"status\">Aktiv konto</span>");
    if(completed)h.Append("<span class=\"reset-complete\">✓ Passord endret</span>");
    else h.Append("<a class=\"button account-reset\" href=\"/auth/reset\">Endre passord →</a>");
    h.Append("</div></article><p class=\"privacy-note\">AD-brukernavnet brukes i kommunens systemer. 365-brukernavnet er kontoens påloggingsnavn for Microsoft 365.</p>");
   }
   h.Append("<p class=\"privacy-note\">Innloggingen varer i inntil 10 minutter.</p>");
   return Shell("Din brukerkonto",h.ToString());
  }
 }
 public static class ResetPages {
  private static string E(string v){return HttpUtility.HtmlEncode(v??"");}
  public static string Message(string s){switch(s){
   case "length":return "Passordet må være mellom 14 og 256 tegn.";
   case "mismatch":return "Passordene er ikke like. Skriv inn det samme passordet i begge feltene.";
   case "policy":return "AD avviste passordet. Velg et nytt passord som oppfyller kommunens krav og ikke er brukt tidligere.";
   case "rate":return "Vent litt før du prøver igjen. Etter flere forsøk må du logge inn på nytt.";
   case "csrf":return "Skjemaet er utløpt eller allerede sendt inn. Åpne passordskjemaet på nytt.";
   case "completed":return "Passordet er allerede endret i denne økten. Logg inn på nytt ved behov.";
   case "denied":return "Kontoen er ikke lenger tilgjengelig for passordreset. Gå tilbake til kontoen din.";
   default:return "Passordet kunne ikke endres. Prøv igjen senere. " + Branding.SupportText;
  }}
  public static string Form(MatchedAccount a,string csrf,string error){
   var h=new StringBuilder("<a class=\"text-link\" href=\"/auth/success\">← Tilbake til din konto</a><section class=\"card narrow reset-card\"><p class=\"eyebrow\">"+E(Branding.ServiceName)+"</p><h1>Velg et nytt passord</h1><p>Du endrer passordet for <strong>"+E(a.UserName)+"</strong>.</p>");
   if(!String.IsNullOrEmpty(error))h.Append("<div class=\"form-error\" role=\"alert\">"+E(error)+"</div>");
   if(csrf==null)h.Append("<p>Åpne kontosiden og logg inn på nytt ved behov.</p>");
   else h.Append("<form method=\"post\" action=\"/auth/reset\" class=\"reset-form\"><input type=\"hidden\" name=\"csrf\" value=\""+E(csrf)+"\"><label for=\"new-password\">Nytt passord</label><input id=\"new-password\" name=\"newPassword\" type=\"password\" minlength=\"14\" maxlength=\"256\" autocomplete=\"new-password\" required aria-describedby=\"password-help\"><p id=\"password-help\" class=\"field-help\">Minst 14 tegn. Passordet må også oppfylle kommunens passordkrav. Du kan bruke mellomrom.</p><label for=\"confirm-password\">Gjenta nytt passord</label><input id=\"confirm-password\" name=\"confirmPassword\" type=\"password\" minlength=\"14\" maxlength=\"256\" autocomplete=\"new-password\" required><button class=\"button\" type=\"submit\">Endre passord <span aria-hidden=\"true\">→</span></button></form>");
   h.Append("<p class=\"privacy-note\">Det nye passordet gjelder for AD-kontoen. "+E(Branding.PasswordSyncHelpText)+"</p></section>");
   return AccountPages.Shell("Endre passord",h.ToString());
  }
 }
 public static class ResetHttp {
  public static async Task<NameValueCollection> ReadForm(Stream body){
   var b=new char[8193];int used=0;
   using(var r=new StreamReader(body,Encoding.UTF8,false,1024,true)){
    while(used<b.Length){var n=await r.ReadAsync(b,used,b.Length-used);if(n==0)break;used+=n;}
   }
   if(used>8192)throw new InvalidDataException();
   var f=HttpUtility.ParseQueryString(new string(b,0,used));
   if(f.Count!=3 || new[]{"csrf","newPassword","confirmPassword"}.Any(k=>f.GetValues(k)==null || f.GetValues(k).Length!=1))throw new InvalidDataException();
   return f;
  }
  public static async Task Handle(IOwinContext ctx,string cookieType,string high){
   var auth=await ctx.Authentication.AuthenticateAsync(cookieType);
   if(auth==null||!auth.Identity.IsAuthenticated||auth.Identity.FindAll("acr").Count()!=1||auth.Identity.FindFirst("acr").Value!=high){await Startup.Reply(ctx,401,AccountPages.Expired());return;}
   var session=AccountSession.Get(auth.Identity);
   if(session==null){ctx.Authentication.SignOut(cookieType);await Startup.Reply(ctx,401,AccountPages.Expired());return;}
   if(ctx.Request.Query.Any()){await Startup.Reply(ctx,400,"Ugyldig forespørsel.");return;}
   var accounts=session.Accounts();
   if(accounts.Status!="ok"||accounts.Accounts.Count!=1){await Startup.Reply(ctx,403,AccountPages.Accounts(accounts));return;}
   var account=accounts.Accounts[0];
   if(ctx.Request.Method=="GET"){
    var token=session.IssueResetToken(account.AccountId);
    await Startup.Reply(ctx,token==null?409:200,ResetPages.Form(account,token,token==null?ResetPages.Message("completed"):null));return;
   }
   if(ctx.Request.Method!="POST"){ctx.Response.Headers.Set("Allow","GET, POST");await Startup.Reply(ctx,405,"Ugyldig metode.");return;}
   var origin=ctx.Request.Headers.Get("Origin");
   if((origin!=null&&origin!=Settings.SiteOrigin)||ctx.Request.ContentType==null||!ctx.Request.ContentType.Split(';')[0].Trim().Equals("application/x-www-form-urlencoded",StringComparison.OrdinalIgnoreCase)){
    await Startup.Reply(ctx,403,ResetPages.Form(account,null,ResetPages.Message("csrf")));return;
   }
   NameValueCollection form=null;
   try{form=await ReadForm(ctx.Request.Body);}catch{}
   if(form==null){await Startup.Reply(ctx,400,ResetPages.Form(account,null,ResetPages.Message("csrf")));return;}
   var result=session.TryReset(account.AccountId,form["csrf"],form["newPassword"],form["confirmPassword"],new AdPasswordResetDirectory());
   form.Clear();
   if(result.Status=="success"){ctx.Response.StatusCode=303;ctx.Response.Headers.Set("Location","/auth/success");return;}
   // Redisplay ordinary form errors with 200; keep security and service failures distinct.
   var status=result.Status=="csrf"||result.Status=="denied"?403:result.Status=="rate"?429:result.Status=="unavailable"?503:result.Status=="mismatch"||result.Status=="length"||result.Status=="policy"?200:422;
   await Startup.Reply(ctx,status,ResetPages.Form(account,session.IssueResetToken(account.AccountId),ResetPages.Message(result.Status)));
  }
 }
}
