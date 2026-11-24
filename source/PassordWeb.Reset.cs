using System;
using System.Collections.Generic;
using System.DirectoryServices;
using System.Linq;
using System.Text;
using System.Web;
namespace PassordWeb.TestAuth {
 public sealed class ResetResult { public string Status; public DateTime? PasswordChangedUtc; public bool PasswordTimeEstimated; public static ResetResult Of(string s){return new ResetResult{Status=s};} }
 public interface IPasswordResetDirectory { ResetResult Reset(string pid,Guid accountId,string password); }
 public sealed class ResetSettings {
  public string LdapPath, UserName, Password;
  public static ResetSettings Load() { return LocalConfiguration.Current.AdReset; }
 }
 public sealed class AdPasswordResetDirectory:IPasswordResetDirectory {
  public static string TargetFilter(string pid,Guid id){
   return TargetFilter(pid,id,LocalConfiguration.AdIdentityAttribute());
  }
  private static string TargetFilter(string pid,Guid id,string identityAttribute){
   if(id==Guid.Empty)throw new ArgumentException();
   return "(&"+AccountDirectory.FilterForPid(pid,identityAttribute)+"(objectGUID="+String.Concat(id.ToByteArray().Select(b=>"\\"+b.ToString("x2")))+"))";
  }
  public ResetResult Reset(string pid,Guid id,string password){
   var outcome=ResetResult.Of("unavailable");string adUserName=null;
   try { outcome=ResetCore(pid,id,password,out adUserName);return outcome; }
   finally { PasswordResetAudit.Write(id,outcome.Status,adUserName); }
  }
  private ResetResult ResetCore(string pid,Guid id,string password,out string adUserName){
   adUserName=null;
   if(!AccountDirectory.IsPid(pid)||id==Guid.Empty||!PasswordResetPolicy.IsValid(password))return ResetResult.Of("invalid");
   try{
    var identityAttribute=LocalConfiguration.AdIdentityAttribute();
    var current=AccountDirectory.Find(pid);
    if(current.Status!="ok")return ResetResult.Of("unavailable");
    if(current.Accounts.Count!=1 || current.Accounts[0].AccountId!=id)return ResetResult.Of("denied");
    var s=ResetSettings.Load();var auth=AuthenticationTypes.Secure|AuthenticationTypes.Signing|AuthenticationTypes.Sealing;
    using(var root=new DirectoryEntry(s.LdapPath,s.UserName,s.Password,auth))
    using(var search=new DirectorySearcher(root)){
     search.Filter=TargetFilter(pid,id,identityAttribute);search.SearchScope=SearchScope.Subtree;search.ReferralChasing=ReferralChasingOption.None;search.SizeLimit=2;
     search.ClientTimeout=TimeSpan.FromSeconds(10);search.ServerTimeLimit=TimeSpan.FromSeconds(8);search.PropertiesToLoad.Add("objectGUID");
     using(var results=search.FindAll()){
      if(results.Count!=1)return ResetResult.Of("denied");
      using(var target=new DirectoryEntry(results[0].Path,s.UserName,s.Password,auth)){
       target.RefreshCache(new[]{"objectGUID",identityAttribute,"userAccountControl","objectClass","sAMAccountName"});
       var guid=target.Properties["objectGUID"].Value as byte[];
       if(guid==null||new Guid(guid)!=id||target.Properties[identityAttribute].Count!=1||!String.Equals(Convert.ToString(target.Properties[identityAttribute].Value),pid,StringComparison.Ordinal)||(Convert.ToInt32(target.Properties["userAccountControl"].Value)&2)!=0||!target.Properties["objectClass"].Cast<object>().Any(v=>Convert.ToString(v)=="user"))return ResetResult.Of("denied");
       if(target.Properties["sAMAccountName"].Count==1)adUserName=Convert.ToString(target.Properties["sAMAccountName"].Value);
       // Only AD write in this flow. No phone lookup, SMS, unlock or other attribute changes.
       target.Invoke("SetPassword",new object[]{password});
       var success=ResetResult.Of("success");
       success.PasswordChangedUtc=DateTime.UtcNow;success.PasswordTimeEstimated=true;
       // A read-back failure must never turn a completed password write into an apparent failure.
       try{
        target.RefreshCache(new[]{"pwdLastSet"});
        var changed=PasswordTimestamp.FromAd(target.Properties["pwdLastSet"].Value);
        if(changed.HasValue && changed.Value>=success.PasswordChangedUtc.Value.AddSeconds(-5)){
         success.PasswordChangedUtc=changed;success.PasswordTimeEstimated=false;
        }
       }catch{}
       return success;
      }
     }
    }
   }catch(Exception error){var e=error;while(e.InnerException!=null)e=e.InnerException;return ResetResult.Of(e.HResult==unchecked((int)0x800708C5)?"policy":"unavailable");}
  }
 }
 public static class PasswordResetPolicy {
  public const int MinimumLength=14,MaximumLength=256;
  public static bool IsValid(string p){return p!=null&&p.Length>=MinimumLength&&p.Length<=MaximumLength&&p.IndexOf('\0')<0;}
 }
 public sealed partial class AccountSession {
  private sealed class ResetForm{public Guid AccountId;public DateTime Expires;}
  private readonly Dictionary<string,ResetForm> resetForms=new Dictionary<string,ResetForm>(StringComparer.Ordinal);
  private readonly HashSet<Guid> completedResets=new HashSet<Guid>();
  private readonly DateTime identityExpires=DateTime.UtcNow.AddMinutes(10);
  private DateTime nextAttempt;private int resetAttempts;private string notice;
  private static string RandomToken(){var b=new byte[32];using(var r=System.Security.Cryptography.RandomNumberGenerator.Create())r.GetBytes(b);return Convert.ToBase64String(b).TrimEnd('=').Replace('+','-').Replace('/','_');}
  public string IssueResetToken(Guid id){lock(this){
   if(revoked||DateTime.UtcNow>=identityExpires||!AccountDirectory.IsPid(pid)||id==Guid.Empty||completedResets.Contains(id))return null;
   var accounts=Accounts();
   if(accounts.Status!="ok"||accounts.Accounts.Count!=1||accounts.Accounts[0].AccountId!=id)return null;
   resetForms.Clear();
   var token=RandomToken();resetForms.Add(token,new ResetForm{AccountId=id,Expires=DateTime.UtcNow.AddMinutes(5)});return token;
  }}
  public ResetResult TryReset(Guid id,string token,string password,string confirmation,IPasswordResetDirectory directory){lock(this){
   if(revoked||DateTime.UtcNow>=identityExpires||!AccountDirectory.IsPid(pid))return ResetResult.Of("expired");
   ResetForm form;if(String.IsNullOrEmpty(token)||token.Length!=43||!resetForms.TryGetValue(token,out form))return ResetResult.Of("csrf");
   resetForms.Remove(token);
   if(form.Expires<=DateTime.UtcNow||form.AccountId!=id||id==Guid.Empty)return ResetResult.Of("csrf");
   if(completedResets.Contains(id))return ResetResult.Of("completed");
   if(!PasswordResetPolicy.IsValid(password))return ResetResult.Of("length");
   if(!String.Equals(password,confirmation,StringComparison.Ordinal))return ResetResult.Of("mismatch");
   if(DateTime.UtcNow<nextAttempt||resetAttempts>=10)return ResetResult.Of("rate");
   resetAttempts++;nextAttempt=DateTime.UtcNow.AddSeconds(3);
   var outcome=directory.Reset(pid,id,password);
   if(outcome.Status=="success"){RememberPasswordChange(id,outcome);completedResets.Add(id);resetForms.Clear();notice="Passordet er endret. " + Branding.PasswordSyncHelpText;result=null;}
   return outcome;
  }}
  public bool ResetCompleted { get { lock(this) { return completedResets.Count>0; } } }
  public string TakeResetNotice(){lock(this){var n=notice;notice=null;return n;}}
 }
}
