using System;
using System.Globalization;
using System.Reflection;
namespace PassordWeb.TestAuth {
 public static class PasswordTimestamp {
  public static DateTime? FromAd(object value){
   if(value==null)return null;
   try{
    long ticks;
    try{ticks=Convert.ToInt64(value,CultureInfo.InvariantCulture);}
    catch{
     var type=value.GetType();
     var high=Convert.ToInt32(type.InvokeMember("HighPart",BindingFlags.GetProperty,null,value,null),CultureInfo.InvariantCulture);
     var low=Convert.ToInt32(type.InvokeMember("LowPart",BindingFlags.GetProperty,null,value,null),CultureInfo.InvariantCulture);
     ticks=((long)high<<32)|(uint)low;
    }
    return ticks>0?(DateTime?)DateTime.FromFileTimeUtc(ticks):null;
   }catch{return null;}
  }
  public static string Display(DateTime? utc,bool estimated=false){
   if(!utc.HasValue)return "Ikke tilgjengelig";
   var local=TimeZoneInfo.ConvertTimeFromUtc(DateTime.SpecifyKind(utc.Value,DateTimeKind.Utc),TimeZoneInfo.FindSystemTimeZoneById("W. Europe Standard Time"));
   return local.ToString("dd.MM.yyyy 'kl.' HH:mm",CultureInfo.GetCultureInfo("nb-NO"))+(estimated?" (bekreftet her)":"");
  }
 }
 public sealed partial class AccountSession {
  private Guid lastChangedAccount;
  private DateTime? lastChangedUtc;
  private bool lastChangedEstimated;
  private void RememberPasswordChange(Guid id,ResetResult outcome){
   lastChangedAccount=id;lastChangedUtc=outcome.PasswordChangedUtc??DateTime.UtcNow;
   lastChangedEstimated=outcome.PasswordTimeEstimated||!outcome.PasswordChangedUtc.HasValue;
  }
  private void ApplyPasswordChange(AccountResult accounts){
   if(!lastChangedUtc.HasValue)return;
   foreach(var account in accounts.Accounts){
    if(account.AccountId==lastChangedAccount&&(!account.PasswordChangedUtc.HasValue||account.PasswordChangedUtc.Value<lastChangedUtc.Value)){
     account.PasswordChangedUtc=lastChangedUtc;account.PasswordTimeEstimated=lastChangedEstimated;
    }
   }
  }
 }
}
