using System;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Text;
using System.Threading;

namespace PassordWeb.TestAuth {
 internal static class PasswordResetAudit {
  internal static string FilePath { get { return LocalConfiguration.Current.AuditPath; } }
  private static readonly object Sync = new object();
  internal static void Write(Guid accountId, string status, string adUserName = null) { try { WriteTo(FilePath, accountId, status, adUserName); } catch(Exception error) { Trace.TraceError("Audit configuration unavailable ({0}).", error.GetType().Name); } }
  internal static void WriteLogin(AccountSession session) {
   if(session == null) return;
   try { WriteLoginTo(FilePath, session.Accounts()); }
   catch(Exception error) { Trace.TraceError("Audit configuration unavailable ({0}).", error.GetType().Name); }
  }
  internal static void WriteLoginTo(string path, AccountResult accounts) {
   var accountId = "-";
   var match = "unavailable";
   if(accounts != null && accounts.Status == "ok") {
    match = accounts.Accounts.Count == 0 ? "none" : accounts.Accounts.Count == 1 ? "unique" : "multiple";
    if(accounts.Accounts.Count == 1) accountId = accounts.Accounts[0].AccountId.ToString("D");
   }
   Append(path, "\tevent=idporten_login\tmessage=logget inn med idporten\taccountId=" + accountId + "\taccountMatch=" + match);
  }
  internal static void WriteTo(string path, Guid accountId, string status, string adUserName = null) {
   // Accept only fixed categories: never write exception messages, identity claims or form data.
   switch(status) {
    case "success": case "invalid": case "denied": case "policy": case "unavailable": break;
    default: status = "unavailable"; break;
   }
   Append(path, "\taccountId=" + accountId.ToString("D") + "\tresult=" + status + (String.IsNullOrEmpty(adUserName) ? "" : "\tadUserName=" + EscapeField(adUserName)));
  }
  private static string EscapeField(string value) {
   var safe = new StringBuilder();
   foreach(var c in value) {
    if(c == (char)92) { safe.Append((char)92); safe.Append((char)92); }
    else if(Char.IsControl(c) || c == (char)0x2028 || c == (char)0x2029) safe.Append((char)92).Append('u').Append(((int)c).ToString("x4", CultureInfo.InvariantCulture));
    else safe.Append(c);
   }
   return safe.ToString();
  }
  private static void Append(string path, string fields) {
   try {
    var line = DateTime.UtcNow.ToString("o", CultureInfo.InvariantCulture) + fields + Environment.NewLine;
    var bytes = new UTF8Encoding(false).GetBytes(line);
    lock(Sync) {
     // Exclusive writer plus bounded retry also covers overlapping IIS worker processes.
     for(var attempt = 0; ; attempt++) {
      try {
       using(var file = new FileStream(path, FileMode.Append, FileAccess.Write, FileShare.Read)) {
        file.Write(bytes, 0, bytes.Length);
        file.Flush(true);
       }
       break;
      } catch(IOException) {
       if(attempt >= 19) throw;
       Thread.Sleep(25);
      }
     }
    }
   } catch(Exception error) {
    // A log failure must not change the result of an AD write that already succeeded.
    try { Trace.TraceError("Password service audit write failed ({0}).", error.GetType().Name); } catch { }
   }
  }
 }
}