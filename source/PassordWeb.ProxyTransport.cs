using System;
using System.Linq;
using System.Net;
using Microsoft.Owin;
namespace PassordWeb.TestAuth {
 public static class ProxyTransport {
  public static string NormalizeAddress(string address) {
   IPAddress parsed;
   if (String.IsNullOrWhiteSpace(address) || !IPAddress.TryParse(address, out parsed)) throw new InvalidOperationException("Invalid trusted proxy address.");
   if (parsed.IsIPv4MappedToIPv6) parsed = parsed.MapToIPv4();
   return parsed.ToString();
  }
  public static bool Apply(IOwinContext context, Settings settings) {
   if (context.Request.IsSecure) return false;
   if (!String.Equals(context.Request.Scheme, "http", StringComparison.OrdinalIgnoreCase)) return false;
   string peer;
   try { peer = NormalizeAddress(context.Request.RemoteIpAddress); } catch { return false; }
   if (settings.TrustedProxyAddresses == null || !settings.TrustedProxyAddresses.Contains(peer, StringComparer.OrdinalIgnoreCase)) return false;
   // Explicit opt-in for a proxy that forwards external HTTPS only.
   if (!settings.AssumeHttpsFromTrustedProxy) {
    var proto = context.Request.Headers.GetValues("X-Forwarded-Proto");
    if (proto == null || proto.Count != 1 || !String.Equals(proto[0], "https", StringComparison.OrdinalIgnoreCase)) return false;
   }
   // Never trust X-Forwarded-For or forwarded Host to select the proxy or application host.
   context.Request.Scheme = "https";
   return true;
  }
 }
}