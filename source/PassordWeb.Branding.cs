using System;
using System.Web;

namespace PassordWeb.TestAuth
{
    public static class Branding
    {
        public static string MunicipalityName { get { return LocalConfiguration.Current.MunicipalityName; } }
        public static string ServiceName { get { return LocalConfiguration.Current.ServiceName; } }
        public static string SupportText { get { return LocalConfiguration.Current.SupportText; } }
        public static string PasswordSyncHelpText { get { return LocalConfiguration.Current.PasswordSyncHelpText; } }

        public static string PageTitle(string page)
        {
            var suffix = ServiceName + " | " + MunicipalityName;
            return String.IsNullOrEmpty(page) ? suffix : page + " | " + suffix;
        }

        public static string BrandHtml()
        {
            var path = LocalConfiguration.Current.LogoPath;
            var name = HttpUtility.HtmlEncode(MunicipalityName);
            return path.Length == 0 ? "<strong>" + name + "</strong>" :
                "<img src=\"" + HttpUtility.HtmlAttributeEncode(path) + "\" alt=\"" + name + "\">";
        }

        public static string FaviconHtml()
        {
            var path = LocalConfiguration.Current.FaviconPath;
            return path.Length == 0 ? "" : "<link rel=\"icon\" href=\"" + HttpUtility.HtmlAttributeEncode(path) + "\">";
        }

        public static string FooterHtml()
        {
            return HttpUtility.HtmlEncode(MunicipalityName) + "<span>" + HttpUtility.HtmlEncode(SupportText) + "</span>";
        }
    }
}
