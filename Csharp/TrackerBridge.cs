using System;
using System.Globalization;
using System.IO;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace UssdApp
{
    // Consent-based bridge to the external laptop-tracker service.
    // This class does not start external processes and does not access
    // location hardware; it only calls explicit HTTP endpoints when the user
    // supplies server + identifiers.
    public sealed class TrackerBridge
    {
        public sealed class Reply
        {
            public bool Ok;
            public int StatusCode;
            public string Body = "";
            public string Error = "";
        }

        private readonly string _baseUrl;
        private readonly string _deviceToken;

        public TrackerBridge(string baseUrl) : this(baseUrl, null) { }

        public TrackerBridge(string baseUrl, string deviceToken)
        {
            _baseUrl = NormalizeBase(baseUrl);
            _deviceToken = deviceToken;
        }

        public static bool IsSafeServerUrl(string url)
        {
            if (string.IsNullOrEmpty(url)) return false;
            Uri u;
            if (!Uri.TryCreate(url, UriKind.Absolute, out u)) return false;
            return u.Scheme == Uri.UriSchemeHttps &&
                   !string.IsNullOrEmpty(u.Host) &&
                   string.IsNullOrEmpty(u.UserInfo);
        }

        public Reply GeneratePair()
        {
            return PostJson("/api/v2/pair/generate", "{ \"deviceType\": \"laptop\" }");
        }

        public Reply VerifyPair(string pairCode)
        {
            return PostJson("/api/v2/pair/verify",
                "{ \"pairCode\": " + Q(pairCode) + ", \"deviceType\": \"laptop\" }");
        }

        public Reply PairInfo(string deviceId)
        {
            return GetJson("/api/v2/pair-info?deviceId=" + UrlEncode(deviceId));
        }

        public Reply Heartbeat(string deviceId, double? lat, double? lng, string source)
        {
            string loc = (lat.HasValue && lng.HasValue)
                ? "{ \"lat\": " + F(lat.Value) + ", \"lng\": " + F(lng.Value) + ", \"source\": " + Q(source) + " }"
                : "null";
            return PostJson("/api/v2/heartbeat",
                "{ \"deviceId\": " + Q(deviceId) + ", \"location\": " + loc + " }");
        }

        public Reply LostMode(string deviceId, bool active)
        {
            return PostJson("/api/v2/lost-mode",
                "{ \"deviceId\": " + Q(deviceId) + ", \"active\": " + (active ? "true" : "false") + " }");
        }

        public static string ProtectDeviceToken(string token)
        {
            if (string.IsNullOrEmpty(token)) throw new ArgumentException("Tracker token is empty.", "token");
            byte[] clear = Encoding.UTF8.GetBytes(token);
            byte[] protectedBytes = ProtectedData.Protect(clear, null, DataProtectionScope.CurrentUser);
            return Convert.ToBase64String(protectedBytes);
        }

        public static string UnprotectDeviceToken(string protectedToken)
        {
            if (string.IsNullOrEmpty(protectedToken)) return "";
            byte[] protectedBytes = Convert.FromBase64String(protectedToken);
            byte[] clear = ProtectedData.Unprotect(protectedBytes, null, DataProtectionScope.CurrentUser);
            return Encoding.UTF8.GetString(clear);
        }

        public static string ReadJsonString(string json, string name)
        {
            if (string.IsNullOrEmpty(json) || string.IsNullOrEmpty(name)) return "";
            Match match = Regex.Match(json, "\"" + Regex.Escape(name) +
                "\"\\s*:\\s*\"((?:\\\\.|[^\"\\\\])*)\"");
            if (!match.Success) return "";
            return match.Groups[1].Value.Replace("\\\"", "\"").Replace("\\\\", "\\");
        }

        public static string RedactDeviceToken(string body)
        {
            if (string.IsNullOrEmpty(body)) return "";
            return Regex.Replace(body, "(\"deviceToken\"\\s*:\\s*\")[^\"]*(\")",
                "$1[stored securely]$2", RegexOptions.IgnoreCase);
        }

        private Reply GetJson(string relative)
        {
            var reply = new Reply();
            try
            {
                HttpWebRequest req = (HttpWebRequest)WebRequest.Create(_baseUrl + relative);
                req.Method = "GET";
                req.AllowAutoRedirect = false;
                req.Accept = "application/json";
                req.Timeout = 10000;
                SetAuthorization(req);
                using (HttpWebResponse res = (HttpWebResponse)req.GetResponse())
                using (StreamReader rd = new StreamReader(res.GetResponseStream()))
                {
                    reply.StatusCode = (int)res.StatusCode;
                    reply.Body = rd.ReadToEnd();
                    reply.Ok = reply.StatusCode >= 200 && reply.StatusCode < 300 &&
                               IsSuccessJson(reply.Body);
                }
            }
            catch (WebException wx)
            {
                reply.Error = wx.Message;
                if (wx.Response != null)
                {
                    try
                    {
                        HttpWebResponse er = (HttpWebResponse)wx.Response;
                        reply.StatusCode = (int)er.StatusCode;
                        using (StreamReader rd = new StreamReader(er.GetResponseStream()))
                            reply.Body = rd.ReadToEnd();
                    }
                    catch { }
                }
            }
            catch (Exception ex) { reply.Error = ex.Message; }
            return reply;
        }

        private Reply PostJson(string relative, string body)
        {
            var reply = new Reply();
            try
            {
                byte[] payload = Encoding.UTF8.GetBytes(body ?? "{}");
                HttpWebRequest req = (HttpWebRequest)WebRequest.Create(_baseUrl + relative);
                req.Method = "POST";
                req.AllowAutoRedirect = false;
                req.ContentType = "application/json";
                req.Accept = "application/json";
                req.Timeout = 10000;
                SetAuthorization(req);
                req.ContentLength = payload.Length;
                using (Stream s = req.GetRequestStream()) s.Write(payload, 0, payload.Length);
                using (HttpWebResponse res = (HttpWebResponse)req.GetResponse())
                using (StreamReader rd = new StreamReader(res.GetResponseStream()))
                {
                    reply.StatusCode = (int)res.StatusCode;
                    reply.Body = rd.ReadToEnd();
                    reply.Ok = reply.StatusCode >= 200 && reply.StatusCode < 300 &&
                               IsSuccessJson(reply.Body);
                }
            }
            catch (WebException wx)
            {
                reply.Error = wx.Message;
                if (wx.Response != null)
                {
                    try
                    {
                        HttpWebResponse er = (HttpWebResponse)wx.Response;
                        reply.StatusCode = (int)er.StatusCode;
                        using (StreamReader rd = new StreamReader(er.GetResponseStream()))
                            reply.Body = rd.ReadToEnd();
                    }
                    catch { }
                }
            }
            catch (Exception ex) { reply.Error = ex.Message; }
            return reply;
        }

        static bool IsSuccessJson(string body)
        {
            if (string.IsNullOrEmpty(body)) return false;
            return body.IndexOf("\"success\":true", StringComparison.OrdinalIgnoreCase) >= 0;
        }

        void SetAuthorization(HttpWebRequest req)
        {
            if (!string.IsNullOrEmpty(_deviceToken))
                req.Headers[HttpRequestHeader.Authorization] = "Bearer " + _deviceToken;
        }

        static string NormalizeBase(string url)
        {
            if (string.IsNullOrEmpty(url)) return "";
            string b = url.Trim();
            while (b.EndsWith("/", StringComparison.Ordinal)) b = b.Substring(0, b.Length - 1);
            return b;
        }

        static string UrlEncode(string s) { return Uri.EscapeDataString(s ?? ""); }

        static string Q(string s)
        {
            return "\"" + (s ?? "").Replace("\\", "\\\\").Replace("\"", "\\\"") + "\"";
        }

        static string F(double d)
        {
            return d.ToString("0.######", CultureInfo.InvariantCulture);
        }
    }
}
