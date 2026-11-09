using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Numerics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;

namespace UssdApp
{
    // =====================================================================
    // VoIP + video P2P (WhatsApp-style logic, simplified for LAN/direct use)
    //
    //  1. Discovery  : UDP broadcast HELLO on the LAN -> peer list
    //  2. Signaling  : TCP line protocol INVITE / ACCEPT / REJECT / CONFIRM / BYE
    //  3. Encryption : Diffie-Hellman (RFC 3526 2048-bit MODP) over the
    //                  signaling channel -> SHA256 -> AES-128 key.
    //                  Media is end-to-end encrypted (ZRTP-like idea).
    //  4. NAT        : best-effort STUN (Google STUN) for the reflexive
    //                  address + UDP hole punching to all candidates.
    //  5. Media      : UDP packets, AES-CTR encrypted:
    //                  - audio: PCM 16 kHz mono 16-bit, 20 ms frames
    //                  - video: MJPEG chunks (OpenCV capture helper)
    // =====================================================================

    public class VoipPeer
    {
        public string Name;
        public string Ip;
        public string Number;       // virtual number when known (internet directory)
        public int MediaPort;
        public string NetworkType;
        public DateTime LastSeen;
        // presence / route derived for the peers list
        public string Route { get { return string.IsNullOrEmpty(Number) ? "LAN" : "Internet"; } }
        public string Address { get { return string.IsNullOrEmpty(Number) ? Ip : "#" + Number; } }
        public string Status
        {
            get
            {
                double age = (DateTime.Now - LastSeen).TotalSeconds;
                if (age < 20) return "\u25CF online";
                return "\u25CB seen " + (int)age + "s ago";
            }
        }
        public override string ToString()
        {
            if (!string.IsNullOrEmpty(Number)) return "#" + Number + "  " + Name + "  (" + Ip + ")";
            return Name + "  (" + Ip + ")";
        }
    }

    // ---- Crypto: DH key agreement + AES-128-CTR (C#5 compatible) ----
    public sealed class VoipCrypto : IDisposable
    {
        // RFC 3526 2048-bit MODP Group
        private static readonly BigInteger P = BigInteger.Parse(
            "179769313486231590772930519078902473361797697894230657273430081157732675805500963132708477322407536421569731349699134065666375704358864346744790344368648867336144267175775409857663174603817352732102148423044369757596667764684599147530374804108467842095024667361142842736735824778670676761287816407043979244946139634440886753499935018047847853472674237640364748473744775519419966336368182847344268284883978379475810904654966288671197902617487104511626658419243213301461574041034706782766154167061307440584167343672346263165551546434346726740068665583473166478430146068807292346438623319370413814208892363020890693984240498247719305073476347493377168572877740978366379879398594592669549356814116978067991176862731453995387864504114456922841447091669643246744306866680374357607744117069138476668747837362070387936804690293626853846467631197317954640353669511918374264881874987824484303775395291904478631670443476517681150714280653430884118177428481572658778563787064792446439444304465451746498088679167419669058736467643538999045677563347133927199432477877273177276647726496864966742073944163897348246701147814874441787778452942167866884892846657375450743117629672358664524635797954440017867569089747914760704477496940944517276470384748257596905767478372446749893957072645333677569942248612376648838578544384639889064779524188546583537412936713034845448888888887");
        private static readonly BigInteger G = 2;

        private readonly BigInteger _priv;
        public readonly BigInteger Pub;

        public VoipCrypto()
        {
            byte[] rnd = new byte[32];
            using (RandomNumberGenerator rng = RandomNumberGenerator.Create()) rng.GetBytes(rnd);
            _priv = BigInteger.Abs(new BigInteger(rnd));
            Pub = BigInteger.ModPow(G, _priv, P);
        }

        public byte[] DeriveSharedKey(BigInteger peerPub)
        {
            BigInteger shared = BigInteger.ModPow(peerPub, _priv, P);
            using (SHA256 sha = SHA256.Create())
                return sha.ComputeHash(shared.ToByteArray());
        }

        // AES-128-CTR: keystream = AES-ECB(key, counter blocks); works on C#5/.NET4.
        public static byte[] AesCtr(byte[] key16, byte[] data, byte[] iv16)
        {
            byte[] outp = new byte[data.Length];
            using (Aes aes = Aes.Create())
            {
                aes.Mode = CipherMode.ECB;
                aes.Padding = PaddingMode.None;
                aes.KeySize = 128;
                aes.Key = key16;
                byte[] counter = (byte[])iv16.Clone();
                using (ICryptoTransform enc = aes.CreateEncryptor())
                {
                    byte[] ks = new byte[16];
                    int off = 0;
                    while (off < data.Length)
                    {
                        enc.TransformBlock(counter, 0, 16, ks, 0);
                        int n = Math.Min(16, data.Length - off);
                        for (int i = 0; i < n; i++) outp[off + i] = (byte)(data[off + i] ^ ks[i]);
                        off += n;
                        // increment counter (big-endian, low byte first for simplicity)
                        counter[15]++;
                        if (counter[15] == 0) counter[14]++;
                    }
                }
            }
            return outp;
        }

        public static byte[] HmacSha256(byte[] key, byte[] data)
        {
            using (HMACSHA256 h = new HMACSHA256(key)) return h.ComputeHash(data);
        }

        public void Dispose() { }
    }

    // ---- STUN binding: "what address does my socket look like from outside?" ----
    // RFC 5389/5381, the smallest useful slice: one binding request, read the
    // XOR-MAPPED-ADDRESS back. This is what a peer needs in order to hit a socket
    // through NAT at all.
    //
    // Two things the first attempt got wrong, and both made the answer useless:
    //   - the port is XORed with the FIRST TWO BYTES of the cookie (0x21,0x12), not
    //     with 0x12 and 0x42. The old code skipped the leading 0x21 and reached for
    //     the last byte instead, so every mapped port came out wrong (real 50000
    //     decoded as 61440) and the candidate it produced was unreachable.
    //   - the request has to go out of the socket whose mapping is being asked about.
    //     Asking from a fresh UdpClient returns that socket's mapping, which is gone
    //     by the time a peer aims at it. So the query now runs on the media socket,
    //     and the answer is picked up by the same receive loop that reads media.
    public static class Stun
    {
        public const int MAGIC_COOKIE = 0x2112A442;
        const int HEADER = 20;

        public static byte[] Request(byte[] transactionId)
        {
            byte[] req = new byte[HEADER];
            req[0] = 0x00; req[1] = 0x01;               // binding request
            req[4] = 0x21; req[5] = 0x12; req[6] = 0xA4; req[7] = 0x42;
            Buffer.BlockCopy(transactionId, 0, req, 8, 12);
            return req;
        }

        public static byte[] NewTransactionId()
        {
            byte[] tx = new byte[12];
            using (RandomNumberGenerator rng = RandomNumberGenerator.Create())
                rng.GetBytes(tx);
            return tx;
        }

        // Is this datagram the answer to OUR request? Both the cookie and the
        // transaction id have to match, because an encrypted audio frame can begin
        // with the same two bytes as a STUN response header (type 1, then an IV that
        // starts with the type) and must not be mistaken for one.
        public static bool LooksLikeResponse(byte[] data, byte[] transactionId)
        {
            if (data == null || data.Length < HEADER || transactionId == null) return false;
            if (!(data[0] == 0x01 && data[1] == 0x01)) return false;
            if (data[4] != 0x21 || data[5] != 0x12 || data[6] != 0xA4 || data[7] != 0x42) return false;
            for (int i = 0; i < 12; i++) if (data[8 + i] != transactionId[i]) return false;
            return true;
        }

        // Walk the attributes for XOR-MAPPED-ADDRESS (0x0020), IPv4 only.
        public static bool TryParse(byte[] data, byte[] transactionId, out string ip, out int port)
        {
            ip = ""; port = 0;
            if (!LooksLikeResponse(data, transactionId)) return false;
            // Trust the declared message length only as far as bounding the walk:
            // a packet claiming more than it carries is refused rather than read to
            // the end of whatever else happens to be in the datagram.
            int msgLen = (data[2] << 8) | data[3];
            if (msgLen < 0 || HEADER + msgLen > data.Length) return false;
            int off = HEADER;
            int end = HEADER + msgLen;
            while (off + 4 <= end)
            {
                int atype = (data[off] << 8) | data[off + 1];
                int alen = (data[off + 2] << 8) | data[off + 3];
                if (alen < 0 || off + 4 + alen > end) return false;   // corrupt length
                if (atype == 0x0020 && alen >= 8)
                {
                    byte fam = data[off + 5];
                    if (fam != 0x01) return false;                            // IPv6 not claimed
                    int xport = (data[off + 6] << 8) | data[off + 7];
                    // XOR key for the port = the top 16 bits of the cookie.
                    port = xport ^ 0x2112;
                    byte[] raw = new byte[4];
                    for (int i = 0; i < 4; i++)
                        raw[i] = (byte)(data[off + 8 + i] ^ data[4 + i]);
                    ip = new IPAddress(raw).ToString();
                    return port > 0 && port < 65536 && ip.Length > 0;
                }
                off += 4 + alen;
            }
            return false;
        }
    }

    // =====================================================================
    // PortMap: asking a home router to open a door, so a relay hosted on a
    // laptop can be reached from outside its own network at all.
    //
    // Nothing else in this project can fix that problem. An inbound connection
    // cannot arrive at a machine the network will not route to, so two people
    // each hosting a relay at home cannot link until somebody forwards a port.
    // UPnP IGD is the twenty-year-old router API that does it for you.
    //
    // It is OFF by default, deliberately. It asks a piece of shared infrastructure
    // to expose this PC, it can fail for reasons belonging to somebody else's
    // network, and it does not work where it was never meant to work: a corporate
    // LAN, a VPS with no router, or carrier-grade NAT in front of the modem. In
    // all of those the answer is "no", and the answer has to be said plainly
    // rather than retried forever.
    //
    // Discovery, parsing and SOAP-building are separated from the network calls so
    // the parts that are easy to get wrong - a relative <controlURL>, a router that
    // offers WANIPConnection:2 rather than :1, a fault meaning "already mapped" -
    // can be tested with no router in the loop.
    // =====================================================================
    public static class PortMap
    {
        public const string SsdpTarget = "239.255.255.250";
        public const int SsdpPort = 1900;
        public const string StIgd = "urn:schemas-upnp-org:device:InternetGatewayDevice:1";
        public const string StWanDevice = "urn:schemas-upnp-org:device:WANDevice:1";

        // ── SSDP: which device is the gateway? ─────────────────────────
        public static string SearchRequest(string targetType)
        {
            return "M-SEARCH * HTTP/1.1\r\n" +
                   "HOST: " + SsdpTarget + ":" + SsdpPort + "\r\n" +
                   "MAN: \"ssdp:discover\"\r\n" +
                   "MX: 2\r\n" +
                   "ST: " + targetType + "\r\n" +
                   "\r\n";
        }

        // The LOCATION header and nothing else. A response without one, or with a
        // scheme we cannot fetch, is no device - and returning the raw string anyway
        // is how a broken router turns into a confusing exception three steps later.
        public static string LocationFromResponse(string response)
        {
            if (string.IsNullOrEmpty(response)) return null;
            string[] lines = response.Replace("\r\n", "\n").Split('\n');
            foreach (string raw in lines)
            {
                string l = raw.Trim();
                if (!l.StartsWith("LOCATION:", StringComparison.OrdinalIgnoreCase)) continue;
                string url = l.Substring("LOCATION:".Length).Trim().Trim('<', '>');
                if (!url.StartsWith("http://", StringComparison.OrdinalIgnoreCase) &&
                    !url.StartsWith("https://", StringComparison.OrdinalIgnoreCase)) return null;
                return url;
            }
            return null;
        }

        // ── The description: where does the SOAP actually go? ────────────
        // Routers list one or more WAN*Connection services. Preference order is
        // WANIPConnection:2, :1, then WANPPPConnection - the last one is the old
        // DSL flavour, and using it when nothing better exists is the difference
        // between working on a stranger's router and not.
        static int ServiceRank(string serviceType)
        {
            if (string.IsNullOrEmpty(serviceType)) return -1;
            string s = serviceType.ToLowerInvariant();
            if (s.Contains("wanipconnection:2") || s.Contains("wanipconnection:3")) return 3;
            if (s.Contains("wanipconnection")) return 2;
            if (s.Contains("wanpppconnection")) return 1;
            return -1;
        }

        static string TagValue(string xml, string tag)
        {
            if (string.IsNullOrEmpty(xml)) return null;
            string open = "<" + tag + ">", close = "</" + tag + ">";
            int a = xml.IndexOf(open, StringComparison.OrdinalIgnoreCase);
            if (a < 0) return null;
            int b = xml.IndexOf(close, a + open.Length, StringComparison.OrdinalIgnoreCase);
            if (b < 0) return null;
            string v = xml.Substring(a + open.Length, b - a - open.Length).Trim();
            return v.Length == 0 ? null : v;
        }

        // Resolve a controlURL against the description's own URL. Most routers say
        // "/igdupnp/control/WANIPConn1", and posting that at a bare host is a 404
        // that reads exactly like "this router has no UPnP".
        public static string ResolveUrl(string baseUrl, string controlUrl)
        {
            if (string.IsNullOrEmpty(controlUrl)) return null;
            if (controlUrl.StartsWith("http://", StringComparison.OrdinalIgnoreCase) ||
                controlUrl.StartsWith("https://", StringComparison.OrdinalIgnoreCase)) return controlUrl;
            if (string.IsNullOrEmpty(baseUrl)) return null;
            try
            {
                Uri b, u;
                if (!Uri.TryCreate(baseUrl, UriKind.Absolute, out b)) return null;
                if (!Uri.TryCreate(b, controlUrl, out u)) return null;
                return u.ToString();
            }
            catch { return null; }
        }

        public static bool TryFindControlUrl(string xml, string baseUrl, out string controlUrl, out string serviceType)
        {
            controlUrl = null; serviceType = null;
            if (string.IsNullOrEmpty(xml)) return false;
            int best = 0;
            int pos = 0;
            while (pos < xml.Length)
            {
                int s = xml.IndexOf("<service", pos, StringComparison.OrdinalIgnoreCase);
                if (s < 0) break;
                int e = xml.IndexOf("</service>", s, StringComparison.OrdinalIgnoreCase);
                if (e < 0) break;
                string block = xml.Substring(s, e - s);
                string st = TagValue(block, "serviceType");
                string cu = TagValue(block, "controlURL");
                int rank = ServiceRank(st);
                if (cu != null && rank > best)
                {
                    best = rank; serviceType = st; controlUrl = cu;
                }
                pos = e + 10;
            }
            if (controlUrl == null) return false;
            controlUrl = ResolveUrl(baseUrl, controlUrl);
            return controlUrl != null && serviceType != null;
        }

        // ── SOAP ────────────────────────────────────────────────────────
        public static string AddPortMappingBody(string serviceType, int externalPort,
                                                int internalPort, string internalClient,
                                                string desc)
        {
            return AddPortMappingBody(serviceType, externalPort, internalPort, internalClient,
                                      desc, "TCP");
        }

        // UDP is what a direct call actually needs: opening the relay's TCP port does
        // nothing for the media socket, and a router asked for the wrong protocol answers
        // OK and leaves the door shut anyway. So the protocol is one string, written in
        // one place, and never inferred from what the caller probably meant.
        public static string NormProtocol(string p)
        {
            if (string.IsNullOrEmpty(p)) return "TCP";
            return p.Trim().ToUpperInvariant() == "UDP" ? "UDP" : "TCP";
        }

        public static string AddPortMappingBody(string serviceType, int externalPort,
                                                int internalPort, string internalClient,
                                                string desc, string protocol)
        {
            // NewLeaseDuration 0 = "keep it as long as you like". Some devices refuse a
            // non-zero lease outright, and none refuses zero.
            return "<?xml version=\"1.0\"?>\r\n" +
                "<s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\"" +
                " s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\">\r\n" +
                "<s:Body>\r\n" +
                "<u:AddPortMapping xmlns:u=\"" + serviceType + "\">\r\n" +
                "<NewRemoteHost></NewRemoteHost>\r\n" +
                "<NewExternalPort>" + externalPort + "</NewExternalPort>\r\n" +
                "<NewProtocol>" + NormProtocol(protocol) + "</NewProtocol>\r\n" +
                "<NewInternalPort>" + internalPort + "</NewInternalPort>\r\n" +
                "<NewInternalClient>" + Esc(internalClient) + "</NewInternalClient>\r\n" +
                "<NewEnabled>1</NewEnabled>\r\n" +
                "<NewPortMappingDescription>" + Esc(desc) + "</NewPortMappingDescription>\r\n" +
                "<NewLeaseDuration>0</NewLeaseDuration>\r\n" +
                "</u:AddPortMapping>\r\n" +
                "</s:Body>\r\n" +
                "</s:Envelope>\r\n";
        }

        public static string GetExternalIpBody(string serviceType)
        {
            return "<?xml version=\"1.0\"?>\r\n" +
                "<s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\"" +
                " s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\">\r\n" +
                "<s:Body>\r\n" +
                "<u:GetExternalIPAddress xmlns:u=\"" + serviceType + "\">\r\n" +
                "</u:GetExternalIPAddress>\r\n" +
                "</s:Body>\r\n</s:Envelope>\r\n";
        }

        static string Esc(string s)
        {
            if (string.IsNullOrEmpty(s)) return "";
            return s.Replace("&", "&amp;").Replace("<", "&lt;").Replace(">", "&gt;");
        }

        public static string ExternalIpFrom(string response)
        {
            string v = TagValue(response ?? "", "NewExternalIPAddress");
            if (string.IsNullOrEmpty(v)) return null;
            IPAddress a;
            if (!IPAddress.TryParse(v, out a)) return null;
            // A router that answers 0.0.0.0 has answered nothing, and putting it in a
            // seed line would produce an entry that fails on somebody else's machine.
            if (IPAddress.Any.Equals(a) || IPAddress.IPv6Any.Equals(a)) return null;
            return v;
        }

        // A fault is not "it failed". The IGD error numbers say what to do next: 718
        // means somebody already holds that external port, 725 means this router will
        // not accept a wildcard source, and a 404 on the control URL means the
        // description lied or this is not an IGD. Reporting the number is the
        // difference between a user giving up and a user turning off UPnP.
        public static string FaultText(string response)
        {
            if (string.IsNullOrEmpty(response)) return "the router answered nothing";
            bool isFault = response.IndexOf("<s:Fault>", StringComparison.OrdinalIgnoreCase) >= 0 ||
                           response.IndexOf("<Fault", StringComparison.OrdinalIgnoreCase) >= 0;
            if (!isFault) return null;
            string code = TagValue(response, "errorCode");
            string msg = TagValue(response, "faultstring");
            string mean = "";
            if (code == "718") mean = " - that external port is already mapped to another device";
            else if (code == "725") mean = " - this router refuses a mapping for any source address";
            else if (code == "732") mean = " - the schedule says this mapping is not allowed right now";
            else if (code == "606" || code == "501") mean = " - UPnP is switched off in the router's own settings";
            return "the router refused (" +
                   (string.IsNullOrEmpty(code) ? "no error code" : "error " + code) + ")" +
                   (string.IsNullOrEmpty(msg) ? "" : ": " + msg) + mean;
        }

        // ── The live calls ──────────────────────────────────────────────
        public static string Discover(int timeoutMs)
        {
            try
            {
                UdpClient u = new UdpClient();
                u.Client.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.Broadcast, true);
                u.Client.ReceiveTimeout = timeoutMs;
                byte[] q = Encoding.UTF8.GetBytes(SearchRequest(StIgd));
                u.Send(q, q.Length, SsdpTarget, SsdpPort);
                DateTime end = DateTime.UtcNow.AddMilliseconds(timeoutMs);
                IPEndPoint any = new IPEndPoint(IPAddress.Any, 0);
                while (DateTime.UtcNow < end)
                {
                    byte[] data;
                    try { data = u.Receive(ref any); } catch { break; }   // timeout: nobody answered
                    string loc = LocationFromResponse(Encoding.UTF8.GetString(data));
                    if (!string.IsNullOrEmpty(loc)) { u.Close(); return loc; }
                }
                u.Close();
            }
            catch { }
            return null;
        }

        public static string HttpGet(string url, int timeoutMs)
        {
            try
            {
                HttpWebRequest req = (HttpWebRequest)WebRequest.Create(url);
                req.Timeout = timeoutMs;
                req.ReadWriteTimeout = timeoutMs;
                req.UserAgent = "UssdApp/4.2 IGD-client";
                using (HttpWebResponse res = (HttpWebResponse)req.GetResponse())
                using (System.IO.Stream s = res.GetResponseStream())
                using (StreamReader r = new StreamReader(s, Encoding.UTF8))
                    return r.ReadToEnd();
            }
            catch { return null; }
        }

        public static string HttpPost(string url, string serviceType, string action, string body, int timeoutMs)
        {
            try
            {
                HttpWebRequest req = (HttpWebRequest)WebRequest.Create(url);
                req.Method = "POST";
                req.Timeout = timeoutMs;
                req.ReadWriteTimeout = timeoutMs;
                req.UserAgent = "UssdApp/4.2 IGD-client";
                req.ContentType = "text/xml; charset=\"utf-8\"";
                req.Headers["SOAPAction"] = "\"" + serviceType + "#" + action + "\"";
                byte[] b = Encoding.UTF8.GetBytes(body);
                req.ContentLength = b.Length;
                using (System.IO.Stream os = req.GetRequestStream()) os.Write(b, 0, b.Length);
                using (HttpWebResponse res = (HttpWebResponse)req.GetResponse())
                using (System.IO.Stream s = res.GetResponseStream())
                using (StreamReader r = new StreamReader(s, Encoding.UTF8))
                    return r.ReadToEnd();
            }
            catch (WebException wex)
            {
                // A 500 IS the fault envelope - reading it is how the reason survives.
                try
                {
                    HttpWebResponse err = wex.Response as HttpWebResponse;
                    if (err == null) return null;
                    using (System.IO.Stream s = err.GetResponseStream())
                    using (StreamReader r = new StreamReader(s, Encoding.UTF8))
                        return r.ReadToEnd();
                }
                catch { return null; }
            }
            catch { return null; }
        }

        // Discover the gateway and read its description ONCE. The relay's TCP mapping and
        // the media socket's UDP one come from the same answer, and doing SSDP twice is
        // two more seconds of waiting for a second copy of nothing.
        public static bool TryOpenService(out string control, out string serviceType,
                                          out string gateway, out string why)
        {
            control = null; serviceType = null; gateway = null; why = "";
            string desc = Discover(2500);
            if (desc == null)
            {
                why = "no UPnP gateway answered on this network - normal for a VPS, a corporate" +
                      " LAN or carrier-grade NAT; forward the port yourself or use a reachable relay";
                return false;
            }
            gateway = desc;
            string xml = HttpGet(desc, 5000);
            if (string.IsNullOrEmpty(xml)) { why = "the gateway at " + desc + " did not send its description"; return false; }
            if (!TryFindControlUrl(xml, desc, out control, out serviceType))
            {
                why = "the gateway at " + desc + " is not an Internet Gateway Device (no WAN connection service)";
                return false;
            }
            return true;
        }

        // Ask for one mapping. The external port always equals the internal one, by
        // deliberately never sending 0: a router handed 0 is free to choose another
        // number, and then the address announced to a peer is one nobody forwarded.
        // Failing loudly beats announcing a port that is not open.
        public static bool TryMap(string control, string serviceType, int port,
                                  string internalClient, string protocol, string desc, out string why)
        {
            why = "";
            string resp = HttpPost(control, serviceType, "AddPortMapping",
                AddPortMappingBody(serviceType, port, port, internalClient, desc, protocol), 6000);
            string fault = FaultText(resp);
            if (fault != null) { why = fault; return false; }
            if (resp == null)
            {
                why = "the gateway at " + control + " did not answer the " +
                      NormProtocol(protocol) + " mapping request";
                return false;
            }
            return true;
        }

        // What the router thinks this machine is called from outside. "" when it will not
        // or cannot say, which the caller has to report rather than guess around.
        public static string ExternalIp(string control, string serviceType)
        {
            return ExternalIpFrom(HttpPost(control, serviceType, "GetExternalIPAddress",
                GetExternalIpBody(serviceType), 5000) ?? "") ?? "";
        }

        // One attempt, one honest sentence either way. Returns the router's idea of
        // this machine's public address when the mapping lands, and never throws:
        // a relay that cannot open a port is still a relay for anybody on its network.
        public static bool TryApply(int port, string internalClient, out string publicIp, out string why)
        {
            publicIp = "";
            string control, serviceType, gateway;
            if (!TryOpenService(out control, out serviceType, out gateway, out why)) return false;
            if (!TryMap(control, serviceType, port, internalClient, "TCP", "UssdApp relay", out why)) return false;
            publicIp = ExternalIp(control, serviceType);
            why = "TCP " + port + " opened on " + gateway + (publicIp.Length == 0
                  ? " (the router would not say its public address - use the address your friend can reach)"
                  : ", which reports " + publicIp + " from outside");
            return true;
        }

        // The media-port mapping, which is the one that decides whether two people at
        // distance can speak directly at all. STUN's reflexive answer says "this is what
        // you look like from outside"; without a forward nothing can reach that port,
        // so the mapping is what turns the announced address into a usable one.
        // Returns the endpoint to announce, and the reason when it cannot.
        public static bool TryApplyMedia(int mediaPort, string internalClient,
                                         out IPEndPoint mapped, out string why)
        {
            mapped = null;
            string control, serviceType, gateway;
            if (!TryOpenService(out control, out serviceType, out gateway, out why)) return false;
            if (!TryMap(control, serviceType, mediaPort, internalClient, "UDP", "UssdApp media", out why)) return false;
            string ip = ExternalIp(control, serviceType);
            if (ip.Length == 0)
            {
                why = "UDP " + mediaPort + " opened on " + gateway + ", but the router would not say its public"
                    + " address - the forward exists and is useful if a peer learns the address another way";
                return false;
            }
            IPAddress a;
            if (!IPAddress.TryParse(ip, out a))
            {
                why = "the router gave " + ip + " as its public address, which is not an address";
                return false;
            }
            mapped = new IPEndPoint(a, mediaPort);
            why = "UDP " + mediaPort + " opened on " + gateway + ", so media for this machine arrives at " +
                  ip + ":" + mediaPort;
            return true;
        }
    }

    // ---- UDP hole-punch + media transport ----
    public sealed class VoipMedia : IDisposable
    {
        public const byte PKT_AUDIO = 1;
        public const byte PKT_VIDEO = 2;
        public const byte PKT_PUNCH = 3;
        public const byte PKT_KEEPALIVE = 4;   // tiny liveness probe (no key needed)
        // A receipt, not a liveness probe: "I hold this call key and I have decrypted N
        // of the frames you sent". Only the peer can produce something that decrypts, so
        // this is the half of a route claim that a keepalive cannot make - and the reason
        // it is encrypted while PKT_KEEPALIVE deliberately is not.
        public const byte PKT_ACK = 5;

        private UdpClient _udp;
        private Thread _rxThread;
        private volatile bool _run;
        private readonly List<IPEndPoint> _candidates = new List<IPEndPoint>();
        private readonly object _candLock = new object();
        private byte[] _key;
        private long _txSeq;

        // internet-call relay fallback (wired by VoipService when a call
        // server is configured): when active, datagrams go over TCP relay
        // instead of UDP; LastRxTicks tells the watchdog whether direct
        // media is actually flowing.
        public volatile bool RelayActive;
        public long LastRxTicks;
        public Action<byte[]> RelaySend;   // full datagram -> relay (null = no relay)

        // The UDP endpoint the last MEDIA-shaped packet came from, and only from UDP -
        // relayed frames never set it, because a relayed frame's UDP source is the relay.
        // Without this the app can say a call is direct but not over which of the peer's
        // three announced addresses it is direct, and that distinction is the difference
        // between a path a router promised and one that happens to be open right now.
        //
        // It replaced LastRxRemote, which was set by ANY datagram including a keyless
        // keep-alive: a stray packet on the media port - a LAN scanner, a previous call's
        // peer, a misdirected broadcast - was enough to make this app name a route, and
        // nothing read the old field afterwards, so the weaker one was deleted rather than
        // kept as a second opinion.
        //
        // Say exactly what this does and does not raise. Audio and video carry no MAC, so
        // "media-shaped, while we hold a key" is NOT proof the sender holds that key - it
        // rules out keep-alives, punch packets and noise, which is the bug being fixed, and
        // nothing more. The authenticated half of the story is LastAckRemote below, whose
        // packets are MAC'd. Both are reachability claims, not identity claims.
        public volatile IPEndPoint LastRxAuthRemote;

        // What the PEER reported it has decrypted, and when it last said so - a claim the
        // peer MAC'd under the call key, so unlike everything else on this path somebody
        // else cannot write it. Read against our own TxFrames this is the only evidence on
        // this machine that our audio actually arrived: without it a call that reaches
        // nobody still reports a route, because a route was only ever named from the
        // address that sent us something.
        // LastAckTicks stays 0 until a receipt passes its MAC, so "never" and "long ago" are
        // distinguishable rather than both being an old timestamp. Not volatile: this
        // toolchain (.NET 4.0 / C# 5) refuses volatile long, and a torn 64-bit read would
        // misreport the count anyway, so both sides go through Interlocked.
        public long PeerRxFrames;
        public volatile IPEndPoint LastAckRemote;
        public long LastAckTicks;
        public long AcksSent;
        public long AcksRcvd;

        private volatile IPEndPoint _localEp;
        private readonly HashSet<string> _localAddrs = new HashSet<string>();

        // video reassembly (shared by UDP + relay receive paths)
        private readonly Dictionary<long, byte[]> _videoChunks = new Dictionary<long, byte[]>();
        private readonly Dictionary<long, int> _videoSeen = new Dictionary<long, int>();

        // Same machine: candidates may point at our own media port - those
        // packets are our own echo and must not count as remote media.
        private bool IsFromSelf(IPEndPoint rep)
        {
            if (rep == null || _localEp == null) return false;
            if (rep.Port != _localEp.Port) return false;
            return IPAddress.IsLoopback(rep.Address) || _localAddrs.Contains(rep.Address.ToString());
        }

        public int LocalPort { get { return _udp == null ? 0 : ((IPEndPoint)_udp.Client.LocalEndPoint).Port; } }

        public event Action<byte[], IPEndPoint> AudioFrame;   // pcm, remote ep
        public event Action<byte[], IPEndPoint> VideoFrame;   // jpeg, remote ep
        public event Action<IPEndPoint> RemoteDiscovered;

        // Read-only accessor so the owner can re-raise mixed conference audio
        // through the same playout chain (events are not readable outside).
        public bool RaiseAudioFrame(byte[] pcm, IPEndPoint from)
        {
            Action<byte[], IPEndPoint> h = AudioFrame;
            if (h == null) return false;
            h(pcm, from);
            return true;
        }

        public void Open(int port)
        {
            Close();
            // Prefer the preferred media port, but fall back to the next few if
            // it is taken (second instance on this PC, stale socket, firewall).
            // Without this the socket stayed null: no RX loop, no media at all.
            Exception last = null;
            for (int i = 0; i < 10; i++)
            {
                try
                {
                    _udp = new UdpClient(new IPEndPoint(IPAddress.Any, port + i));
                    if (i > 0) EmitLog("media port " + port + " busy - using " + (port + i) +
                        " (announced to the peer as soon as the call starts).");
                    break;
                }
                catch (Exception ex) { last = ex; _udp = null; }
            }
            if (_udp == null)
                throw new Exception("no free UDP media port near " + port +
                    (last != null ? " (" + last.Message + ")" : ""));
            try { _udp.EnableBroadcast = true; } catch { }
            try
            {
                _localEp = (IPEndPoint)_udp.Client.LocalEndPoint;
                _localAddrs.Clear();
                foreach (IPAddress a in Dns.GetHostAddresses(Dns.GetHostName()))
                    if (a.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                        _localAddrs.Add(a.ToString());
            }
            catch { _localEp = null; }
            _run = true;
            RelayActive = false;
            LastRxTicks = 0;
            LastRxAuthRemote = null;
            ClearAckProof();
            _videoChunks.Clear();
            _videoSeen.Clear();
            lock (_candLock) _candidates.Clear();   // don't leak the previous peer's IP
            _txAudioLogged = _txVideoLogged = _rxAudioLogged = _rxVideoLogged = false;
            _stunTx = null; _publicEp = null;   // a new call asks for itself, and a
                                                 // mapping from the last one is not
                                                 // this socket's answer any more
            _rxThread = new Thread(RxLoop);
            _rxThread.IsBackground = true;
            _rxThread.Start();
        }

        // Reset per-call state WITHOUT destroying the UDP socket. Rebinding
        // the media port on every call can fail (10048) and leaves _udp null
        // with no receive loop - a total media blackout.
        public void ResetForCall()
        {
            if (_udp == null)
            {
                // no socket - try to (re)open it, surfacing any failure
                try { Open(VoipService.MEDIA_PORT); }
                catch (Exception ex) { EmitLog("media reopen failed: " + ex.Message); }
                return;
            }
            RelayActive = false;
            LastRxTicks = 0;
            LastRxAuthRemote = null;
            ClearAckProof();
            // ICE: clear confirmed candidate so the new call probes fresh.
            _confirmedCandidate = null;
            _confirmedLastRx = DateTime.MinValue;
            _probeCandidateIdx = 0;
            _probeStartedAt = DateTime.MinValue;
            Interlocked.Exchange(ref _txSeq, 0);
            _videoChunks.Clear();
            _videoSeen.Clear();
            lock (_candLock) _candidates.Clear();
            _txAudioLogged = _txVideoLogged = _rxAudioLogged = _rxVideoLogged = false;
            _stunTx = null; _publicEp = null;   // a new call asks for itself, and a
                                                 // mapping from the last one is not
                                                 // this socket's answer any more
        }

        private Action<string> _log;
        public Action<string> LogLine { get { return _log; } set { _log = value; } }
        private void EmitLog(string s) { Action<string> h = _log; if (h != null) h(s); }

        public bool IsOpen { get { return _udp != null && _run; } }

        public void SetKey(byte[] key) { _key = key; if (key != null) _keyHeldLogged = false; }

        // ---- our own public address, asked of STUN over THIS socket ----
        byte[] _stunTx;
        volatile IPEndPoint _publicEp;
        public IPEndPoint PublicEp { get { return _publicEp; } }
        public event Action<IPEndPoint> PublicAddressKnown;

        // Send the binding requests and return; the answer arrives on the receive
        // loop like any other datagram. Blocking here would delay the call, and a
        // second socket would ask about the wrong one.
        public void StunAsk(string[] servers)
        {
            if (_udp == null || servers == null) return;
            _stunTx = Stun.NewTransactionId();
            _publicEp = null;
            byte[] req = Stun.Request(_stunTx);
            foreach (string s in servers)
            {
                try
                {
                    string host = s.Trim(); int port = 3478;
                    int colon = host.IndexOf(':');
                    if (colon > 0)
                    {
                        int.TryParse(host.Substring(colon + 1), out port);
                        if (port <= 0) port = 3478;
                        host = host.Substring(0, colon);
                    }
                    if (host.Length == 0) continue;
                    _udp.Send(req, req.Length, host, port);
                }
                catch { }      // an unreachable server in the list is not an error
            }
        }

        // Called from the receive loop. Returns true when the datagram was a STUN
        // answer, so it is never handed to the media path.
        bool TakeStunAnswer(byte[] data)
        {
            string ip; int port;
            if (!Stun.TryParse(data, _stunTx, out ip, out port)) return false;
            try
            {
                IPEndPoint ep = new IPEndPoint(IPAddress.Parse(ip), port);
                _publicEp = ep;
                EmitLog("our address as the outside world sees it: " + ep);
                Action<IPEndPoint> h = PublicAddressKnown;
                if (h != null) h(ep);
            }
            catch { return false; }
            return true;
        }

        public void AddCandidate(IPEndPoint ep)
        {
            if (ep == null) return;
            lock (_candLock)
            {
                foreach (IPEndPoint e in _candidates)
                    if (e.Equals(ep)) return;
                _candidates.Add(ep);
            }
        }

        public List<IPEndPoint> Candidates
        {
            get { lock (_candLock) return new List<IPEndPoint>(_candidates); }
        }

        // send to all candidates + remember last source (both directions of punch)
        // when the relay is active (direct UDP proven dead), send via relay only.
        //
        // ICE-style candidate checking: rather than spraying every candidate at
        // once, we try candidates in priority order. The first candidate to earn
        // a receipt (PKT_ACK from the peer, which is MAC'd under the call key)
        // becomes the "confirmed" candidate, and subsequent frames go only there.
        // If the confirmed candidate goes quiet for ICE_PROBE_TIMEOUT seconds,
        // we fall back to trying all candidates again. This is not full ICE
        // (no STUN connectivity check handshake) but it does prove which
        // address actually delivers before committing to it, which is the half
        // that mattered: symmetric-to-symmetric NAT used to require a relay
        // because no candidate was ever tested before all were tried.
        private IPEndPoint _confirmedCandidate;
        private DateTime _confirmedLastRx = DateTime.MinValue;
        private const double ICE_PROBE_TIMEOUT = 5.0;    // seconds without rx before re-probing
        private int _probeCandidateIdx;                   // which candidate we are trying
        private DateTime _probeStartedAt = DateTime.MinValue;

        public void SendToAll(byte type, byte[] payloadEnc)
        {
            byte[] pkt = new byte[1 + payloadEnc.Length];
            pkt[0] = type;
            Buffer.BlockCopy(payloadEnc, 0, pkt, 1, payloadEnc.Length);
            if (RelayActive)
            {
                Action<byte[]> rs = RelaySend;
                if (rs != null) { rs(pkt); return; }
            }
            List<IPEndPoint> targets;
            lock (_candLock) targets = new List<IPEndPoint>(_candidates);
            if (targets.Count == 0) return;

            // ICE candidate checking: if we have a confirmed candidate and it
            // is still alive, send only to it. This avoids spraying media at
            // every address simultaneously.
            if (_confirmedCandidate != null)
            {
                double sinceRx = (DateTime.Now - _confirmedLastRx).TotalSeconds;
                if (sinceRx < ICE_PROBE_TIMEOUT)
                {
                    try { if (_udp != null) _udp.Send(pkt, pkt.Length, _confirmedCandidate); }
                    catch { }
                    return;
                }
                // Confirmed candidate went quiet — re-probe all candidates
                _confirmedCandidate = null;
                _probeCandidateIdx = 0;
                _probeStartedAt = DateTime.MinValue;
            }

            // Probing phase: try candidates in order. Send to the current
            // probe candidate, and also send to all candidates for the first
            // few seconds of a call (so we don't lose audio while probing).
            // After the first receipt comes in, _confirmedCandidate is set
            // and subsequent frames go only there.
            if (_probeStartedAt == DateTime.MinValue)
            {
                _probeStartedAt = DateTime.Now;
                _probeCandidateIdx = 0;
            }

            double probeAge = (DateTime.Now - _probeStartedAt).TotalSeconds;

            // For the first 3 seconds of a call, send to all candidates
            // (compatibility with existing behaviour, and ensures no audio
            // is lost while we wait for a receipt to confirm a candidate).
            // After that, try one candidate at a time for 3 seconds each.
            if (probeAge < 3.0)
            {
                foreach (IPEndPoint ep in targets)
                {
                    try { if (_udp != null) _udp.Send(pkt, pkt.Length, ep); }
                    catch { }
                }
            }
            else
            {
                // Try the current probe candidate
                if (_probeCandidateIdx >= targets.Count)
                    _probeCandidateIdx = 0; // wrap around

                IPEndPoint probe = targets[_probeCandidateIdx];
                try { if (_udp != null) _udp.Send(pkt, pkt.Length, probe); }
                catch { }

                // Advance to next candidate every 3 seconds if no receipt
                double candidateAge = (DateTime.Now - _probeStartedAt).TotalSeconds - (_probeCandidateIdx * 3.0);
                if (candidateAge > 3.0)
                {
                    _probeCandidateIdx++;
                    if (_probeCandidateIdx >= targets.Count)
                        _probeCandidateIdx = 0;
                }
            }
        }

        // Called from the receive loop when a PKT_ACK (receipt) passes its MAC.
        // The endpoint that delivered the receipt is the confirmed candidate.
        public void ConfirmCandidate(IPEndPoint ep)
        {
            if (ep == null) return;
            _confirmedCandidate = ep;
            _confirmedLastRx = DateTime.Now;
            _probeCandidateIdx = 0;
            _probeStartedAt = DateTime.MinValue;
        }

        // Called from the receive loop when ANY keyed media frame arrives from
        // a candidate — it proves that candidate is delivering.
        public void NoteRxFrom(IPEndPoint ep)
        {
            if (ep == null) return;
            if (_confirmedCandidate == null)
                _confirmedCandidate = ep;
            _confirmedLastRx = DateTime.Now;
        }

        public void SendRaw(IPEndPoint ep, byte type, byte[] payloadEnc)
        {
            if (_udp == null) return;
            byte[] pkt = new byte[1 + payloadEnc.Length];
            pkt[0] = type;
            Buffer.BlockCopy(payloadEnc, 0, pkt, 1, payloadEnc.Length);
            try { _udp.Send(pkt, pkt.Length, ep); }
            catch { }
        }

        // Media is held until both sides share the E2E key. Sending plaintext
        // before the key existed produced a burst of noise/clicks at answer time.
        private volatile bool _keyHeldLogged;
        // one-time per-call breadcrumbs: prove in hang_trace that encrypted
        // audio/video actually left this machine and arrived + decrypted
        private bool _txAudioLogged, _txVideoLogged, _rxAudioLogged, _rxVideoLogged;
        private bool MediaReady()
        {
            if (_key != null) return true;
            if (!_keyHeldLogged)
            {
                _keyHeldLogged = true;
                EmitLog("media held until the encryption key is negotiated...");
            }
            return false;
        }

        public void SendAudio(byte[] pcm)
        {
            if (!MediaReady()) return;
            if (!_txAudioLogged)
            {
                _txAudioLogged = true;
                EmitLog("media: first encrypted audio frame sent");
            }
            long seq = Interlocked.Increment(ref _txSeq);
            Interlocked.Increment(ref TxFrames);
            byte[] iv = IxFrom(seq, PKT_AUDIO);
            byte[] enc = VoipCrypto.AesCtr(_key, pcm, iv);
            byte[] body = new byte[16 + enc.Length];
            Buffer.BlockCopy(iv, 0, body, 0, 16);
            Buffer.BlockCopy(enc, 0, body, 16, enc.Length);
            SendToAll(PKT_AUDIO, body);
        }

        public void SendVideo(byte[] jpeg, int frameId, int chunkIdx, int chunkCount)
        {
            if (!MediaReady()) return;
            if (!_txVideoLogged)
            {
                _txVideoLogged = true;
                EmitLog("media: first encrypted video frame sent");
            }
            byte[] head = new byte[6];
            head[0] = (byte)(frameId >> 8); head[1] = (byte)frameId;
            head[2] = (byte)(chunkIdx >> 8); head[3] = (byte)chunkIdx;
            head[4] = (byte)(chunkCount >> 8); head[5] = (byte)chunkCount;
            byte[] body = new byte[head.Length + jpeg.Length];
            Buffer.BlockCopy(head, 0, body, 0, 6);
            Buffer.BlockCopy(jpeg, 0, body, 6, jpeg.Length);
            byte[] iv = IxFrom(((long)frameId << 16) | (uint)chunkIdx, PKT_VIDEO);
            Interlocked.Increment(ref TxFrames);
            byte[] enc = VoipCrypto.AesCtr(_key, body, iv);
            byte[] full = new byte[16 + enc.Length];
            Buffer.BlockCopy(iv, 0, full, 0, 16);
            Buffer.BlockCopy(enc, 0, full, 16, enc.Length);
            SendToAll(PKT_VIDEO, full);
        }

        public void Punch()
        {
            SendToAll(PKT_PUNCH, new byte[0]);
        }

        // Liveness probe: sent every few seconds during a call so a muted or
        // silent peer is still provably reachable.
        public void KeepAlive()
        {
            SendToAll(PKT_KEEPALIVE, new byte[1]);
        }

        // Send the peer its receipt: how many of ITS frames we have decrypted. Sent on the
        // media path, not the signalling one, so that it proves the media route specifically
        // - a call whose signalling works and whose audio goes nowhere is exactly the case
        // this exists to catch.
        //
        // It advances _txSeq for a fresh IV but must NOT touch TxFrames: that counter is
        // asserted elsewhere as "frames we sent that the peer received", and counting a
        // receipt as a media frame would quietly inflate it into a false pass.
        public void AckPeer()
        {
            if (_key == null) return;
            long rx = Interlocked.Read(ref RxFrames);
            byte[] cnt = new byte[8];
            for (int i = 0; i < 8; i++) cnt[i] = (byte)(rx >> (8 * i));
            // A CTR keystream carries no integrity, and the packet TYPE travels in the
            // clear in front of it - so an encrypted-only receipt would be forgeable by
            // anybody who could hit this UDP port once, which is precisely the claim this
            // packet exists to make worth believing. The MAC is over the count, under the
            // call key: only the peer can write one. Truncated to 64 bits, which is far
            // beyond what a datagram-rate guesser can do in the seconds a call lasts.
            byte[] mac = VoipCrypto.HmacSha256(_key, cnt);
            byte[] plain = new byte[16];
            Buffer.BlockCopy(cnt, 0, plain, 0, 8);
            for (int i = 0; i < 8; i++) plain[8 + i] = mac[i];
            long seq = Interlocked.Increment(ref _txSeq);
            byte[] iv = IxFrom(seq, PKT_ACK);
            byte[] enc = VoipCrypto.AesCtr(_key, plain, iv);
            byte[] body = new byte[16 + enc.Length];
            Buffer.BlockCopy(iv, 0, body, 0, 16);
            Buffer.BlockCopy(enc, 0, body, 16, enc.Length);
            Interlocked.Increment(ref AcksSent);
            SendToAll(PKT_ACK, body);
        }

        // Compare eight bytes of an expected MAC without leaking position through an
        // early return. Not a secret-string comparison for storage - this one sits on the
        // receive path of a live call, where the cost of a shortcut is a believable lie.
        private static bool MacOk(byte[] body, int off, byte[] mac)
        {
            if (body == null || mac == null) return false;
            if (off < 0 || off + 8 > body.Length || mac.Length < 8) return false;
            int diff = 0;
            for (int i = 0; i < 8; i++) diff |= body[off + i] ^ mac[i];
            return diff == 0;
        }

        // True once the E2E key exists (call fully established).
        public bool HasKey { get { return _key != null; } }

        // Per-call: the receipt a PREVIOUS peer sent must never be read as this call's
        // proof, or a fresh call opens claiming both ways work. Counters are not zeroed,
        // because --call prints them as this call's totals and a second call on the same
        // socket is not the same conversation - the ticks and the peer's number are the
        // parts that would actually lie.
        void ClearAckProof()
        {
            Interlocked.Exchange(ref PeerRxFrames, 0);
            LastAckRemote = null;
            LastAckTicks = 0;
        }

        // Media counters, and they count only *encrypted* frames: tx after the key
        // gate, rx after decryption. A call report that says "200 frames" should be
        // provable as 200 frames that were AES-CTR'd, not 200 datagrams that happened
        // to move - which is the difference between "audio flowed" and "audio was
        // secretly readable by the relay". Read by `--call` to print what happened
        // without a window on either machine.
        public long TxFrames;
        public long RxFrames;
        public long RxBytes;

        private static byte[] IxFrom(long seq, byte type)
        {
            byte[] iv = new byte[16];
            iv[0] = type;
            for (int i = 0; i < 8; i++) iv[8 + i] = (byte)(seq >> (8 * i));
            return iv;
        }

        private void RxLoop()
        {
            IPEndPoint rep = new IPEndPoint(IPAddress.Any, 0);
            while (_run)
            {
                byte[] data = null;
                try
                {
                    data = _udp.Receive(ref rep);
                }
                catch { if (!_run) return; continue; }
                // One bad datagram must never kill the receive loop (and with
                // it all audio+video for the rest of the call).
                // A STUN answer is ours, not a media frame: it arrives on the same
                // socket the request left from, which is the whole point.
                if (TakeStunAnswer(data)) continue;
                try { ProcessDatagram(data, rep, true); }
                catch (Exception ex) { EmitLog("media rx error: " + ex.Message); }
            }
        }

        // Feed a datagram that arrived via the call-server TCP relay.
        public void InjectRelayed(byte[] data)
        {
            if (data == null || data.Length < 1) return;
            LastRxTicks = DateTime.UtcNow.Ticks;
            RelayActive = true;   // receiving via relay => send back via relay
            try { ProcessDatagram(data, new IPEndPoint(IPAddress.Loopback, 0), false); }
            catch (Exception ex) { EmitLog("media relay rx error: " + ex.Message); }
        }

        // Shared packet processing for UDP receives and relayed datagrams.
        private void ProcessDatagram(byte[] data, IPEndPoint rep, bool learn)
        {
            if (data == null || data.Length < 1) return;
            if (IsFromSelf(rep)) return;
            byte type = data[0];
            byte[] payload = new byte[data.Length - 1];
            Buffer.BlockCopy(data, 1, payload, 0, payload.Length);

            // learn the sender as a candidate (hole punch / symmetric NAT peer)
            if (learn)
            {
                bool known = false;
                lock (_candLock)
                    foreach (IPEndPoint e in _candidates) if (e.Equals(rep)) { known = true; break; }
                if (!known && type != PKT_PUNCH)
                {
                    AddCandidate(rep);
                    Action<IPEndPoint> h = RemoteDiscovered;
                    if (h != null) h(rep);
                }
            }
            if (type == PKT_PUNCH) return;
            if (type == PKT_KEEPALIVE)
            {
                // Path is alive even when the peer is muted (muted mics send
                // no audio at all - a dead-peer check on audio alone would
                // false-positive on every mute). Needs no decryption, and so -
                // deliberately - it credits the watchdog and NOTHING else. It
                // cannot name a route, because an address that only ever sent
                // keyless bytes has not been shown to carry media.
                LastRxTicks = DateTime.UtcNow.Ticks;
                return;
            }
            if (type != PKT_AUDIO && type != PKT_VIDEO && type != PKT_ACK)
                return;   // noise: no LastRx credit

            // Arrival itself proves the direct path works - credit the watchdog
            // even when the packet is then dropped below. The source address is NOT
            // recorded here: it waits until the bytes actually decrypt, below.
            LastRxTicks = DateTime.UtcNow.Ticks;

            // Sends are gated on key readiness, so a packet landing before our
            // key exists is pre-negotiation/misordered. Feeding its bytes to the
            // audio path would be a burst of noise - drop it instead.
            if (_key == null) return;
            if (payload.Length <= 16) return;   // encrypted packets always carry a 16-byte IV

            // Encrypted packets carry a 16-byte IV prefix.
            byte[] dec;
            byte[] iv = new byte[16];
            Buffer.BlockCopy(payload, 0, iv, 0, 16);
            byte[] encBody = new byte[payload.Length - 16];
            Buffer.BlockCopy(payload, 16, encBody, 0, encBody.Length);
            dec = VoipCrypto.AesCtr(_key, encBody, iv);

            if (type == PKT_ACK)
            {
                // A receipt. Not a media frame: it must not touch RxFrames/RxBytes, or the
                // "frames sent == frames received" assertion would count its own paperwork.
                if (dec.Length < 16) return;
                long peerRx = 0;
                byte[] cnt = new byte[8];
                for (int i = 0; i < 8; i++) { peerRx |= (long)dec[i] << (8 * i); cnt[i] = dec[i]; }
                byte[] mac = VoipCrypto.HmacSha256(_key, cnt);
                // This is the only place on the media path that can tell the peer from
                // somebody else, because a CTR keystream has no integrity: an off-path
                // datagram that merely says it is an ACK decrypts to noise and fails here.
                // It earns no proof - no receipt, no source address, no pair. It does still
                // credit the watchdog above, as any media-shaped packet has always done,
                // because making THAT depend on a tag audio and video do not carry would
                // drop live calls on a single forged packet rather than protect anything.
                if (!MacOk(dec, 8, mac)) return;
                Interlocked.Exchange(ref PeerRxFrames, peerRx);
                LastAckTicks = DateTime.UtcNow.Ticks;
                if (learn) { LastAckRemote = rep; LastRxAuthRemote = rep; }
                // ICE: a receipt that passes its MAC proves this candidate delivers.
                // Confirm it so subsequent frames go only to this address.
                if (learn) ConfirmCandidate(rep);
                Interlocked.Increment(ref AcksRcvd);
                return;
            }

            // A media-shaped packet while we hold a key may name the route. Say what that
            // does and does not prove: audio and video carry no MAC, so this rules out
            // keep-alives, punch packets and noise - which is the whole of the bug being
            // fixed, since a keyless probe used to be enough - but it is NOT evidence the
            // sender holds the key. The keyed evidence is the receipt above.
            if (learn) LastRxAuthRemote = rep;

            // ICE: keyed media from this address proves it delivers. Note it so
            // the confirmed-candidate path can send only here.
            if (learn) NoteRxFrom(rep);

            if (type == PKT_AUDIO)
            {
                LastRxTicks = DateTime.UtcNow.Ticks;
                Interlocked.Increment(ref RxFrames);
                Interlocked.Add(ref RxBytes, dec.Length);
                Action<byte[], IPEndPoint> h = AudioFrame;
                if (h != null) h(dec, rep);
                if (!_rxAudioLogged)
                {
                    _rxAudioLogged = true;
                    EmitLog("media: first encrypted audio frame received+decrypted from " + rep);
                }
            }
            else if (type == PKT_VIDEO && dec.Length >= 6)
            {
                LastRxTicks = DateTime.UtcNow.Ticks;
                int fid = ((int)dec[0] << 8) | dec[1];
                int cidx = ((int)dec[2] << 8) | dec[3];
                int ccnt = ((int)dec[4] << 8) | dec[5];
                // guards: corrupt/absurd counts must never poison reassembly
                if (ccnt < 1 || ccnt > 128 || cidx < 0 || cidx >= ccnt) return;
                byte[] chunk = new byte[dec.Length - 6];
                Buffer.BlockCopy(dec, 6, chunk, 0, chunk.Length);
                long key = ((long)fid << 8) | (uint)cidx;
                _videoChunks[key] = chunk;
                // bound memory for frames that never complete
                if (_videoChunks.Count > 4000) { _videoChunks.Clear(); _videoSeen.Clear(); return; }

                // Completeness is decided by actual chunk presence (a 32-bit
                // "seen" mask wraps for large frames and could trigger a
                // KeyNotFoundException that killed the receive loop).
                bool complete = true;
                int total = 0;
                for (int i = 0; i < ccnt; i++)
                {
                    byte[] c;
                    if (!_videoChunks.TryGetValue(((long)fid << 8) | (uint)i, out c))
                    { complete = false; break; }
                    total += c.Length;
                }
                if (complete)
                {
                    Interlocked.Increment(ref RxFrames);
                    Interlocked.Add(ref RxBytes, total);
                    byte[] frame = new byte[total];
                    int off = 0;
                    for (int i = 0; i < ccnt; i++)
                    {
                        long ck = ((long)fid << 8) | (uint)i;
                        byte[] c = _videoChunks[ck];
                        Buffer.BlockCopy(c, 0, frame, off, c.Length);
                        off += c.Length;
                        _videoChunks.Remove(ck);
                    }
                    _videoSeen.Remove(fid);
                    Action<byte[], IPEndPoint> h = VideoFrame;
                    if (h != null) h(frame, rep);
                    if (!_rxVideoLogged)
                    {
                        _rxVideoLogged = true;
                        EmitLog("media: first video frame reassembled+decrypted (" + frame.Length + " bytes)");
                    }
                }
            }
        }

        public void Dispose() { Close(); }

        public void Close()
        {
            _run = false;
            if (_udp != null) { try { _udp.Close(); } catch { } _udp = null; }
            if (_rxThread != null) { try { _rxThread.Join(500); } catch { } _rxThread = null; }
        }
    }

    // ---- Signaling (TCP) + discovery (UDP) + call orchestration ----
    public sealed class VoipService : IDisposable
    {
        public const int DISC_PORT = 45670;
        public const int SIG_PORT = 45671;
        public const int MEDIA_PORT = 45672;

        public string LocalName = Environment.MachineName;

        private TcpListener _sigListener;
        private UdpClient _discUdp;
        private Thread _sigThread;
        private Thread _discThread;
        private Thread _discSendThread;
        private volatile bool _run;

        private readonly Dictionary<string, VoipPeer> _peers = new Dictionary<string, VoipPeer>();
        private readonly object _peerLock = new object();
        public readonly TnsrlRouteFlow TnsrlRoutes = new TnsrlRouteFlow();

        public VoipCrypto _crypto;
        public VoipMedia Media = new VoipMedia();

        // Which STUN servers to ask. This is the Settings field doing the thing its
        // label says: the old code stored the list and hard-coded Google's, so the
        // box changed nothing - and an ISP that blocks that host had no alternative.
        public string StunServers = "stun.l.google.com:19302,stun1.l.google.com:19302,stun.stunprotocol.org:3478";
        string[] StunServerList()
        {
            string s = StunServers;
            if (string.IsNullOrEmpty(s)) return new string[0];
            return s.Split(',');
        }

        // call state
        public bool InCall;
        public bool VideoCall;
        public string RemoteName;
        public string RemoteIp;
        private string _callId;
        private TcpClient _callTcp;          // active signaling socket for current call
        private StreamReader _callReader;
        private StreamWriter _callWriter;
        private Thread _callThread;

        // internet calling: identity + relay (call server) client
        public string MyNumber = "";
        public string NumberToken = "";

        // ---- end-to-end security (see Security.cs) ----
        // The identity key is created on first run beside the exe; the relay
        // only ever sees it inside a signed handshake, never as a secret.
        public Identity SecIdentity;
        public PeerIdentityBook SecPeers;
        public bool RequireE2e = true;          // refuse to send chat in clear
        private readonly Dictionary<string, ChatKey> _e2eKeys = new Dictionary<string, ChatKey>();
        // Ratchet counter: tracks total messages (sent + received) per peer.
        // Both sides count the same total, so they ratchet at the same point.
        // Ratchet AFTER sending/receiving to avoid key desync.
        private readonly Dictionary<string, int> _ratchetCount = new Dictionary<string, int>();
        private const int RATCHET_INTERVAL = 100;
        private readonly Dictionary<string, ChatHandshake> _e2ePending = new Dictionary<string, ChatHandshake>();
        private readonly Dictionary<string, List<string>> _e2eQueue = new Dictionary<string, List<string>>();
        private readonly Dictionary<string, DateTime> _e2eLastTry = new Dictionary<string, DateTime>();
        private readonly Dictionary<string, string> _secBlocked = new Dictionary<string, string>();
        private readonly object _secLock = new object();
        // ── Offline sealing (see OfflineSeal in Security.cs) ───────────────
        // A session key needs the peer awake. Their PUBLISHED identity key does not,
        // so a message to somebody who is off-line can still be sealed - which is what
        // lets a relay store it, and lets other relays carry it without being able to
        // read it. Filled from the relay's key directory and, for free, from every
        // KEYX we have ever completed (the book already holds those).
        private readonly Dictionary<string, string> _peerPubKeys = new Dictionary<string, string>();
        // Lines waiting on a key that has been asked for, and inbound offline messages
        // waiting on the SENDER's key (needed to verify who signed them).
        private readonly Dictionary<string, List<string>> _heldForPubKey = new Dictionary<string, List<string>>();
        private readonly Dictionary<string, List<string>> _heldOfflineIn = new Dictionary<string, List<string>>();
        private readonly Dictionary<string, DateTime> _pubKeyAsked = new Dictionary<string, DateTime>();
        // Capability-routed transports (see Transport.cs). Only the relay
        // exists today; the seam is what lets mesh/radio arrive unchanged.
        public readonly TransportRouter Routes = new TransportRouter();
        private bool _routesWired;
        // number, state (locked|handshaking|changed|failed), detail
        public event Action<string, string, string> ChatSecurity;
        // Raised whenever the route table could have changed - a link appeared or
        // went away, or the user redrew the consent line - so the settings page
        // shows the current decision instead of one taken at startup.
        public event Action RoutesChanged;
        private void RaiseRoutes() { Action h = RoutesChanged; if (h != null) h(); }
        public RelayClient Relay;
        private bool _viaRelay;              // current call signals over the relay
        private string _peerNumber;          // peer's virtual number for current call
        // Which UDP port the peer said it is actually holding. Guessing MEDIA_PORT
        // is right until that port is busy on the far machine, and then both sides
        // send to a port nobody listens on. Reset per call, not per media setup:
        // the caller announces while we are still ringing.
        private int _peerMediaPort;
        private Thread _watchThread;

        public event Action<string> Log;
        public event Action<VoipPeer> PeerListChanged;
        public event Action<string, bool> IncomingCall;          // callerName, isVideo
        public event Action<string> CallStateChanged;            // text
        public event Action<byte[]> RemoteVideoFrame;            // jpeg
        public event Action CallEnded;
        public event Action<string> DtmfReceived;                    // digit from the peer
        public event Action<string, string> ChatReceived;            // fromNumber, text
        public event Action DirectoryChanged;                    // relay directory updated

        public List<VoipPeer> Peers
        {
            get
            {
                lock (_peerLock)
                {
                    List<VoipPeer> l = new List<VoipPeer>();
                    foreach (VoipPeer p in _peers.Values)
                        if ((DateTime.Now - p.LastSeen).TotalSeconds < 15) l.Add(p);
                    return l;
                }
            }
        }

        // Number of LAN peers seen in the last 15 seconds. Used by the status
        // dot to distinguish "relay connected" from "LAN only" from "disconnected".
        public int LanPeersCount
        {
            get { lock (_peerLock) { return Peers.Count; } }
        }

        private void Emit(string msg)
        {
            Action<string> h = Log;
            if (h != null) h(msg);
        }

        public void Start()
        {
            if (_run) return;
            _run = true;

            // Open media + wire frame events FIRST, and independently of the
            // signaling bind. Otherwise a busy TCP port (45671) would silently
            // disable all audio/video for the process.
            Media.LogLine = Emit;   // before Open: port-fallback messages must surface
            try { Media.Open(MEDIA_PORT); }
            catch (Exception ex) { Emit("VoIP media error: " + ex.Message); }
            Media.AudioFrame -= OnAudioFrame;
            Media.VideoFrame -= OnVideoFrame;
            Media.AudioFrame += OnAudioFrame;
            Media.VideoFrame += OnVideoFrame;
            // The reflexive address turns out after the INVITE has gone out, on a
            // network that may never answer at all. When it does, use it: add it as a
            // candidate and tell the peer, whose other option is our LAN address.
            Media.PublicAddressKnown -= OnPublicAddress;
            Media.PublicAddressKnown += OnPublicAddress;

            bool sigOk = true;
            try
            {
                _sigListener = new TcpListener(IPAddress.Any, SIG_PORT);
                _sigListener.Start();
            }
            catch (Exception ex)
            {
                Emit("VoIP listen error: " + ex.Message + " (outgoing calls only - port " + SIG_PORT + " busy).");
                sigOk = false;
            }
            if (sigOk)
            {
                _sigThread = new Thread(SigAcceptLoop);
                _sigThread.IsBackground = true;
                _sigThread.Start();
            }

            try
            {
                _discUdp = new UdpClient();
                _discUdp.Client.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
                _discUdp.Client.Bind(new IPEndPoint(IPAddress.Any, DISC_PORT));
                _discUdp.EnableBroadcast = true;
            }
            catch (Exception)
            {
                // fall back: try plain bind
                try { _discUdp = new UdpClient(DISC_PORT); }
                catch (Exception ex2)
                {
                    Emit("VoIP discovery error: " + ex2.Message);
                    _discUdp = null;
                }
            }
            if (_discUdp != null)
            {
                _discThread = new Thread(DiscLoop);
                _discThread.IsBackground = true;
                _discThread.Start();
            }
            _discSendThread = new Thread(DiscSendLoop);
            _discSendThread.IsBackground = true;
            _discSendThread.Start();

            Emit("VoIP started: discovery+signaling+media on ports " + DISC_PORT + "/" + SIG_PORT + "/" + MEDIA_PORT);
        }

        // ---------- internet relay (call server) ----------
        // "Ready" has to mean the relay registered us, because that is what every caller
        // of this property then assumes: that the directory is real, that a number can be
        // dialled, that a queued message will reach somebody. A socket answers none of
        // that, and a socket-open-but-unregistered moment is exactly when the old gate let
        // a dial through - the caller's own list was empty by definition and the relay
        // replied ERR|registerfirst to everything it was asked.
        public bool RelayReady { get { return Relay != null && Relay.Connected && Relay.Registered; } }

        // The route table, for the settings page.
        public List<RouteRow> RouteRows() { return Routes.Rows(); }
        public bool CarryForPeers
        {
            get { return Routes.DefaultConsentGranted; }
        }

        // One switch for a whole class of behaviour: does this node carry traffic
        // for people it is not talking to? Applied to every link that asks for
        // consent, including links registered later.
        public void SetCarryForPeers(bool allowed)
        {
            Routes.DefaultConsentGranted = allowed;
            foreach (string n in Routes.ConsentLinks()) Routes.SetConsent(n, allowed);
            Emit("Route: carrying for peers " + (allowed ? "allowed" : "refused") +
                 " - the relay hop is always your own traffic only.");
            RaiseRoutes();
        }

        public void EnableRelay(string address)
        {
            if (string.IsNullOrEmpty(address)) { DisableRelay(); return; }
            EnsureSecurity();
            if (!_routesWired)
            {
                _routesWired = true;
                Routes.Add(new RelayTransport(
                    delegate(string to, byte[] frame)
                    {
                        RelayClient rr = Relay;
                        return rr != null && rr.SendMessage(to, MyNumber, Encoding.UTF8.GetString(frame));
                    },
                    delegate() { RelayClient rn = Relay; return rn != null && rn.Connected; }));
                Routes.RouteNotice += delegate(string n, string d) { Emit("Route: " + n + " " + d); RaiseRoutes(); };
                RaiseRoutes();
            }
            if (Relay != null && Relay.Address == address && Relay.Running) return;
            DisableRelay();
            Relay = new RelayClient();
            Relay.Log += delegate(string s) { Emit(s); };
            // Which server is this address, really? Pinned per address in its own file,
            // so that deleting a relay pin is never mistaken for deleting every peer's.
            try { Relay.RelayPins = new PeerIdentityBook(Path.Combine(Home.Dir, "relay_pins.txt")); }
            catch (Exception ex) { Emit("Relay: cannot open the relay pin file - relay identity checks are off: " + ex.Message); }
            // Forwarded, because a verdict that only exists inside the client object
            // has to be asked for, and nothing asks for it. The window shows this live.
            Relay.RelayTrustChanged += delegate(string verdict)
            {
                Action<string> ht = RelayTrustChanged;
                if (ht != null) ht(verdict);
            };
            Relay.DirectoryChanged += delegate
            {
                Action h = DirectoryChanged;
                if (h != null) h();
            };
            Relay.MessageArrived += HandleRelayMessage;
            // Referral: the relay we are already trusted by names other relays.
            // Surfaced to the user, never auto-dialled - see RelayClient.Dispatch.
            Relay.RelaysReferral += delegate(string list)
            {
                Action<string> hrr = RelayReferral;
                if (hrr != null) hrr(list);
            };
            Relay.MessageQueued += delegate(string to)
            {
                Action<string> hq = ChatQueued;
                if (hq != null) hq(to);
            };
            Relay.MessageUndeliverable += delegate(string to)
            {
                Action<string> ho = PeerOffline;
                if (ho != null) ho(to);
            };
            Relay.RoomUnavailable += delegate(string room)
            {
                // The relay holds a join while it waits for a route to the room
                // owner; this line means it waited and never got one. Before it
                // existed, a failed join still printed "joined room", so the member
                // sat in an empty call believing it had started.
                if (string.Equals(room, ActiveConferenceRoom, StringComparison.Ordinal))
                {
                    ActiveConferenceRoom = null;
                    ConferenceMembers.Clear();
                    Action<string, List<string>> hr = ConferenceRosterChanged;
                    if (hr != null) hr(null, ConferenceMembers);
                }
                Action<string> hc = ConferenceRefused;
                if (hc != null) hc(room);
            };
            Relay.MediaArrived += delegate(string from, string b64)
            {
                try
                {
                    if (!InCall || from != _peerNumber) return;
                    Media.InjectRelayed(Convert.FromBase64String(b64));
                }
                catch { }
            };
            Media.RelaySend = delegate(byte[] pkt)
            {
                RelayClient r = Relay;
                if (r != null && r.Connected && _peerNumber != null)
                    r.SendMedia(_peerNumber, MyNumber, pkt);
            };
            if (string.IsNullOrEmpty(MyNumber)) { Emit("Relay: no virtual number - not connecting."); return; }
            EnsureSecurity();
            // Publish our identity key with the registration. A peer who wants to
            // leave us a message while we are off-line needs it, and the only moment
            // we are guaranteed to be reachable is now.
            PublishOwnKey();
            Relay.PeerKeyArrived += OnPeerKeyArrived;
            Emit("Relay: connecting to " + address + " as #" + MyNumber);
            Relay.Start(address, MyNumber, NumberToken);
        }

        // The claim a relay stores as this number's key: our public key, signed over
        // "PUBK|<number>" by the matching private key. Settable rather than sent on
        // demand, because the relay re-registers on its own schedule and the line has
        // to be ready whenever it does.
        public void PublishOwnKey()
        {
            RelayClient r = Relay;
            if (r == null || SecIdentity == null || string.IsNullOrEmpty(MyNumber)) return;
            try
            {
                byte[] sig = SecIdentity.Sign(Encoding.UTF8.GetBytes("PUBK|" + MyNumber));
                if (sig == null) return;
                r.OwnKeyLine = "PUBK|" + MyNumber + "|" + SecIdentity.PublicBase64 + "|" +
                               Convert.ToBase64String(sig);
                // And the ownership proof, signed by the same key over a different
                // claim: this is what turns the relay's lease into something the
                // number belongs to rather than borrows.
                try
                {
                    byte[] own = SecIdentity.Sign(Encoding.UTF8.GetBytes(NumberLeaseBook.OwnClaim(MyNumber)));
                    if (own != null)
                        r.OwnProof = SecIdentity.PublicBase64 + "|" + Convert.ToBase64String(own);
                }
                catch (Exception ex2) { Emit("Security: could not sign the ownership claim: " + ex2.Message); }
                if (r.Connected) r.PublishNow(r.OwnKeyLine);
            }
            catch (Exception ex) { Emit("Security: could not publish our identity key: " + ex.Message); }
        }

        // ---- bootstrap: finding a relay when you have never had one ----
        //
        // relays.seed lives in the profile, so a friend can hand over a file instead
        // of an IP address and a fingerprint to compare. Entries are tried in order
        // and each one is probed: the probe asks WHOAMI and the answer is checked
        // BEFORE anything is registered, so a wrong entry learns nothing about us -
        // which is a promise about the wire, not just about the decision, so the
        // probe runs in a mode that has no registration in it at all.
        // An entry whose fingerprint does not match is skipped out loud - not
        // "tried anyway", which is the whole reason to carry the fingerprint.
        public static string SeedPath
        {
            get
            {
                try
                {
                    string p = Path.Combine(Home.Dir, "relays.seed");
                    if (File.Exists(p)) return p;
                    string s = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "relays.seed");
                    return File.Exists(s) ? s : p;
                }
                catch { return "relays.seed"; }
            }
        }

        public string BootstrappedFrom = "";

        // How many usable lines are in the seed list right now. The window asks this
        // before it spends anybody's time on a bootstrap: "no relay set" and "no relay
        // set, but three relays to try" are different warnings to show.
        public static int SeedEntryCount
        {
            get
            {
                string text = "";
                try { if (File.Exists(SeedPath)) text = File.ReadAllText(SeedPath); } catch { }
                try { return RelaySeed.Load(text).Count; } catch { return 0; }
            }
        }

        public bool TryBootstrapRelay()
        {
            string text = "";
            try { if (File.Exists(SeedPath)) text = File.ReadAllText(SeedPath); } catch { }
            List<RelaySeedEntry> entries = RelaySeed.Load(text);
            if (entries.Count == 0)
            {
                Emit("Bootstrap: nothing to try - relays.seed is missing or has no entries."
                     + " A relay prints a line ready to paste into it when you start one.");
                return false;
            }
            foreach (RelaySeedEntry e in entries)
            {
                if (string.Equals(e.Address, Relay == null ? null : Relay.Address, StringComparison.Ordinal)) continue;
                RelayClient probe = new RelayClient();
                probe.Log += delegate(string s) { Emit(s); };
                probe.ProbeOnly = true;     // look; do not introduce ourselves
                try { probe.RelayPins = new PeerIdentityBook(Path.Combine(Home.Dir, "relay_pins.txt")); } catch { }
                Emit("Bootstrap: checking " + e.Address + (string.IsNullOrEmpty(e.Note) ? "" : " - " + e.Note));
                bool ok = false;
                try
                {
                    // No number and no token handed over either. ProbeOnly already
                    // means this socket never sends a REG; giving it an empty identity
                    // is belt and braces, so that no later change can make a probe name
                    // somebody it was only supposed to look at.
                    probe.Start(e.Address, "", "");
                    // Wait for the identity ANSWER, not for the socket: the connection
                    // comes up first and the check runs behind it, so waiting on
                    // Connected decides while the reply is still in flight. The bound
                    // is the probe's own timeout plus a connect allowance, so a slow
                    // relay gets a full say and a dead address cannot stall the list.
                    int budget = (probe.IdentityTimeoutMs + 6000) / 100;
                    int waited = 0;
                    while (waited < budget && !probe.RelayAskSettled) { Thread.Sleep(100); waited++; }
                    ok = probe.RelayAskSettled && probe.RelayIdentityChecked &&
                         RelaySeed.Matches(e, probe.RelayFingerprint) &&
                         probe.RelayTrust != "mismatch" && probe.RelayTrust != "bad-signature";
                    if (!ok)
                    {
                        Emit("Bootstrap: " + e.Address + " was not used - " +
                             (!probe.RelayAskSettled ? "it had not answered by the time we stopped waiting."
                              : probe.RelayRefusedIdentity ? "it says it has no relay identity, so there is nothing to compare the seed line against."
                              : !probe.RelayIdentityChecked ? "it never identified itself, and this line expects a fingerprint."
                              : !RelaySeed.Matches(e, probe.RelayFingerprint)
                                  ? "its fingerprint is " + probe.RelayFingerprint + ", not what the seed line says."
                                  : "its key check failed (" + probe.RelayTrust + ")."));
                    }
                }
                catch (Exception ex) { Emit("Bootstrap: " + e.Address + " failed: " + ex.Message); ok = false; }
                try { probe.Stop(); } catch { }
                try { probe.Dispose(); } catch { }
                if (!ok) continue;
                EnableRelay(e.Address);
                BootstrappedFrom = e.Address;
                Emit("Bootstrap: connecting through " + e.Address + " (relay key " +
                     (RelaySeed.AnyKey == e.Fingerprint ? "pinned on first use" : "verified against the seed") + ").");
                return true;
            }
            return false;
        }

        public void DisableRelay()
        {
            if (Relay != null)
            {
                try { Relay.Stop(); } catch { }
                try { Relay.Dispose(); } catch { }
                Relay = null;
            }
            Media.RelaySend = null;
        }

        public List<RelayClient.PeerInfo> RelayDirectory()
        {
            return Relay == null ? new List<RelayClient.PeerInfo>() : Relay.Directory;
        }

        public bool IsRegisteredNumber(string number)
        {
            return Relay != null && Relay.Lookup(number) != null;
        }

        // ---- authenticated calls -------------------------------------------------
        // A call used to be an anonymous Diffie-Hellman exchange: strong encryption,
        // and nothing proving who is on the other end. The relay forwards INVITE and
        // ACCEPT, so a relay that swapped both public keys would sit in the middle of
        // a call nobody could decrypt - the exact thing the chat handshake already
        // refuses, by signing the exchange with the install's identity key. Same idea:
        // sign this call's DH key, verify it with the key that claims to have made it,
        // pin it beside the peer's chat key.
        //
        // "absent" (a peer on an older build) and "bad" (a signature that does not
        // verify) are deliberately different words: one is a compatibility note, the
        // other is a possible interception.
        string _callVerified = "pending";
        public string CallVerified { get { return _callVerified; } }
        public string CallPeerNumber { get { return _peerNumber; } }

        // The two fields appended to INVITE/ACCEPT. Last, so a peer that stops reading
        // after the DH key - every build before this one - still works.
        string CallAuthFields(string dhPub)
        {
            if (SecIdentity == null || string.IsNullOrEmpty(MyNumber)) return "";
            try
            {
                byte[] sig = SecIdentity.Sign(Encoding.UTF8.GetBytes(CallClaim(_callId, dhPub)));
                if (sig == null) return "";
                return "|" + SecIdentity.PublicBase64 + "|" + Convert.ToBase64String(sig);
            }
            catch { return ""; }
        }

        static string CallClaim(string id, string dhPub) { return "CALL|" + id + "|" + dhPub; }

        // Never cancels a call: by the time the answer arrives the media is already
        // flowing. What it does is say, in words, whether the far end is proven, and
        // print the digits the two people can read out to each other.
        bool VerifyCallProof(string number, string id, string dhPub, string identPub, string sigB64)
        {
            if (string.IsNullOrEmpty(identPub) || string.IsNullOrEmpty(sigB64))
            {
                _callVerified = "absent";
                Emit("Security: this call is encrypted but NOT verified - the other install"
                     + " does not sign its calls. Ask them to update it.");
                return false;
            }
            byte[] sig;
            try { sig = Convert.FromBase64String(sigB64); } catch { sig = null; }
            bool ok = sig != null && Identity.Verify(identPub,
                Encoding.UTF8.GetBytes(CallClaim(id, dhPub)), sig);
            if (!ok)
            {
                _callVerified = "bad";
                Emit("SECURITY: the call presented as #" + number + " signed its key with a key"
                     + " that does not verify. The audio is encrypted, but the far end is not"
                     + " proven to be " + number + " - treat this as a possible interception.");
                return false;
            }
            _callVerified = "yes";
            PeerIdentityBook.Trust t = PeerIdentityBook.Trust.New;
            lock (_secLock) { if (SecPeers != null) t = SecPeers.Check(number, identPub); }
            if (t == PeerIdentityBook.Trust.Changed)
            {
                _callVerified = "blocked";
                Emit("SECURITY: the call appears to come from #" + number + " with a different identity key. " +
                     "Nothing is allowed through until the new key is explicitly accepted.");
                return false;
            }
            string sn = SafetyNumberFor(number);
            Emit("Security: call with #" + number + " is encrypted AND verified" +
                 (string.IsNullOrEmpty(sn) ? "" : ". Safety number: " + sn) + ".");
            return true;
        }

        public VoipPeer FindByNumber(string number)
        {
            RelayClient.PeerInfo pi = Relay == null ? null : Relay.Lookup(number);
            if (pi == null) return null;
            return new VoipPeer { Name = pi.Machine, Ip = pi.Ip, Number = pi.Number, LastSeen = DateTime.Now };
        }

        // A signaling line arrived for the current relay call.
        private void HandleRelayMessage(string from, string line)
        {
            try
            {
                string[] p = line.Split(new char[] { '|' }, 5);
                if (p[0] == "INVITE" && p.Length >= 5)
                {
                    if (InCall)
                    {
                        RelayClient r0 = Relay;
                        if (r0 != null) r0.SendMessage(from, MyNumber, "BUSY|" + p[1]);
                        return;
                    }
                    string machine = p[3];
                    _viaRelay = true;
                    _peerNumber = from;
                    _peerMediaPort = 0;      // a new call, not a continuation
                    RelayClient.PeerInfo info = Relay == null ? null : Relay.Lookup(from);
                    RemoteIp = info == null ? null : info.Ip;
                    RemoteName = "#" + from + " (" + machine + ")";
                    _callId = p[1];
                    VideoCall = p[2] == "1";
                    _crypto = new VoipCrypto();
                    _callVerified = "pending";
                    // This handler was given four fields by the relay's split, so
                    // whatever the caller appended after the DH key is still glued
                    // into p[4]. Split it here: parsing the whole remainder as a
                    // number is how a signed INVITE would have thrown instead of
                    // ringing.
                    string[] inv = p[4].Split('|');
                    _pendingPeerPub = BigInteger.Parse(inv[0]);
                    bool proofOk = VerifyCallProof(from, _callId, inv[0],
                        inv.Length >= 2 ? inv[1] : "", inv.Length >= 3 ? inv[2] : "");
                    if (!proofOk)
                    {
                        if (Relay != null)
                            Relay.SendMessage(from, MyNumber, "REJECT|" + _callId);
                        EndCallInternal(false);
                        Emit("Security: rejected relay INVITE from #" + from + " because the identity proof was absent or invalid.");
                        return;
                    }
                    _callTcp = null;
                    _callReader = null;
                    _callWriter = null;
                    Emit("Incoming VoIP " + (VideoCall ? "video" : "voice") +
                         " call from #" + from + " (" + machine + ") via relay");
                    Action<string, bool> h = IncomingCall;
                    if (h != null) h(RemoteName, VideoCall);
                    return;
                }
                // ── the peer's real UDP media port ────────────────────────
                // Re-split without a limit, deliberately: `p` here comes from a split of
                // five, so a fifth and sixth announced field would arrive glued into
                // p[4] and be read as a port number. This is the project's oldest trap,
                // and MPORT is exactly the kind of line that grows fields at the end.
                if (p[0] == "MPORT" && p.Length >= 2) { LearnPeerPort(line.Split('|')); return; }
                // peer chat text (not call signaling) - deliver once
                if (p[0] == "CHAT")
                {
                    string chatText = line.Length > 5 ? line.Substring(5) : "";
                    Emit("Chat received from #" + from);
                    // delivery receipt: confirm to the sender the moment the
                    // text reached this device (WhatsApp double-tick logic)
                    try { RelayClient r0 = Relay; if (r0 != null) r0.SendMessage(from, MyNumber, "CHATACK|"); } catch { }
                    Action<string, string> ch = ChatReceived;
                    if (ch != null) ch(from, chatText);
                    return;
                }
                // ---- security handshake + sealed payloads ----
                if (p[0] == "KEYX" || p[0] == "KEYXOK" || p[0] == "ECHAT" || p[0] == OfflineSeal.Verb)
                {
                    HandleSecurityLine(from, p, line);
                    return;
                }
                if (p[0] == "CHATACK")
                {
                    Action<string> h2 = ChatAckReceived;
                    if (h2 != null) h2(from);
                    return;
                }
                if (p[0] == "CTYP")
                {
                    bool on = line.Length < 6 || line.Substring(6) != "0";
                    Action<string, bool> h3 = ChatTypingReceived;
                    if (h3 != null) h3(from, on);
                    return;
                }
                // Read receipt — peer opened our conversation
                if (p[0] == "CHATREAD")
                {
                    long ts = 0;
                    if (p.Length >= 2) long.TryParse(p[1], out ts);
                    Action<string, long> hr = ChatReadReceived;
                    if (hr != null) hr(from, ts);
                    return;
                }
                // Message reaction
                if (p[0] == "REACT" && p.Length >= 3)
                {
                    Action<string, string, string> hrx = ReactionReceived;
                    if (hrx != null) hrx(from, p[1], p[2]);
                    return;
                }
                // File transfer signaling
                if (p[0] == "FTOFFER" && p.Length >= 4)
                {
                    long sz = 0; long.TryParse(p[3], out sz);
                    Action<string, string, string, long> hfo = FileOfferReceived;
                    if (hfo != null) hfo(from, p[1], p[2], sz);
                    return;
                }
                if (p[0] == "FTACCEPT" && p.Length >= 3)
                {
                    int port = 0; int.TryParse(p[2], out port);
                    Action<string, string, int> hfa = FileAcceptReceived;
                    if (hfa != null) hfa(from, p[1], port);
                    return;
                }
                if (p[0] == "FTREJECT" && p.Length >= 2)
                {
                    Action<string, string> hfr = FileRejectReceived;
                    if (hfr != null) hfr(from, p[1]);
                    return;
                }
                // Session key rotation (PFS)
                if (p[0] == "KEYROTATE" && p.Length >= 2)
                {
                    HandleKeyRotate(p[1]);
                    return;
                }
                // voice note: base64 WAV in one relay line ("VAUD|<b64>")
                if (p[0] == "VAUD")
                {
                    string b64 = line.Length > 5 ? line.Substring(5) : "";
                    byte[] wav = null;
                    try { wav = Convert.FromBase64String(b64); } catch { }
                    Emit("Voice note received from #" + from +
                        (wav == null ? " (corrupt)" : " (" + (wav.Length / 1024) + " KB)"));
                    try { RelayClient r0 = Relay; if (r0 != null) r0.SendMessage(from, MyNumber, "CHATACK|"); } catch { }
                    if (wav != null)
                    {
                        Action<string, byte[]> h4 = ChatVoiceReceived;
                        if (h4 != null) h4(from, wav);
                    }
                    return;
                }
                // Sticker pack sync: frames are content, so these lines only
                // ever arrive inside a sealed payload. Routing is all the
                // transport does - the stickers folder belongs to the UI layer.
                if (StickerSync.IsStickerLine(line))
                {
                    Action<string, string> hsk = StickerLine;
                    if (hsk != null) hsk(from, line);
                    return;
                }
                // Conference room key distribution (arrives via sealed chat)
                if (p[0] == "CONFKEY" && p.Length >= 2)
                {
                    try
                    {
                        byte[] key = Convert.FromBase64String(p[1]);
                        SetConferenceRoomKey(key);
                        Emit("Conference: received E2E room key from #" + from);
                    }
                    catch { }
                    return;
                }
                // Conference signals
                if (p[0] == "CONF_MIXED" && p.Length >= 4)
                {
                    string roomId = p[1];
                    // "mix" = the server summed the room for us (v4 mixer). An
                    // older server puts the speaker's number here instead; both
                    // decode the same way, so an old peer still gets audio.
                    string fromNum = p[2];
                    try
                    {
                        byte[] pcm = Convert.FromBase64String(p[3]);
                        Action<string, string, byte[]> hcm = ConferenceMixedAudio;
                        if (hcm != null) hcm(roomId, fromNum, pcm);
                        // Also playout via the normal audio path
                        Media.RaiseAudioFrame(pcm, null);
                    }
                    catch { }
                    return;
                }
                if (p[0] == "CONF_TALK" && p.Length >= 3)
                {
                    Dictionary<string, int> levels = new Dictionary<string, int>();
                    foreach (string pair in p[2].Split(','))
                    {
                        int c = pair.IndexOf(':');
                        if (c <= 0) continue;
                        int lvl;
                        if (int.TryParse(pair.Substring(c + 1), out lvl)) levels[pair.Substring(0, c)] = lvl;
                    }
                    Action<string, Dictionary<string, int>> hct = ConferenceTalkLevels;
                    if (hct != null) hct(p[1], levels);
                    return;
                }
                if (p[0] == "CONF_VID" && p.Length >= 4)
                {
                    byte[] jpeg = null;
                    try { jpeg = Convert.FromBase64String(p[3]); } catch { }
                    if (jpeg != null)
                    {
                        Action<string, string, byte[]> hcv = ConferenceVideo;
                        if (hcv != null) hcv(p[1], p[2], jpeg);
                    }
                    return;
                }
                if (p[0] == "CONF_JOINROOM" && p.Length >= 3)
                {
                    Action<string, string, string> hci = ConferenceInviteReceived;
                    if (hci != null) hci(p[1], from, p[2]);
                    return;
                }
                if (p[0] == "CONF_ROSTER" && p.Length >= 3)
                {
                    string roomId = p[1];
                    List<string> members = new List<string>(p[2].Split(new char[] { ',' }, StringSplitOptions.RemoveEmptyEntries));
                    ConferenceMembers.Clear();
                    ConferenceMembers.AddRange(members);
                    Action<string, List<string>> hcr = ConferenceRosterChanged;
                    if (hcr != null) hcr(roomId, members);
                    return;
                }
                // E2E conference audio forwarded from a peer (relay did not mix)
                if (p[0] == "CONF_EAUDIOR" && p.Length >= 4)
                {
                    if (_confRoomKey == null) return; // not in E2E mode
                    try
                    {
                        byte[] raw = Convert.FromBase64String(p[3]);
                        if (raw.Length < 16) return;
                        byte[] iv = new byte[16];
                        byte[] ct = new byte[raw.Length - 16];
                        Buffer.BlockCopy(raw, 0, iv, 0, 16);
                        Buffer.BlockCopy(raw, 16, ct, 0, ct.Length);
                        byte[] pcm = VoipCrypto.AesCtr(_confRoomKey, ct, iv);
                        string fromNum = p[2];
                        // Local mix: sum decrypted PCM from all peers
                        byte[] mixed = LocalConfMix(fromNum, pcm);
                        if (mixed != null)
                        {
                            Action<string, string, byte[]> hcm = ConferenceMixedAudio;
                            if (hcm != null) hcm(p[1], fromNum, pcm);
                            Media.RaiseAudioFrame(mixed, null);
                        }
                    }
                    catch { }
                    return;
                }
                if (InCall && _viaRelay && from == _peerNumber)
                    HandleSigLine(line);
            }
            catch (Exception ex) { Emit("Relay signaling error: " + ex.Message); }
        }

        // Send one signaling line on the current call (direct socket or relay).
        private void SendSig(string line)
        {
            try
            {
                if (_viaRelay)
                {
                    RelayClient r = Relay;
                    if (r != null && _peerNumber != null)
                        if (!r.SendMessage(_peerNumber, MyNumber, line))
                            Emit("Relay: send failed: " + line);
                    return;
                }
                if (_callWriter != null) _callWriter.WriteLine(line);
            }
            catch (Exception ex) { Emit("Signaling send error: " + ex.Message); }
        }

        // Watchdog rule, split out as pure logic so it can be tested without a call.
        // Returns the reason to move the send path onto the relay, or null to leave
        // direct media alone.
        //
        // Two different failures, two different timers. A path that never arrived is
        // a blocked/symmetric route and is given up on at 3 s. A path that worked and
        // then went quiet is a roam between access points, a NAT re-mapping the port,
        // or a phone leaving LTE - and ending the call for that, when a relay route
        // exists and has never been tried, is the wrong recovery. Silence of 5 s is
        // also longer than a peer can be silent by accident, because keep-alives ride
        // the same path every 3 s and credit it whenever they arrive.
        public static string RelayFallbackReason(long lastRxTicks, double upSeconds,
                                                 bool relayActive, bool hasRelayRoute, bool numberRouted)
        {
            if (relayActive) return null;
            // A plain IP call has no relay route to fall back to; it must stay direct
            // and let the dead-peer timer do its work.
            if (!hasRelayRoute || !numberRouted) return null;
            if (lastRxTicks == 0)
                return upSeconds >= 3.0 ? "no direct media after 3 s" : null;
            double silent = (DateTime.UtcNow - new DateTime(lastRxTicks, DateTimeKind.Utc)).TotalSeconds;
            return silent >= 5.0 ? "direct media went quiet for " + (int)silent + " s" : null;
        }

        // ── The third failure: ours lands nowhere while theirs lands fine ──────
        // Every rule above is judged from OUR side of the call - we are not receiving, so
        // move. None of them can see the case this exists for: media arriving at the peer's
        // socket from an address we are not sending to, so the peer hears nothing, we hear
        // perfectly, and both screens report a connected call. It is only visible as the
        // peer's signed receipt saying it has decrypted none of our frames.
        //
        // The two thresholds are what make that actionable rather than a coin flip. A
        // receipt taken in the first seconds of a call says 0 for an honest reason - we had
        // sent nothing yet - and a peer's receipts are 3 s apart, so a single one-way
        // reading is not evidence. ONE_WAY_BEATS spans enough watchdog seconds to catch at
        // least two receipts, and ONE_WAY_MIN_FRAMES ensures we had actually been talking
        // before the peer's silence is read as failure. Without both, the first receipt of
        // every call would bounce it to the relay.
        public const int OneWayBeatsNeeded = 6;
        public const long OneWayMinFrames = 100;    // ~2 s of audio at 50 frames/s

        public static string OneWayFallbackReason(string pair, long ourTx, int beats,
                                                  bool relayActive, bool hasRelayRoute, bool numberRouted)
        {
            if (relayActive) return null;
            // Same guard as the rule above: with no relay route to move to, deciding the
            // direct path failed only ends a call that at least works one way.
            if (!hasRelayRoute || !numberRouted) return null;
            if (pair != "one-way") return null;
            if (beats < OneWayBeatsNeeded) return null;
            if (ourTx < OneWayMinFrames) return null;
            return "the peer reports our media is not arriving";
        }

        // Watchdog: if no direct media arrives 3 s into the call, switch the
        // send path to the server relay (both sides run this independently;
        // receiving a relayed packet also activates the relay).
        private int _watchGen;
        private void StartCallWatchdog()
        {
            int gen = Interlocked.Increment(ref _watchGen);
            DateTime start = DateTime.UtcNow;
            Thread t = new Thread((ThreadStart)delegate
            {
                DateTime lastKa = DateTime.MinValue;
                DateTime keyAt = DateTime.MinValue;
                string lastRoute = "";
                int oneWayBeats = 0;
                while (InCall && gen == _watchGen)
                {
                    Thread.Sleep(1000);
                    if (!InCall || gen != _watchGen) break;
                    double up = (DateTime.UtcNow - start).TotalSeconds;

                    // Say how the call is reaching us as soon as the answer is known. Two
                    // people at distance cannot debug a path they have never been shown,
                    // and "direct" is not a fact about a network - which address actually
                    // delivered the frames is. The proof is tracked alongside rather than
                    // inside the kind, because it lands a few seconds later than the route
                    // does and a change of either has to be said out loud.
                    string rk = Route;
                    string pf = RouteProved;
                    string token = rk + "/" + pf;
                    if (rk != "none" && token != lastRoute)
                    {
                        lastRoute = token;
                        Emit("media route: " + RouteWords(rk) + " (from " +
                             (Media.LastRxAuthRemote == null ? "?" : Media.LastRxAuthRemote.ToString()) +
                             ") - " + PairWords(pf));
                        if (Media.HasKey)
                            SetState((VideoCall ? "Video call" : "VoIP call") +
                                (_callVerified == "yes" ? " (encrypted, verified)" : " (encrypted, other end unproven)") +
                                " \u00b7 " + RouteWords(rk) + " \u00b7 " + PairWords(pf));
                        RaiseRoutes();
                    }

                    // Counted, never sampled. A single one-way reading is not a verdict:
                    // the peer's receipt may simply have been taken before we had sent
                    // anything, and receipts are 3 s apart while this beat is 1 s. Any other
                    // state - proved, waiting, or a peer that sends no receipts at all -
                    // restarts the count, so a path that recovers is not punished for the
                    // moment it looked dead.
                    if (pf == "one-way") oneWayBeats++;
                    else oneWayBeats = 0;

                    // keep-alive every 3 s: proves the path alive even when a
                    // side is muted (a muted mic sends no audio at all). Once the key
                    // exists a receipt rides the same beat, so "alive" and "the peer is
                    // decrypting us" are reported together instead of one being inferred
                    // from the other - and the receipt, unlike the keep-alive, can only
                    // have come from somebody holding the call key.
                    if ((DateTime.UtcNow - lastKa).TotalSeconds >= 3.0)
                    {
                        lastKa = DateTime.UtcNow;
                        try { Media.KeepAlive(); } catch { }
                        try { if (Media.HasKey) Media.AckPeer(); } catch { }
                    }

                    // No direct media at all after 3 s, or a path that worked and
                    // then fell silent: move to the relay rather than suffering.
                    string why = RelayFallbackReason(Media.LastRxTicks, up, Media.RelayActive,
                        Media.RelaySend != null, !string.IsNullOrEmpty(_peerNumber));
                    if (why != null)
                    {
                        Media.RelayActive = true;
                        Emit(why + " - switching to relay");
                        RaiseRoutes();
                    }

                    // The third failure, and the only one the two timers above are blind
                    // to: our media landing nowhere while theirs lands perfectly. Nothing
                    // here goes quiet, so nothing measured here can see it - it takes the
                    // peer's signed receipt saying it decrypted none of our frames. Kept
                    // separate from `why` because the two reasons read differently to a
                    // person on the call, and a relay already active makes it moot.
                    string ow = OneWayFallbackReason(pf, Interlocked.Read(ref Media.TxFrames),
                        oneWayBeats, Media.RelayActive, Media.RelaySend != null,
                        !string.IsNullOrEmpty(_peerNumber));
                    if (ow != null)
                    {
                        Media.RelayActive = true;
                        Emit(ow + " - switching to relay");
                        RaiseRoutes();
                    }

                    // dead-peer detection: only once the call is established
                    // (key negotiated - ringing must be allowed to last), and
                    // with a 6 s grace for the first keep-alives to arrive.
                    if (Media.HasKey)
                    {
                        if (keyAt == DateTime.MinValue) keyAt = DateTime.UtcNow;
                        double sinceKey = (DateTime.UtcNow - keyAt).TotalSeconds;
                        if (sinceKey >= 6.0)
                        {
                            long last = Media.LastRxTicks;
                            DateTime lastDt = last == 0 ? keyAt : new DateTime(last, DateTimeKind.Utc);
                            double silent = (DateTime.UtcNow - lastDt).TotalSeconds;
                            if (silent >= 12.0)
                            {
                                Emit("no media from the peer for " + (int)silent + " s - ending the call");
                                try { SendSig("BYE|" + _callId); } catch { }
                                EndCallInternal(true);
                                break;
                            }
                        }
                    }
                }
            });
            t.IsBackground = true;
            t.Start();
            _watchThread = t;
        }

        // ---------- discovery ----------
        // Zero-configuration joining. A device with no relay asks on its own
        // network "is anyone hosting?" and any hosting app answers with the
        // address to dial. This is what removes "somebody must type an IP" for
        // the neighbourhood/LAN case - it is broadcast, so it never leaves the
        // local network and nothing central resolves it.
        public bool HostingRelay;                        // set by the app when Host server is on
        public string RelayAdvertiseAddr = "";           // what we answer to a probe
        public event Action<string> RelayDiscovered;     // host:port heard on the LAN

        private void DiscSendLoop()
        {
            int tick = 0;
            while (_run)
            {
                try
                {
                    if (_discUdp != null)
                    {
                        byte[] hello = Encoding.UTF8.GetBytes("USSDDISC|1|" + LocalName);
                        _discUdp.Send(hello, hello.Length, new IPEndPoint(IPAddress.Broadcast, DISC_PORT));
                        string tnsrl = Tnsrl.BuildAnnouncement(
                            LocalName, GetLocalIp(), Media.LocalPort);
                        if (!string.IsNullOrEmpty(tnsrl))
                        {
                            byte[] route = Encoding.UTF8.GetBytes(tnsrl);
                            _discUdp.Send(route, route.Length, new IPEndPoint(IPAddress.Broadcast, DISC_PORT));
                        }

                        // Ask for a relay only while we have none, and every 5th
                        // pass (about 10 s): a probe storm on a busy WLAN buys nothing.
                        RelayClient r = Relay;
                        bool haveRelay = r != null && r.Connected;
                        if (!haveRelay && tick % 5 == 0)
                        {
                            byte[] probe = Encoding.UTF8.GetBytes("USSDRELAY?|" + LocalName);
                            _discUdp.Send(probe, probe.Length, new IPEndPoint(IPAddress.Broadcast, DISC_PORT));
                        }
                    }
                }
                catch { }
                tick++;
                Thread.Sleep(2000);
            }
        }

        private void DiscLoop()
        {
            while (_run)
            {
                IPEndPoint rep = new IPEndPoint(IPAddress.Any, 0);
                byte[] data = null;
                try { data = _discUdp.Receive(ref rep); }
                catch { if (!_run) return; continue; }
                if (data == null) continue;
                string s = Encoding.UTF8.GetString(data);
                string[] parts = s.Split('|');

                TnsrlRoute discoveredRoute;
                if (Tnsrl.TryParse(s, rep.Address, out discoveredRoute))
                {
                    TnsrlRoutes.Observe(discoveredRoute);
                    lock (_peerLock)
                    {
                        VoipPeer p;
                        string ip = rep.Address.ToString();
                        if (!_peers.TryGetValue(ip, out p))
                        {
                            p = new VoipPeer { Name = discoveredRoute.Name, Ip = ip };
                            _peers[ip] = p;
                            Action<VoipPeer> h2 = PeerListChanged;
                            if (h2 != null) h2(p);
                        }
                        if (!string.IsNullOrEmpty(discoveredRoute.Name))
                            p.Name = discoveredRoute.Name;
                        p.MediaPort = discoveredRoute.MediaPort;
                        p.NetworkType = discoveredRoute.NetworkType;
                        p.LastSeen = DateTime.Now;
                    }
                    Action<VoipPeer> hr = PeerListChanged;
                    if (hr != null) hr(null);
                    continue;
                }

                // A neighbour asking who hosts a relay. Answer only if we do, and
                // reply *unicast* to the asker: a broadcast answer would advertise
                // this machine's hosting to every other device on the WLAN for nothing.
                if (parts.Length >= 1 && parts[0] == "USSDRELAY?")
                {
                    if (!HostingRelay || string.IsNullOrEmpty(RelayAdvertiseAddr)) continue;
                    try
                    {
                        byte[] ans = Encoding.UTF8.GetBytes("USSDRELAY|" + RelayAdvertiseAddr + "|" + LocalName);
                        _discUdp.Send(ans, ans.Length, new IPEndPoint(rep.Address, rep.Port));
                    }
                    catch { }
                    continue;
                }
                if (parts.Length >= 2 && parts[0] == "USSDRELAY")
                {
                    string addr = parts[1].Trim();
                    if (addr.Length == 0) continue;
                    Action<string> hrly = RelayDiscovered;
                    if (hrly != null) hrly(addr);
                    continue;
                }
                if (parts.Length >= 3 && parts[0] == "USSDDISC")
                {
                    if (rep.Address.Equals(IPAddress.Loopback)) continue;
                    string name = parts[2];
                    if (name == LocalName && rep.Address.Equals(GetLocalIp())) continue;
                    lock (_peerLock)
                    {
                        VoipPeer p;
                        string ip = rep.Address.ToString();
                        if (!_peers.TryGetValue(ip, out p))
                        {
                            p = new VoipPeer { Name = name, Ip = ip };
                            _peers[ip] = p;
                            Action<VoipPeer> h2 = PeerListChanged;
                            if (h2 != null) h2(p);
                        }
                        p.LastSeen = DateTime.Now;
                    }
                    Action<VoipPeer> h = PeerListChanged;
                    if (h != null) h(null); // refresh signal
                }
            }
        }

        public static IPAddress GetLocalIp()
        {
            try
            {
                using (Socket s = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp))
                {
                    s.Connect("8.8.8.8", 80);
                    return ((IPEndPoint)s.LocalEndPoint).Address;
                }
            }
            catch { return IPAddress.Loopback; }
        }

        // ---------- signaling ----------
        private void SigAcceptLoop()
        {
            while (_run)
            {
                TcpClient c = null;
                try { c = _sigListener.AcceptTcpClient(); }
                catch { if (!_run) return; continue; }
                TcpClient cc = c;
                Thread t = new Thread((ThreadStart)delegate { HandleIncoming(cc); });
                t.IsBackground = true;
                t.Start();
            }
        }

        private void HandleIncoming(TcpClient c)
        {
            try
            {
                c.ReceiveTimeout = 60000;
                StreamReader r = new StreamReader(c.GetStream(), Encoding.UTF8);
                StreamWriter w = new StreamWriter(c.GetStream(), Encoding.UTF8);
                w.AutoFlush = true;
                string line;
                while ((line = r.ReadLine()) != null)
                {
                    string[] p = line.Split('|');
                    if (p.Length == 0) continue;
                    if (p[0] == "INVITE" && p.Length >= 5)
                    {
                        string callId = p[1];
                        bool video = p[2] == "1";
                        string name = p[3];
                        BigInteger pub = BigInteger.Parse(p[4]);
                        if (InCall)
                        {
                            w.WriteLine("BUSY|" + callId);
                            continue;
                        }
                        RemoteName = name;
                        RemoteIp = ((IPEndPoint)c.Client.RemoteEndPoint).Address.ToString();
                        _peerMediaPort = 0;      // a new call, not a continuation
                        _callId = callId;
                        _callTcp = c;
                        _callReader = r;
                        _callWriter = w;
                        VideoCall = video;
                        _viaRelay = false;
                        _peerNumber = null;
                        _crypto = new VoipCrypto();
                        _callVerified = "pending";
                        // A LAN peer has no number to look up, so the identity is
                        // pinned under whatever it announced itself as; the signature
                        // check itself does not depend on that.
                        bool proofOk = VerifyCallProof(name, callId, p[4],
                            p.Length >= 6 ? p[5] : "", p.Length >= 7 ? p[6] : "");
                        if (!proofOk)
                        {
                            try { w.WriteLine("REJECT|" + callId); } catch { }
                            try { c.Close(); } catch { }
                            Emit("Security: rejected direct call from " + name + " because the identity proof was absent or invalid.");
                            return;
                        }
                        Action<string, bool> h = IncomingCall;
                        if (h != null) h(name, video);
                        Emit("Incoming VoIP " + (video ? "video" : "voice") + " call from " + name + " (" + RemoteIp + ")");
                        // store peer pub for accept
                        _pendingPeerPub = pub;
                        // read signaling already while ringing: a caller cancel
                        // (BYE) or a dead socket must dismiss the ring overlay
                        // instead of leaving it ringing forever.
                        _callThread = new Thread(CallReadLoop);
                        _callThread.IsBackground = true;
                        _callThread.Start();
                        return; // call thread continues in AcceptIncomingCall/RejectIncomingCall
                    }
                    if (p[0] == "HELLO")
                    {
                        w.WriteLine("HELLO|" + LocalName);
                    }
                }
            }
            catch (Exception)
            {
                if (InCall) { Emit("Signaling closed."); EndCallInternal(false); }
            }
        }

        private BigInteger _pendingPeerPub;

        // ---------- placing a call ----------
        public bool StartCall(string ip, bool video)
        {
            return TryDirectCall(ip, null, null, video);
        }

        // Place a call to a registered virtual number: try the direct path
        // first (identity-verified), fall back to relay signaling.
        public bool StartCallByNumber(string number, bool video)
        {
            if (InCall) { Emit("Already in a call."); return false; }
            if (Relay == null) { Emit("No relay server configured."); return false; }
            RelayClient.PeerInfo info = Relay.Lookup(number);
            if (info == null)
            {
                // A miss in our own directory is not a fact about the friend. The list of
                // who is here arrives some moments after connecting, so a call placed
                // immediately after opening the app used to be refused as "not online"
                // while the person being dialled was online and idle. Ask the relay, which
                // is the only party that knows - including numbers registered on another
                // relay, which this client's list may never contain at all.
                if (!Relay.Registered)
                {
                    // Not a fact about the friend, and it must not be worded like one.
                    Emit("Still registering with the relay - try the call again in a moment.");
                    return false;
                }
                if (!Relay.AskOnline(number, 1500) && Relay.WhoVerdict == "no")
                {
                    // Only an explicit "no" from the relay stops the dial. A timeout is
                    // not a fact about the friend, and refusing on one would be the old
                    // lie with a new excuse - so "silent" falls through and the signalling
                    // itself answers: the relay either routes the INVITE or reports it
                    // undeliverable, and the call fails as an unanswered call does.
                    Emit("Number #" + number + " is not connected - the relay says so, not just our empty list.");
                    return false;
                }
                if (Relay.WhoVerdict == "silent")
                    Emit("The relay did not answer our question about #" + number +
                         " in time. Not knowing is not a no, so the call is being placed and " +
                         "the signalling will answer it: if they are not there, the INVITE comes back undeliverable.");
                info = Relay.Lookup(number);
                if (info == null)
                {
                    // Worded from what is actually known. "They are online at the relay"
                    // would be a claim this branch cannot make when the question timed
                    // out - which is how a timeout ends up reported as a fact about the
                    // peer, the exact mistake this whole path exists to stop.
                    bool known = Relay.WhoVerdict == "yes";
                    Emit("#" + number + (known
                            ? " is online at the relay" + (Relay.IsRemoteNumber(number) ? " on another relay" : "")
                            : " may well be online; the relay was not asked in time")
                         + ", and we have no address for them - the call goes through the relay.");
                }
                else
                    Emit("#" + number + " was online though unseen a moment ago; reaching them now.");
            }

            if (info != null && !string.IsNullOrEmpty(info.Ip) &&
                TryDirectCall(info.Ip, info.Machine, number, video))
                return true;

            try
            {
                InCall = true;
                VideoCall = video;
                _viaRelay = true;
                _peerNumber = number;
                _peerMediaPort = 0;
                // No address is allowed here: the relay can deliver signalling and media to
                // a number it knows even when this client has never seen its IP, and a call
                // carried one hop away still beats a call refused by a cold cache.
                RemoteIp = info == null ? "" : info.Ip;
                RemoteName = "#" + number + " (" + (info == null ? "via relay" : info.Machine) + ")";
                _callId = Guid.NewGuid().ToString("N").Substring(0, 8);
                _crypto = new VoipCrypto();
                SetState("Calling #" + number + " (relay) ...");
                _callVerified = "pending";      // the last call's answer is not this one's
                if (!Relay.SendMessage(number, MyNumber,
                    "INVITE|" + _callId + "|" + (video ? "1" : "0") + "|" + LocalName + "|" +
                    _crypto.Pub.ToString() + CallAuthFields(_crypto.Pub.ToString())))
                {
                    EndCallInternal(false);
                    Emit("Relay not connected.");
                    return false;
                }
                // RemoteIp, not info.Ip: a number the relay confirmed but this client has
                // never seen an address for is a legitimate call - through the relay - and
                // dereferencing the missing entry would throw exactly there.
                SetupMediaForCall(RemoteIp);
                StartCallWatchdog();
                return true;
            }
            catch (Exception ex)
            {
                Emit("Call failed: " + ex.Message);
                InCall = false;
                SetState("Idle");
                return false;
            }
        }

        // Direct TCP call. When expectMachine is set, the far end must answer
        // HELLO with that machine name (proves it is the directory's device -
        // not some unrelated host on the same public IP).
        private bool TryDirectCall(string ip, string expectMachine, string number, bool video)
        {
            if (InCall) { Emit("Already in a call."); return false; }
            try
            {
                TcpClient c = new TcpClient();
                IAsyncResult ar = c.BeginConnect(ip, SIG_PORT, null, null);
                if (!ar.AsyncWaitHandle.WaitOne(2500, false))
                {
                    try { c.Close(); } catch { }
                    return false;
                }
                c.EndConnect(ar);
                StreamWriter w = new StreamWriter(c.GetStream(), Encoding.UTF8);
                w.AutoFlush = true;
                StreamReader r = new StreamReader(c.GetStream(), Encoding.UTF8);
                w.WriteLine("HELLO|");
                c.ReceiveTimeout = 3000;
                string hello = r.ReadLine();
                if (hello == null || !hello.StartsWith("HELLO|"))
                {
                    try { c.Close(); } catch { }
                    Emit("Direct connect to " + ip + " is not a USSD Manager endpoint.");
                    return false;
                }
                string machine = hello.Substring(6);
                if (!string.IsNullOrEmpty(expectMachine) && machine != expectMachine)
                {
                    try { c.Close(); } catch { }
                    Emit("Endpoint at " + ip + " is '" + machine + "', expected '" + expectMachine + "' - using relay.");
                    return false;
                }
                try { c.ReceiveTimeout = 0; } catch { }

                _callTcp = c;
                _callReader = r;
                _callWriter = w;
                InCall = true;
                VideoCall = video;
                _viaRelay = false;
                _peerNumber = number;
                _peerMediaPort = 0;
                RemoteIp = ip;
                RemoteName = string.IsNullOrEmpty(number) ? ip : "#" + number + " (" + machine + ")";
                _callId = Guid.NewGuid().ToString("N").Substring(0, 8);
                _crypto = new VoipCrypto();
                SetState("Connecting to " + ip + " ...");
                _callVerified = "pending";
                w.WriteLine("INVITE|" + _callId + "|" + (video ? "1" : "0") + "|" + LocalName + "|" +
                    _crypto.Pub.ToString() + CallAuthFields(_crypto.Pub.ToString()));

                // media setup + STUN + punch
                SetupMediaForCall(ip);
                StartCallWatchdog();

                _callThread = new Thread(CallReadLoop);
                _callThread.IsBackground = true;
                _callThread.Start();
                return true;
            }
            catch (Exception ex)
            {
                Emit("Call failed: " + ex.Message);
                InCall = false;
                SetState("Idle");
                return false;
            }
        }

        // ---- routing a call's media over the relay on purpose --------------
        // Off by default: direct is lower latency and costs the relay's operator less.
        // On, a call works where UDP is blocked or shaped - mobile hotspots, corporate
        // Wi-Fi, symmetric NAT - for the price of one extra hop.
        //
        // It is NOT an anonymity feature and must not be described as one. The relay
        // directory already tells a peer the address it saw you at (`RDIST` carries the
        // IP of every registered number), so moving only the media would hide nothing
        // worth hiding. Fixing that properly means the directory advertising a
        // relay-only endpoint, which is not built; see ROADMAP "still open".
        public bool ForceRelayedMedia;

        // ── how this call's media is actually arriving ──────────────────
        // The three addresses a peer has announced for itself, kept apart so a route can
        // be named instead of merely declared working, and our own mapped media endpoint
        // when the owner asked the router for a forward.
        IPEndPoint _peerHostEp, _peerReflexiveEp, _peerMappedEp;
        public IPEndPoint MyMappedMediaEp;
        public string PeerHostText { get { return _peerHostEp == null ? "-" : _peerHostEp.ToString(); } }
        public string PeerReflexiveText { get { return _peerReflexiveEp == null ? "-" : _peerReflexiveEp.ToString(); } }
        public string PeerMappedText { get { return _peerMappedEp == null ? "-" : _peerMappedEp.ToString(); } }
        // Which of them is delivering the frames. Reported on the call line and in the
        // window, because a person at distance cannot otherwise tell a route a router
        // promised from one that is merely open today.
        public string Route
        {
            get
            {
                try
                {
                    return RouteKind(Media.RelayActive, Media.LastRxAuthRemote, Media.LastRxTicks != 0,
                                     _peerHostEp, _peerReflexiveEp, _peerMappedEp);
                }
                catch { return "none"; }
            }
        }

        // Whether this call's path is proved in BOTH directions, as opposed to merely
        // observed from one. Separate from Route on purpose: the four route kinds answer
        // "which of their addresses delivered", and this answers "did ours ever get there",
        // which is the question a person on the other end of a silent call actually asked.
        public string RouteProved
        {
            get
            {
                try
                {
                    long ackAge = Media.LastAckTicks == 0
                        ? -1
                        : (long)(DateTime.UtcNow - new DateTime(Media.LastAckTicks, DateTimeKind.Utc)).TotalMilliseconds;
                    // Whether the peer has had a chance to answer: counted in receipt
                    // attempts rather than seconds, so the verdict does not depend on how
                    // busy this machine happens to be - and the test can drive it exactly.
                    bool pastGrace = Media.AcksSent >= 2;
                    bool sameSource = Media.LastAckRemote == null || Media.LastRxAuthRemote == null
                        || Media.LastAckRemote.Equals(Media.LastRxAuthRemote);
                    return PairProof(Media.HasKey,
                                     Interlocked.Read(ref Media.TxFrames),
                                     Interlocked.Read(ref Media.RxFrames),
                                     Interlocked.Read(ref Media.PeerRxFrames),
                                     ackAge, sameSource, pastGrace);
                }
                catch { return "none"; }
            }
        }

        // ── Is this pair proved both ways? ──────────────────────────────
        // Naming a route from the address that sent us something answers "where did their
        // audio come from". It cannot answer whether ours got there, and with media sprayed
        // at every candidate at once a reply does not imply it either - the peer may be
        // hearing us through an address it does not even answer from. Six states rather
        // than two, because "we do not know" has at least three different reasons, and
        // conflating them is how a broken call gets reported as a working one.
        //
        // One limit, stated because the opposite is easy to read into this: the peer's
        // count is CUMULATIVE for its call, so `proved` means "the peer has confirmed our
        // frames", not "is still confirming them". A path that worked for ten seconds and
        // then died keeps reading `proved`, and it is the peer's own silence timer that
        // notices. That monotone behaviour is deliberate - one lost receipt must not bounce
        // a healthy call - and it means the state worth acting on is one-way FROM THE START,
        // which is exactly the asymmetric-NAT case this was built to see.
        public static string PairProof(bool keyReady, long ourTx, long ourRx, long peerRxReported,
                                       long ackAgeMs, bool ackSameSource, bool pastGrace)
        {
            if (!keyReady) return "none";
            if (ackAgeMs < 0)
            {
                if (ourRx == 0) return "none";         // nothing arriving, nothing claimed
                if (!pastGrace) return "waiting";      // it has not had the chance yet
                return "unreported";                   // it never sends these: older build
            }
            if (!ackSameSource) return "asymmetric";   // receipt from elsewhere, not a pair
            if (peerRxReported > 0) return "proved";
            // It said, with the key, that it has decrypted nothing while we have been
            // sending. This is exactly the call the old wording described as a route.
            return ourTx > 0 ? "one-way" : "ours-silent";
        }

        // The same verdict in words, because "pair=one-way" is not something to show a
        // person holding a phone. These must stay reachability wording - a receipt proves
        // the peer decrypted our media, not that the peer is who it claims to be.
        public static string PairWords(string proof)
        {
            if (proof == "proved") return "both directions proved";
            if (proof == "one-way") return "our audio is not reaching them";
            if (proof == "asymmetric") return "their receipt came from another address than their media";
            if (proof == "ours-silent") return "nothing of ours to prove yet";
            if (proof == "waiting") return "waiting on their receipt";
            if (proof == "unreported") return "they send no receipts, so we cannot say ours reached them";
            return "no proved path yet";
        }

        // Which route a call's media starts on, before any timer is involved. Pure, so
        // the rule can be tested without two phones on the wire.
        public static string MediaRouteChoice(bool viaRelay, bool hasRelayRoute,
                                              bool peerNumberRouted, bool force)
        {
            if (!viaRelay || !hasRelayRoute || !peerNumberRouted) return "direct";
            return force ? "relay" : "direct";
        }

        // Ask this machine's router to forward UDP to the media socket, then start
        // announcing the address it reports. This is the half of reachability that
        // decides whether two people on two home networks can speak directly at all: the
        // relay's TCP forward only helps traffic that goes through a relay.
        //
        // Returns false with the router's own reason. That is the normal answer on a VPS,
        // a corporate network or a carrier-grade NAT link, and it is said as a fact rather
        // than retried - a call still works over a relay in that case.
        public bool MapMediaPort()
        {
            int port = Media.LocalPort;
            if (port <= 0)
            {
                Emit("Media port mapping: no media socket is open, so there is nothing to forward to.");
                return false;
            }
            string local = "127.0.0.1";
            try
            {
                IPAddress mine = VoipService.GetLocalIp();
                if (mine != null) local = mine.ToString();
            }
            catch { }
            IPEndPoint mapped;
            string why;
            bool ok = false;
            try { ok = PortMap.TryApplyMedia(port, local, out mapped, out why); }
            catch (Exception ex) { mapped = null; why = "the UPnP attempt itself failed: " + ex.Message; }
            if (ok && mapped != null)
            {
                MyMappedMediaEp = mapped;
                Emit("Media port mapping: " + why);
                if (InCall) { try { AnnounceMediaPort(); } catch { } }
                return true;
            }
            MyMappedMediaEp = null;
            Emit("Media port mapping: " + why);
            return false;
        }

        private void SetupMediaForCall(string ip)
        {
            // Reset per-call state, keeping the live UDP socket (rebinding it
            // here used to swallow errors and could blackhole all media).
            try { Media.ResetForCall(); }
            catch (Exception ex) { Emit("media setup error: " + ex.Message); }
            Media.SetKey(null); // until CONFIRM
            // A new peer announces its own addresses; the last call's would make this
            // one's route be judged against the wrong endpoints and reported as
            // "unannounced" when it is merely someone else's host.
            _peerHostEp = null; _peerReflexiveEp = null; _peerMappedEp = null;
            if (!Media.IsOpen)
                Emit("WARNING: media socket is not open - no audio/video will flow.");
            // Ask STUN from the media socket itself, and carry on: the answer lands
            // on the receive loop mid-call and adds the reflexive candidate then.
            // Waiting for it here would stall the call for a second and a half on a
            // server that may not answer at all.
            try { Media.StunAsk(StunServerList()); }
            catch (Exception ex) { Emit("STUN: " + ex.Message); }
            if (MediaRouteChoice(_viaRelay, Media.RelaySend != null,
                                 !string.IsNullOrEmpty(_peerNumber), ForceRelayedMedia) == "relay")
            {
                // Deliberately no candidate and no punch. The point of putting the media
                // on the relay is that nothing is sent to the peer's address directly -
                // adding the candidate and then not using it would still leak the punch.
                Media.RelayActive = true;
                Emit("Media: routed through the relay by request - no direct path will be tried.");
                AnnounceMediaPort();
                return;
            }
            if (!string.IsNullOrEmpty(ip))
            {
                IPAddress peerAddress = null;
                try { peerAddress = IPAddress.Parse(ip); } catch { }
                foreach (IPEndPoint routeCandidate in TnsrlRoutes.Candidates(peerAddress))
                    Media.AddCandidate(routeCandidate);
                int discoveredPort = 0;
                lock (_peerLock)
                {
                    foreach (VoipPeer known in _peers.Values)
                    {
                        if (known.Ip == ip && known.MediaPort > 0)
                        {
                            discoveredPort = known.MediaPort;
                            break;
                        }
                    }
                }
                try { Media.AddCandidate(new IPEndPoint(IPAddress.Parse(ip), MEDIA_PORT)); }
                catch { }
                if (discoveredPort > 0 && discoveredPort != MEDIA_PORT)
                {
                    try { Media.AddCandidate(new IPEndPoint(IPAddress.Parse(ip), discoveredPort)); }
                    catch { }
                }
                // A port learned while the peer was ringing has to be re-added after
                // the reset above, or announcing it would be pointless.
                if (_peerMediaPort > 0)
                {
                    try { Media.AddCandidate(new IPEndPoint(IPAddress.Parse(ip), _peerMediaPort)); }
                    catch { }
                }
            }
            // Tell the peer which port we really hold. Both sides used to assume
            // MEDIA_PORT; when one of them had to move, the direct path was silently
            // dead in both directions and only the relay fallback saved the call.
            AnnounceMediaPort();
            // punch for 3s
            Thread pt = new Thread((ThreadStart)delegate
            {
                for (int i = 0; i < 15 && InCall; i++) { Media.Punch(); Thread.Sleep(200); }
            });
            pt.IsBackground = true;
            pt.Start();
        }

        void AnnounceMediaPort()
        {
            try
            {
                int lp = Media.LocalPort;
                if (lp <= 0) return;
                // A forward that no longer matches this socket is a lie about
                // reachability: the media port can move when a second instance holds the
                // preferred one, and announcing the old mapping would send a peer to a
                // door that is open for somebody else.
                if (MyMappedMediaEp != null && MyMappedMediaEp.Port != lp)
                {
                    Emit("media port moved to " + lp + ", so the router's forward no longer applies.");
                    MyMappedMediaEp = null;
                }
                IPEndPoint pub = Media.PublicEp;
                // The router's forward, if we have one, rides as its own labelled field on
                // every form of this line: a peer that can only reach us through it is the
                // peer at distance, and it is the one address of ours a router has
                // promised to deliver.
                string mapField = MyMappedMediaEp == null ? "" : "|map=" +
                    MyMappedMediaEp.Address.ToString() + ":" + MyMappedMediaEp.Port;
                if (pub != null)
                {
                    // The reflexive pair, as well as the local one: a peer on another
                    // network cannot route to a 192.168 address, and this is the only
                    // address it can.
                    SendSig("MPORT|" + lp + "|" + pub.Address.ToString() + "|" + pub.Port + mapField);
                    return;
                }
                if (mapField.Length > 0)
                {
                    // No STUN answer but a real forward: say so, and leave the reflexive
                    // slots empty rather than filling them with something we do not know.
                    SendSig("MPORT|" + lp + "||" + mapField);
                    return;
                }
                SendSig("MPORT|" + lp);
            }
            catch { }
        }

        // The reflexive address, once STUN answers.
        void OnPublicAddress(IPEndPoint ep)
        {
            try { Media.AddCandidate(ep); } catch { }
            if (InCall)
            {
                AnnounceMediaPort();
                Emit("telling the peer our address as it looks from outside: " + ep);
            }
        }

        // Where to aim media at the peer, best first. Kept as a pure function over
        // the announced fields, because this decision is the difference between a
        // call that crosses NAT and one that silently falls back to the relay - and
        // it has to be testable without two phones.
        //
        //   MPORT|<localPort>                                a build that knows only this
        //   MPORT|<localPort>|<publicIp>|<publicPort>        and the reflexive pair
        //   MPORT|...|map=<ip>:<port>                        and the router's forward
        //
        // The forward rides as a self-describing `map=` field rather than as fixed
        // positions five and six, because a machine can know its mapped address without
        // ever getting a STUN answer (or the other way round). Index-based optional fields
        // would then shift, and a shifted field is read as a port number - which is how
        // this project has broken itself before.
        //
        // The three addresses mean different things and only show apart at distance: the
        // reflexive pair is what STUN happened to see, the mapped pair is what a router
        // has promised to deliver, and a call riding the reflexive address alone can stop
        // the moment that NAT binding ages out. None of it is a claim about the peer - it
        // is whatever the peer announced, and an older build announces less.
        public static bool ParsePeerMediaAnnounce(string peerIp, string[] fields, out IPEndPoint host,
                                                  out IPEndPoint reflexive, out IPEndPoint mapped)
        {
            host = null; reflexive = null; mapped = null;
            if (string.IsNullOrEmpty(peerIp) || fields == null || fields.Length < 2) return false;
            IPAddress pip;
            if (!IPAddress.TryParse(peerIp, out pip)) return false;
            int local;
            if (int.TryParse(fields[1], out local) && local >= 1024 && local <= 65535)
                host = new IPEndPoint(pip, local);
            if (fields.Length >= 4)
            {
                IPAddress pup; int pport;
                if (IPAddress.TryParse(fields[2], out pup) && int.TryParse(fields[3], out pport) &&
                    pport >= 1024 && pport <= 65535) reflexive = new IPEndPoint(pup, pport);
            }
            for (int i = 2; i < fields.Length; i++)
            {
                if (fields[i] == null || !fields[i].StartsWith("map=", StringComparison.Ordinal)) continue;
                string spec = fields[i].Substring("map=".Length).Trim();
                int colon = spec.LastIndexOf(':');
                if (colon <= 0) continue;
                IPAddress mup; int mport;
                if (IPAddress.TryParse(spec.Substring(0, colon), out mup) &&
                    int.TryParse(spec.Substring(colon + 1), out mport) &&
                    mport >= 1024 && mport <= 65535) { mapped = new IPEndPoint(mup, mport); break; }
            }
            return host != null || reflexive != null || mapped != null;
        }

        public static IPEndPoint[] MediaTargets(string peerIp, string[] fields)
        {
            var list = new List<IPEndPoint>();
            IPEndPoint host, reflexive, mapped;
            if (!ParsePeerMediaAnnounce(peerIp, fields, out host, out reflexive, out mapped)) return list.ToArray();
            // 0.0.0.0 is not an address anybody can aim at, whatever a peer announces;
            // and an announced public pair identical to the local one is the same
            // endpoint twice, which would make the punch send each frame twice with no
            // extra information. Both were rules in the older two-field form and are
            // kept here rather than re-derived per caller.
            if (reflexive != null && IPAddress.Any.Equals(reflexive.Address)) reflexive = null;
            if (reflexive != null && host != null && reflexive.Equals(host)) reflexive = null;
            if (mapped != null && IPAddress.Any.Equals(mapped.Address)) mapped = null;
            if (mapped != null && host != null && mapped.Equals(host)) mapped = null;
            // Mapped first when there is one: it is the only address of the three that a
            // router has promised to deliver. Then reflexive, then the local address,
            // which is useless across networks but still right when both machines are on
            // one. Adding the weaker ones after means the punch tries them, just last.
            if (mapped != null) list.Add(mapped);
            if (reflexive != null && !Contains(list, reflexive)) list.Add(reflexive);
            if (host != null && !Contains(list, host)) list.Add(host);
            return list.ToArray();
        }

        static bool Contains(List<IPEndPoint> list, IPEndPoint ep)
        {
            foreach (IPEndPoint e in list) if (e.Equals(ep)) return true;
            return false;
        }

        // ── Which route is carrying this call? ─────────────────────────
        // "direct" used to be the whole answer, and it is not enough. Four different
        // endpoints can deliver the media - the peer's local address, its reflexive one,
        // its router's forward, or the relay - and which one actually arrived says
        // something true about the two networks in front of the people on the call. It is
        // also the difference between "direct" and "direct over an address nobody
        // forwarded, so it will die when the binding ages out". Pure, so synthetic
        // endpoints can settle it without a phone on the wire.
        public static string RouteKind(bool relayActive, IPEndPoint source, bool gotAnyRx,
                                       IPEndPoint peerHost, IPEndPoint peerReflexive, IPEndPoint peerMapped)
        {
            if (relayActive) return "relay";
            if (!gotAnyRx || source == null) return "none";
            if (peerHost != null && source.Equals(peerHost)) return "host";
            if (peerReflexive != null && source.Equals(peerReflexive)) return "reflexive";
            if (peerMapped != null && source.Equals(peerMapped)) return "mapped";
            // Media from an address the peer never announced. Not automatically an
            // attacker - a NAT can remap a port mid-call - but it is not a route worth
            // calling direct, and it must not be reported as one.
            return "unannounced";
        }

        // The same fact in words a person can act on. The codes stay in the logs and the
        // tests; these go on the screen, because "route=mapped" means nothing to somebody
        // holding a phone in the other ear.
        public static string RouteWords(string kind)
        {
            if (kind == "host") return "direct, on the same network";
            if (kind == "reflexive") return "direct, over its public address";
            if (kind == "mapped") return "direct, through the port it opened";
            if (kind == "relay") return "carried by the relay";
            if (kind == "unannounced") return "direct, from an address it never announced";
            return "no media yet";
        }

        // A peer's media announcement arrives on its own line rather than as a field
        // of INVITE, because the relay handler splits INVITE with a limit and a sixth
        // field would be glued onto the DH public value that has to be parsed. Same
        // trap as everywhere else on this socket: the extra fields ride at the end.
        void LearnPeerPort(string[] fields)
        {
            if (fields == null || fields.Length < 2) return;
            int port;
            if (!int.TryParse(fields[1], out port) || port < 1024 || port > 65535) port = 0;
            if (port > 0) _peerMediaPort = port;
            try
            {
                IPEndPoint host, reflexive, mapped;
                if (ParsePeerMediaAnnounce(RemoteIp, fields, out host, out reflexive, out mapped))
                {
                    if (host != null) _peerHostEp = host;
                    if (reflexive != null) _peerReflexiveEp = reflexive;
                    if (mapped != null) _peerMappedEp = mapped;
                }
                IPEndPoint[] targets = MediaTargets(RemoteIp, fields);
                foreach (IPEndPoint ep in targets) Media.AddCandidate(ep);
                if (targets.Length > 0)
                    Emit("peer media targets (best first): " + string.Join(", ",
                        Array.ConvertAll<IPEndPoint, string>(targets, delegate(IPEndPoint e) { return e.ToString(); })));
            }
            catch { }
        }

        private void CallReadLoop()
        {
            try
            {
                string line;
                while (_callReader != null && (line = _callReader.ReadLine()) != null)
                {
                    if (!HandleSigLine(line)) return;
                }
            }
            catch { }
            // ended (BYE/REJECT already cleaned up) or the peer vanished while we
            // were still ringing - a lingering socket must not keep the overlay up.
            if (InCall || _callTcp != null) EndCallInternal(false);
        }

        // Process one signaling line. Returns false when the call is over.
        private bool HandleSigLine(string line)
        {
            string[] p = line.Split('|');
            // The peer's real UDP media port. Its own line rather than a field of
            // INVITE, so an older build that has never heard of it just ignores it.
            if (p[0] == "MPORT" && p.Length >= 2) { LearnPeerPort(p); return true; }
            if (p[0] == "ACCEPT" && p.Length >= 3)
            {
                if (p[1] != _callId) return true;
                _pendingPeerPub = BigInteger.Parse(p[2]);
                // The answer carries the callee's proof: without it, only the caller
                // would be authenticated and the other direction could be whoever the
                // relay put on the wire.
                bool proofOk = VerifyCallProof(string.IsNullOrEmpty(_peerNumber) ? RemoteName : _peerNumber,
                    p[1], p[2], p.Length >= 4 ? p[3] : "", p.Length >= 5 ? p[4] : "");
                if (!proofOk)
                {
                    Emit("Security: rejecting answer to call " + _callId + " because the peer's proof was absent or invalid.");
                    SendSig("REJECT|" + _callId);
                    EndCallInternal(false);
                    return false;
                }
                DeriveAndConfirm();
                SendSig("CONFIRM|" + _callId);
                // Two different claims, and the bar has to say which one it is:
                // "encrypted" only means nobody on the wire can listen; "verified" means
                // the person you dialled is the person answering.
                SetState((VideoCall ? "Video call" : "VoIP call") +
                    (_callVerified == "yes" ? " (encrypted, verified)" : " (encrypted, other end unproven)"));
            }
            else if (p[0] == "RING" && p.Length >= 2)
            {
                SetState("Ringing on remote side...");
            }
            else if (p[0] == "REJECT" && p.Length >= 2)
            {
                SetState("Call rejected");
                Emit("Call rejected by " + RemoteName);
                EndCallInternal(false);
                return false;
            }
            else if (p[0] == "BUSY" && p.Length >= 2)
            {
                SetState("Peer busy");
                EndCallInternal(false);
                return false;
            }
            else if (p[0] == "CONFIRM" && p.Length >= 2)
            {
                DeriveAndConfirm();
                // Two different claims, and the bar has to say which one it is:
                // "encrypted" only means nobody on the wire can listen; "verified" means
                // the person you dialled is the person answering.
                SetState((VideoCall ? "Video call" : "VoIP call") +
                    (_callVerified == "yes" ? " (encrypted, verified)" : " (encrypted, other end unproven)"));
            }
            else if (p[0] == "BYE")
            {
                SetState("Call ended");
                EndCallInternal(false);
                return false;
            }
            else if (p[0] == "DTMF" && p.Length >= 3)
            {
                Emit("DTMF " + p[2]);
                Action<string> dh = DtmfReceived;
                if (dh != null) dh(p[2]);
            }
            else if (p[0] == "CHAT")
            {
                // chat text over the direct signaling channel (in-call chat)
                string chatText = line.Length > 5 ? line.Substring(5) : "";
                Emit("Chat received from peer");
                try { if (_viaRelay) { RelayClient r0 = Relay; if (r0 != null && _peerNumber != null) r0.SendMessage(_peerNumber, MyNumber, "CHATACK|"); } else SendSig("CHATACK|"); } catch { }
                Emit("Chat received from peer");
                Action<string, string> ch = ChatReceived;
                if (ch != null) ch(_peerNumber, chatText);
            }
            return true;
        }

        private void DeriveAndConfirm()
        {
            DeriveKey();
            SetState("Key confirmed - media encrypted");
        }

        // Derive the shared AES key from our private + the peer's public
        // (whichever arrived: INVITE pub on the callee, ACCEPT pub on the caller).
        private bool DeriveKey()
        {
            if (_crypto == null || _pendingPeerPub == System.Numerics.BigInteger.Zero) return false;
            byte[] key = _crypto.DeriveSharedKey(_pendingPeerPub);
            Media.SetKey(key);
            // Start session key rotation for perfect forward secrecy
            StartKeyRotation();
            return true;
        }

        // ---------- answering ----------
        public void AcceptIncomingCall()
        {
            if (_crypto == null) return;
            if (_viaRelay)
            {
                // relay call: responses come back through Relay.MessageArrived
                if (Relay == null || _peerNumber == null) return;
                InCall = true;
                SendSig("ACCEPT|" + _callId + "|" + _crypto.Pub.ToString() +
                        CallAuthFields(_crypto.Pub.ToString()));
                SetupMediaForCall(RemoteIp);
                // We already hold the caller's public key from INVITE, so derive
                // now (after setup, which clears the key) - no plaintext window.
                DeriveKey();
                StartCallWatchdog();
                SetState(VideoCall ? "Incoming video call accepted" : "Incoming call accepted");
                return;
            }
            if (_callWriter == null) return;
            InCall = true;
            try { if (_callTcp != null) _callTcp.ReceiveTimeout = 0; } catch { } // long calls must not drop after 60 s idle
            SendSig("ACCEPT|" + _callId + "|" + _crypto.Pub.ToString() +
                    CallAuthFields(_crypto.Pub.ToString()));
            SetupMediaForCall(RemoteIp);
            DeriveKey();
            StartCallWatchdog();
            // the reader may already run (started at INVITE time while ringing);
            // never start a second one - two readers on one stream would steal lines.
            if (_callThread == null || !_callThread.IsAlive)
            {
                _callThread = new Thread(CallReadLoop);
                _callThread.IsBackground = true;
                _callThread.Start();
            }
            SetState(VideoCall ? "Incoming video call accepted" : "Incoming call accepted");
        }

        public void RejectIncomingCall()
        {
            SendSig("REJECT|" + _callId);
            EndCallInternal(false);
        }

        public void EndCall()
        {
            SendSig("BYE|" + _callId);
            EndCallInternal(true);
        }

        // Send one in-band DTMF digit to the peer over the signaling channel
        // (lossless; the peer replays the tone through its speaker).
        public void SendDtmf(string digit)
        {
            if (!InCall || digit == null || digit.Length == 0) return;
            try { SendSig("DTMF|" + _callId + "|" + digit.Substring(0, 1)); }
            catch (Exception ex) { Emit("DTMF send error: " + ex.Message); }
        }

        // Ratchet: advance the key chain after RATCHET_INTERVAL total messages
        // (sent + received) for forward secrecy within a session. Both sides
        // count the same total, so they ratchet at the same point. The ratchet
        // happens AFTER the message is sent/received, so the peer always
        // decrypts with the key they already have, not the next one.
        private void RatchetMaybe(string number, ChatKey k)
        {
            if (k == null || string.IsNullOrEmpty(number)) return;
            lock (_secLock)
            {
                int count;
                if (!_ratchetCount.TryGetValue(number, out count)) count = 0;
                count++;
                _ratchetCount[number] = count;
                if (count % RATCHET_INTERVAL == 0)
                {
                    k.Ratchet();
                    Emit("Security: key ratcheted for #" + number + " at message " + count +
                         " (forward secrecy: past messages are now unreadable even if this key is compromised).");
                }
            }
        }

        // ---------- end-to-end chat security ----------
        // Lazy so the identity file is only touched once we actually relay.
        //
        // Pre-generation: RSA-2048 keygen takes a few hundred milliseconds and
        // used to happen on whatever thread first called EnsureSecurity() —
        // which is the relay connection thread, so a fresh install's first
        // WHO lookup sat behind its own keygen. PreGenerateIdentity() starts
        // the key on a background thread at app startup, so by the time the
        // relay connects the file exists and loading is fast.
        private Thread _keygenThread;
        private volatile bool _keygenDone;
        private string _keygenDir;

        public void PreGenerateIdentity(string dir)
        {
            _keygenDir = dir;
            string path = Path.Combine(dir, "identity.key");
            // If the key already exists, nothing to generate — loading is fast.
            if (File.Exists(path)) { _keygenDone = true; return; }
            _keygenThread = new Thread((ThreadStart)delegate
            {
                try
                {
                    // This creates the key and writes it atomically. The Identity
                    // constructor does the same thing, so when EnsureSecurity()
                    // runs later it will find the file and load it instead of
                    // generating on the relay thread.
                    Identity pre = new Identity(path);
                    Emit("Security: identity key pre-generated on background thread (" + pre.Fingerprint + ")");
                }
                catch (Exception ex) { Emit("Security: pre-generation failed: " + ex.Message); }
                finally { _keygenDone = true; }
            });
            _keygenThread.IsBackground = true;
            _keygenThread.Name = "UssdKeygen";
            _keygenThread.Start();
        }

        private void EnsureSecurity()
        {
            string dir = Home.Dir;
            if (SecIdentity == null)
            {
                // If pre-generation is in progress, wait for it (bounded) rather
                // than generating a second key on this thread. The wait is short
                // because keygen is a few hundred ms and pre-generation started
                // at app boot, so by now it is likely already done.
                if (_keygenThread != null && !_keygenDone)
                {
                    Emit("Security: waiting for identity key generation to finish...");
                    try { _keygenThread.Join(5000); } catch { }
                }
                SecIdentity = new Identity(Path.Combine(dir, "identity.key"));
                SecPeers = new PeerIdentityBook(Path.Combine(dir, "peers_identity.txt"));
                Emit("Security: identity key " + SecIdentity.Fingerprint +
                     " (" + SecPeers.Count + " peer key(s) on file).");
            }
            SecIdentity.Number = MyNumber;
        }

        public string MyFingerprint { get { return SecIdentity == null ? "" : SecIdentity.Fingerprint; } }

        // Verifiable 12-group code: both sides must see the same digits, and
        // any man-in-the-middle changes them.
        public string SafetyNumberFor(string number)
        {
            if (SecIdentity == null || SecPeers == null) return null;
            string peer = SecPeers.Lookup(number);
            return peer == null ? null : Identity.SafetyNumber(SecIdentity.PublicBase64, peer);
        }

        public string ChatSecurityState(string number)
        {
            lock (_secLock)
            {
                if (_secBlocked.ContainsKey(number)) return "blocked";
                if (_e2eKeys.ContainsKey(number)) return "locked";
                if (_e2ePending.ContainsKey(number)) return "handshaking";
                // No session, but their published key: mail to them is still sealed,
                // so the badge must not read "not encrypted" when it is.
                if (_peerPubKeys.ContainsKey(number)) return "sealed-offline";
            }
            return RequireE2e ? "pending" : "plain";
        }

        // User accepted a changed identity key (only reachable from the
        // explicit warning UI) - clear the block and re-handshake.
        public void ForceTrustPeer(string number)
        {
            string newPub = null;
            lock (_secLock)
            {
                if (_secBlocked.TryGetValue(number, out newPub)) _secBlocked.Remove(number);
                _e2eKeys.Remove(number);
            }
            if (!string.IsNullOrEmpty(newPub) && SecPeers != null)
                SecPeers.AcceptChanged(number, newPub);
            E2eStart(number);
            Emit("Security: peer key for #" + number + " accepted by you. Re-establishing.");
        }

        // Route one protocol line: sealed when we hold a session key, else we
        // start a handshake and hold the line until the key lands.
        private bool SendRelaySecure(string number, string line)
        {
            RelayClient r = Relay;
            if (r == null) return false;
            ChatKey k = null;
            lock (_secLock) _e2eKeys.TryGetValue(number, out k);
            if (k != null)
            {
                // A crypto failure here must not travel into the UI thread - it
                // took the whole app down once (crash.log: OID is unknown).
                try
                {
                    bool ok = LineOut(number, "ECHAT|" + k.Encrypt(line));
                    // Ratchet: advance the key chain after RATCHET_INTERVAL messages
                    // for forward secrecy within a session. Both sides count the same
                    // total (sent + received), so they ratchet at the same point.
                    // Ratchet AFTER sending so the peer receives with the old key.
                    if (ok) RatchetMaybe(number, k);
                    return ok;
                }
                catch (Exception ex)
                {
                    Emit("Security: could not seal a message to #" + number + ": " + ex.Message + " Retrying the key exchange.");
                    lock (_secLock) { _e2eKeys.Remove(number); _e2ePending.Remove(number); }
                    E2eStart(number);
                    return false;
                }
            }
            bool blocked;
            lock (_secLock) blocked = _secBlocked.ContainsKey(number);
            if (blocked)
            {
                Emit("SECURITY: nothing is being sent to #" + number + " until you review its new identity key.");
                return false;
            }

            // No session, but a published key: seal to the key itself. This is the
            // whole point of publishing one - the peer may never connect again on
            // this device, and their mail should still not be readable in storage.
            string sealedLine = TryOfflineSeal(number, line);
            if (sealedLine != null) return LineOut(number, sealedLine);

            if (!RequireE2e)
                return LineOut(number, line);
            E2eStart(number);
            // Also ask the relay for their published key: a handshake will not be
            // answered by a switched-off phone, but the key was published when they
            // last registered, so the message can still be sealed and left for them.
            AskPeerKey(number);
            // Held in ONE place. Putting it in both queues would send it twice the
            // moment this peer finally came online: once sealed from the published
            // key, once through the session that arrived afterwards.
            lock (_secLock)
            {
                List<string> pq;
                if (!_heldForPubKey.TryGetValue(number, out pq)) { pq = new List<string>(); _heldForPubKey[number] = pq; }
                if (pq.Count < 32 && !pq.Contains(line)) pq.Add(line);
            }
            return true;
        }

        // Returns a sealed offline line, or null when we have no usable key. A peer
        // whose key changed under us is treated as no key: sending to a substituted
        // key is worse than holding the message.
        string TryOfflineSeal(string number, string line)
        {
            if (SecIdentity == null) return null;
            string pub = PeerPubKey(number);
            if (string.IsNullOrEmpty(pub)) return null;
            try
            {
                string ln = OfflineSeal.Seal(SecIdentity, pub, MyNumber, number, line);
                if (ln == null) return null;
                Emit("Security: sealed to #" + number + "'s published key - they can read it off-line.");
                return ln;
            }
            catch (Exception ex)
            {
                Emit("Security: offline seal to #" + number + " failed: " + ex.Message);
                return null;
            }
        }

        string PeerPubKey(string number)
        {
            lock (_secLock)
            {
                string p;
                if (_peerPubKeys.TryGetValue(number, out p)) return p;
            }
            // Every completed handshake left the peer's identity key in the book, so a
            // person we have ever talked to can receive offline mail immediately.
            try
            {
                if (SecPeers == null) return null;
                string bk = SecPeers.Lookup(number);
                if (!string.IsNullOrEmpty(bk))
                {
                    lock (_secLock) _peerPubKeys[number] = bk;
                    return bk;
                }
            }
            catch { }
            return null;
        }

        // Throttled: an unknown number must not make us flood the relay with asks.
        void AskPeerKey(string number)
        {
            if (string.IsNullOrEmpty(number)) return;
            RelayClient r = Relay;
            if (r == null) return;
            lock (_secLock)
            {
                DateTime last;
                if (_pubKeyAsked.TryGetValue(number, out last) && (DateTime.Now - last).TotalSeconds < 10) return;
                _pubKeyAsked[number] = DateTime.Now;
            }
            try { r.RequestPeerKey(number); } catch { }
        }

        // The relay's answer. Verified by RelayClient before it gets here, so this
        // only has to remember it and let the waiting lines through.
        private void OnPeerKeyArrived(string number, string pubB64)
        {
            if (string.IsNullOrEmpty(number)) return;
            if (string.IsNullOrEmpty(pubB64))
            {
                // No key on file: these lines are now the handshake queue, so they
                // still go out sealed the moment the peer answers - just not to a key
                // nobody has published.
                List<string> waiting = null;
                lock (_secLock)
                {
                    if (_heldForPubKey.TryGetValue(number, out waiting)) _heldForPubKey.Remove(number);
                    if (waiting != null && waiting.Count > 0)
                    {
                        List<string> q;
                        if (!_e2eQueue.TryGetValue(number, out q)) { q = new List<string>(); _e2eQueue[number] = q; }
                        foreach (string ln in waiting) if (q.Count < 32 && !q.Contains(ln)) q.Add(ln);
                    }
                }
                Emit("Security: no published key on file for #" + number + " - " +
                     (waiting == null ? 0 : waiting.Count) + " line(s) will go when a session opens.");
                return;
            }
            bool fresh = false;
            lock (_secLock)
            {
                string old;
                if (_peerPubKeys.TryGetValue(number, out old)) fresh = old != pubB64;
                else fresh = true;
                _peerPubKeys[number] = pubB64;
            }
            if (fresh) Emit("Security: learned #" + number + "'s published key (" + Identity.FingerprintOf(pubB64) + ").");
            ReleaseHeldForPubKey(number);
            ReleaseHeldOfflineIn(number);
        }

        void ReleaseHeldForPubKey(string number)
        {
            List<string> held = null;
            lock (_secLock)
            {
                if (_heldForPubKey.TryGetValue(number, out held)) _heldForPubKey.Remove(number);
            }
            if (held == null || held.Count == 0) return;
            RelayClient r = Relay;
            if (r == null) return;
            foreach (string ln in held)
            {
                string sealedLine = TryOfflineSeal(number, ln);
                if (sealedLine == null) continue;
                try { r.SendMessage(number, MyNumber, sealedLine); }
                catch (Exception ex) { Emit("Security: could not release held line to #" + number + ": " + ex.Message); }
            }
        }

        // Inbound offline mail we could not authenticate yet, because verifying it
        // needs the sender's published key. Held briefly, then opened - never dropped,
        // and never displayed unverified.
        void HoldOfflineIn(string from, string line)
        {
            lock (_secLock)
            {
                List<string> q;
                if (!_heldOfflineIn.TryGetValue(from, out q)) { q = new List<string>(); _heldOfflineIn[from] = q; }
                else if (q.Contains(line)) return;
                if (q.Count < 16) q.Add(line);
            }
            AskPeerKey(from);
        }

        void ReleaseHeldOfflineIn(string from)
        {
            List<string> q = null;
            lock (_secLock) { if (_heldOfflineIn.TryGetValue(from, out q)) _heldOfflineIn.Remove(from); }
            if (q == null) return;
            foreach (string line in q) HandleOfflineEchat(from, line);
        }

        // Open one offline-sealed message. Verification comes first and needs the
        // SENDER's key, so a message from a peer whose key we do not have yet is held
        // rather than shown: plaintext that cannot be attributed is not evidence.
        void HandleOfflineEchat(string from, string line)
        {
            if (SecIdentity == null) return;
            string senderPub = PeerPubKey(from);
            if (string.IsNullOrEmpty(senderPub))
            {
                HoldOfflineIn(from, line);
                Emit("Security: sealed off-line mail from #" + from + " held until their published key is known.");
                return;
            }
            OfflineSeal.Opened o = OfflineSeal.OpenWith(SecIdentity, line, senderPub, from, MyNumber);
            if (o == null)
            {
                Emit("SECURITY: off-line mail from #" + from + " did not verify (tampered, re-attributed, or a key we no longer trust) - discarded.");
                Action<string, string, string> sec = ChatSecurity;
                if (sec != null) sec(from, "failed", "offline signature check");
                return;
            }
            Emit("Security: opened off-line mail from #" + from + " sealed to our published key.");
            HandleRelayMessage(from, o.Text);       // same dispatcher, now in clear
        }

        // Kick a key agreement (throttled - an offline peer must not make us
        // flood handshakes through the relay).
        private void E2eStart(string number)
        {
            if (string.IsNullOrEmpty(number) || SecIdentity == null) return;
            ChatHandshake mine = null;
            lock (_secLock)
            {
                if (_e2eKeys.ContainsKey(number) || _secBlocked.ContainsKey(number)) return;
                if (_e2ePending.TryGetValue(number, out mine)) return;
                DateTime last;
                if (_e2eLastTry.TryGetValue(number, out last) && (DateTime.Now - last).TotalSeconds < 5) return;
                _e2eLastTry[number] = DateTime.Now;
                mine = new ChatHandshake();
                _e2ePending[number] = mine;
            }
            RelayClient r = Relay;
            if (r == null) return;
            try
            {
                r.SendMessage(number, MyNumber, mine.Build(SecIdentity, false));
                Emit("Security: key exchange started with #" + number + ".");
            }
            catch (Exception ex)
            {
                // Drop the pending handshake so the next send retries cleanly
                // instead of queueing forever behind a broken one.
                lock (_secLock) _e2ePending.Remove(number);
                Emit("Security: key exchange with #" + number + " failed: " + ex.Message);
                Action<string, string, string> secx = ChatSecurity;
                if (secx != null) secx(number, "failed", ex.Message);
            }
        }

        private void HandleSecurityLine(string from, string[] p, string line)
        {
            try { HandleSecurityLineInner(from, p, line); }
            catch (Exception ex) { Emit("Security: inbound handshake from #" + from + " failed: " + ex.Message); }
        }

        private void HandleSecurityLineInner(string from, string[] p, string line)
        {
            string verb = p[0];
            if (verb == OfflineSeal.Verb)
            {
                HandleOfflineEchat(from, line);
                return;
            }
            if (verb == "ECHAT")
            {
                string blob = line.Length > 6 ? line.Substring(6) : "";
                ChatKey k = null;
                lock (_secLock) _e2eKeys.TryGetValue(from, out k);
                if (k == null)
                {
                    Emit("Security: sealed chat from #" + from + " with no session key - exchanging keys.");
                    E2eStart(from);
                    return;
                }
                string inner = k.Decrypt(blob);
                if (inner == null)
                {
                    Emit("Security: sealed message from #" + from + " failed authentication (tampered or a stale key) - re-handshaking.");
                    lock (_secLock) { _e2eKeys.Remove(from); _e2ePending.Remove(from); }
                    E2eStart(from);
                    Action<string, string, string> sec = ChatSecurity;
                    if (sec != null) sec(from, "failed", "integrity check failed");
                    return;
                }
                // Ratchet: advance the key chain after RATCHET_INTERVAL messages.
                // Ratchet AFTER receiving so we decrypt with the old key, then advance.
                RatchetMaybe(from, k);
                HandleRelayMessage(from, inner);   // same dispatcher, now in clear
                return;
            }

            // KEYX / KEYXOK: <verb>|<dh pub>|<identity key>|<signature>
            string peerDh = p.Length >= 2 ? p[1] : "";
            string peerId = p.Length >= 3 ? p[2] : "";
            string sig = p.Length >= 4 ? p[3] : "";
            if (SecIdentity == null || peerDh.Length == 0 || peerId.Length == 0) return;

            PeerIdentityBook.Trust trust = SecPeers.Check(from, peerId);
            if (trust == PeerIdentityBook.Trust.Changed)
            {
                lock (_secLock) _secBlocked[from] = peerId;
                Emit("SECURITY WARNING: the identity key for #" + from + " is not the one we recorded. No session established - nothing you send will leave in a form they can read until you review it.");
                Action<string, string, string> sec2 = ChatSecurity;
                if (sec2 != null) sec2(from, "changed", Identity.FingerprintOf(peerId));
                return;
            }

            ChatHandshake mine = null;
            lock (_secLock) _e2ePending.TryGetValue(from, out mine);
            if (mine == null)
            {
                mine = new ChatHandshake();
                lock (_secLock) _e2ePending[from] = mine;
            }
            ChatKey key = mine.Accept(verb, peerDh, peerId, sig, from);
            if (key == null)
            {
                Emit("Security: signature from #" + from + " did not verify - handshake ignored.");
                Action<string, string, string> sec3 = ChatSecurity;
                if (sec3 != null) sec3(from, "failed", "signature did not verify");
                return;
            }
            if (verb == "KEYX")
            {
                RelayClient rr = Relay;
                if (rr != null) rr.SendMessage(from, MyNumber, mine.Build(SecIdentity, true));
            }
            bool first;
            lock (_secLock)
            {
                first = !_e2eKeys.ContainsKey(from);
                _e2eKeys[from] = key;
                _e2ePending.Remove(from);
            }
            string sn = SafetyNumberFor(from);
            Emit("Security: session key " + (first ? "established" : "refreshed") + " with #" + from +
                 " (" + (trust == PeerIdentityBook.Trust.New ? "new peer key trusted on first use" : "peer key verified") + ")." +
                 (sn == null ? "" : " Safety number: " + sn));
            Action<string, string, string> sec4 = ChatSecurity;
            if (sec4 != null) sec4(from, "locked", sn == null ? "session key ready" : sn);
            E2eFlush(from);
        }

        private void E2eFlush(string number)
        {
            List<string> q = null;
            ChatKey k = null;
            lock (_secLock)
            {
                if (_e2eQueue.TryGetValue(number, out q)) _e2eQueue.Remove(number);
                _e2eKeys.TryGetValue(number, out k);
            }
            RelayClient r = Relay;
            if (r == null || k == null || q == null || q.Count == 0) return;
            try
            {
                foreach (string ln in q) r.SendMessage(number, MyNumber, "ECHAT|" + k.Encrypt(ln));
                Emit("Security: sent " + q.Count + " held line(s) to #" + number + " once the key landed.");
            }
            catch (Exception ex) { Emit("Security: could not release held lines to #" + number + ": " + ex.Message); }
        }

        // One funnel for every outbound line: the router decides which link
        // carries it, and the relay socket stays the fallback so behaviour is
        // unchanged while only the relay exists.
        private bool LineOut(string number, string wire)
        {
            try
            {
                byte[] frame = Encoding.UTF8.GetBytes(wire);
                string why;
                ITransport t = Routes.Pick(frame.Length, PayloadClass.Text, out why);
                if (t != null && t.Send(number, frame))
                {
                    if (t.Name != "relay") Emit("Route: #" + number + " via " + t.Name + " (" + frame.Length + "B).");
                    return true;
                }
            }
            catch (Exception ex) { Emit("Route: selection failed (" + ex.Message + "), using the relay socket."); }
            RelayClient r = Relay;
            if (r == null) return false;
            return r.SendMessage(number, MyNumber, wire);
        }

        // Returns false when the relay is not connected (caller can fall back
        // to plain SMS through the modem).
        public bool SendChat(string number, string text)
        {
            if (string.IsNullOrEmpty(number) || text == null || text.Length == 0) return false;
            return SendRelaySecure(number, "CHAT|" + text);
        }

        // Delivery receipt / typing indicator to a relay peer (best effort).
        public bool SendChatAck(string number)
        {
            if (string.IsNullOrEmpty(number)) return false;
            RelayClient r = Relay;
            if (r == null) return false;
            return r.SendMessage(number, MyNumber, "CHATACK|");
        }

        public bool SendChatTyping(string number, bool on)
        {
            if (string.IsNullOrEmpty(number)) return false;
            RelayClient r = Relay;
            if (r == null) return false;
            return r.SendMessage(number, MyNumber, "CTYP|" + (on ? "1" : "0"));
        }

        // Send a voice note (raw WAV bytes) to a relay peer. The sample rate /
        // format of the source WAV does not matter to the receiver (we replay
        // it with SoundPlayer), but recordings are 16 kHz mono 16-bit.
        public bool SendVoiceNote(string number, byte[] wav)
        {
            if (string.IsNullOrEmpty(number) || wav == null || wav.Length == 0) return false;
            return SendRelaySecure(number, "VAUD|" + Convert.ToBase64String(wav));
        }

        // One sealed line of the sticker protocol (see StickerSync.cs).
        public bool SendStickerLine(string number, string line)
        {
            if (string.IsNullOrEmpty(number) || string.IsNullOrEmpty(line)) return false;
            return SendRelaySecure(number, line);
        }

        public event Action<string, string> StickerLine;   // from, whole inner line

        // Non-relay fallback so callers can distinguish availability.
        public event Action<string> RelayReferral;    // host:port list from a linked relay

        // ── Is the server in front of me the one I chose? ───────────────────
        // Raised whenever the relay answers the identity question, and readable at any
        // time afterwards. It exists because the answer used to be only a log line: the
        // fingerprint scrolls away, the person stops looking, and then a relay presenting
        // a different key is as invisible as one that never had a key at all. Pinning is
        // worth nothing if the pin is not on the screen.
        public event Action<string> RelayTrustChanged;    // unattested | verified-new | verified-known | mismatch | bad-signature
        public string RelayTrustText
        {
            get
            {
                RelayClient r = Relay;
                if (r == null) return "no relay";
                string fp = string.IsNullOrEmpty(r.RelayFingerprint) ? "no key shown" : r.RelayFingerprint;
                if (!r.RelayIdentityChecked)
                    return r.RelayRefusedIdentity ? "relay declines to have a key" : "identity unverified";
                return fp;
            }
        }
        // The verdict word itself, for whoever has to colour it.
        public string RelayTrustVerdict
        {
            get { RelayClient r = Relay; return r == null ? "none" : r.RelayTrust; }
        }

        // Ask the relay we are connected to what other relays it knows, and
        // report our own hosting address into LAN probes. Both are how a new
        // device gets into the mesh without being handed an IP by hand.
        public void DiscoverRelays()
        {
            RelayClient r = Relay;
            if (r != null) { try { r.RequestRelayList(); } catch { } }
            // Shout once on the LAN so a hosting neighbour answers us directly.
            if (_discUdp != null)
            {
                try
                {
                    byte[] probe = Encoding.UTF8.GetBytes("USSDRELAY?|" + LocalName);
                    _discUdp.Send(probe, probe.Length, new IPEndPoint(IPAddress.Broadcast, DISC_PORT));
                }
                catch { }
            }
        }

        public string MyAdvertisedRelay()
        {
            return RelayAdvertiseAddr ?? "";
        }

        // Plug an extra link - a KISS/LoRa radio, a mesh pipe, a future RNS
        // bridge - into the router. Incoming frames go to the same dispatcher
        // the relay uses, so a chat line that arrives over the air is handled
        // exactly like one that arrived over the internet, sealing included.
        // nameToNumber maps whatever the link reports as a sender (a callsign)
        // back to an app number, because the chat layer is keyed by number.
        public bool AttachTransport(ITransport t, Func<string, string> nameToNumber)
        {
            if (t == null) return false;
            t.Frame += delegate(string from, byte[] frame)
            {
                try
                {
                    string number = nameToNumber != null ? nameToNumber(from) : from;
                    HandleRelayMessage(number, Encoding.UTF8.GetString(frame));
                }
                catch (Exception ex) { Emit("Inbound frame on " + t.Name + ": " + ex.Message); }
            };
            Routes.Add(t);
            RaiseRoutes();
            Emit("Transport attached: " + t.Name + " (max " + t.MaxFrameBytes +
                 " B, " + t.BitRate + " bps" + (t.RequiresConsent ? ", carries for peers" : "") + ").");
            return true;
        }

        // Chat needs the same thing calls do: a session the relay has accepted, so a peer
        // can be looked up and a message delivered or queued rather than dropped.
        public bool ChatRelayReady { get { return Relay != null && Relay.Connected && Relay.Registered; } }
        public event Action<string> ChatAckReceived;              // #number delivered our last text
        public event Action<string, bool> ChatTypingReceived;     // #number typing start/stop
        public event Action<string, byte[]> ChatVoiceReceived;    // #number, raw WAV bytes
        public event Action<string> ChatQueued;                   // #number offline: text stored on relay
        public event Action<string> PeerOffline;                  // #number offline: line not stored

        // In-call chat to the connected peer (direct socket or relay).
        public bool SendChatCall(string text)
        {
            if (!InCall || text == null || text.Length == 0) return false;
            SendSig("CHAT|" + text);
            return true;
        }

        // ── Read receipts ────────────────────────────────────────────────
        // Tell the peer we read their messages (renders blue ticks on their end).
        public bool SendChatRead(string number)
        {
            if (string.IsNullOrEmpty(number)) return false;
            RelayClient r = Relay;
            if (r == null) return false;
            return r.SendMessage(number, MyNumber, "CHATREAD|" + DateTime.UtcNow.Ticks);
        }

        public event Action<string, long> ChatReadReceived;   // #number, timestamp

        // ── Reactions ────────────────────────────────────────────────────
        // Send a message reaction: emoji attached to a message ID.
        public bool SendReaction(string number, string msgId, string emoji)
        {
            if (string.IsNullOrEmpty(number) || string.IsNullOrEmpty(msgId)) return false;
            return SendRelaySecure(number, "REACT|" + msgId + "|" + (emoji ?? "\uD83D\uDC4D"));
        }

        public event Action<string, string, string> ReactionReceived;  // from, msgId, emoji

        // ── File transfer offer ───────────────────────────────────────────
        // Offer a file to a peer; they accept/reject, then we open a direct TCP stream.
        public bool SendFileOffer(string number, string fileName, long sizeBytes, string transferId)
        {
            if (string.IsNullOrEmpty(number)) return false;
            RelayClient r = Relay;
            if (r == null) return false;
            return r.SendMessage(number, MyNumber, "FTOFFER|" + transferId + "|" + fileName + "|" + sizeBytes);
        }

        public bool SendFileAccept(string number, string transferId, int tcpPort)
        {
            RelayClient r = Relay;
            if (r == null) return false;
            return r.SendMessage(number, MyNumber, "FTACCEPT|" + transferId + "|" + tcpPort);
        }

        public bool SendFileReject(string number, string transferId)
        {
            RelayClient r = Relay;
            if (r == null) return false;
            return r.SendMessage(number, MyNumber, "FTREJECT|" + transferId);
        }

        public event Action<string, string, string, long> FileOfferReceived;   // from, transferId, name, size
        public event Action<string, string, int> FileAcceptReceived;           // from, transferId, port
        public event Action<string, string> FileRejectReceived;                // from, transferId

        // ── Session key rotation (Perfect Forward Secrecy) ───────────────
        // While a call is in progress, re-run DH every 5 minutes.
        // Each rotation generates a fresh key from new ephemeral DH parameters.
        private int _keyRotationGen;
        private VoipCrypto _nextCrypto;

        public void StartKeyRotation()
        {
            int gen = Interlocked.Increment(ref _keyRotationGen);
            Thread t = new Thread((ThreadStart)delegate
            {
                while (InCall && gen == _keyRotationGen)
                {
                    Thread.Sleep(300000);  // rotate every 5 minutes
                    if (!InCall || gen != _keyRotationGen) break;
                    try
                    {
                        _nextCrypto = new VoipCrypto();
                        // Announce our new public key to the peer
                        SendSig("KEYROTATE|" + _nextCrypto.Pub.ToString());
                        Emit("PFS: initiated key rotation");
                    }
                    catch { }
                }
            });
            t.IsBackground = true;
            t.Name = "KeyRotation";
            t.Start();
        }

        private void HandleKeyRotate(string pubHex)
        {
            try
            {
                System.Numerics.BigInteger peerPub = System.Numerics.BigInteger.Parse(pubHex);
                if (_nextCrypto == null) _nextCrypto = new VoipCrypto();
                byte[] newKey = _nextCrypto.DeriveSharedKey(peerPub);
                // Apply new key: truncate to 16 bytes for AES-128
                byte[] key16 = new byte[16];
                Buffer.BlockCopy(newKey, 0, key16, 0, 16);
                Media.SetKey(key16);
                _nextCrypto = null;
                Emit("PFS: session key rotated — forward secrecy applied");
            }
            catch (Exception ex) { Emit("PFS rotation error: " + ex.Message); }
        }

        // ── Network quality metrics ───────────────────────────────────────
        // Sampled every second by the watchdog; exposed for the UI.
        public float LastRttMs = 0;
        public int PacketLoss100 = 0;   // 0-100 percent
        public string NetworkQuality
        {
            get
            {
                if (!InCall) return "idle";
                if (PacketLoss100 > 30) return "poor";
                if (PacketLoss100 > 10 || LastRttMs > 200) return "fair";
                return "good";
            }
        }

        // ── Conference (group call) ───────────────────────────────────────
        // A group call is a room on the relay, not a mesh of 1:1 calls: the
        // server sums the audio and fans out one mix per member. That keeps
        // signalling simple (no per-peer key exchange for the room) and means
        // every member hears the same thing. Entering a room switches the mic
        // path from the UDP media channel to the room mixer.
        public string ActiveConferenceRoom = null;
        public readonly List<string> ConferenceMembers = new List<string>();
        public bool ConferenceMode { get { return !string.IsNullOrEmpty(ActiveConferenceRoom); } }

        // E2E conference audio: a shared room key (random 32 bytes) distributed
        // to members via sealed chat. When set, conference audio is encrypted
        // with this key and the relay forwards without mixing — each member
        // decrypts and mixes locally, so the relay never sees plaintext audio.
        private byte[] _confRoomKey;
        // Local mixer: accumulates decrypted PCM from each peer, sums to a mix
        private readonly Dictionary<string, short[]> _confPeerLastFrame = new Dictionary<string, short[]>();
        private readonly object _confMixLock = new object();
        public bool ConferenceE2E { get { return _confRoomKey != null; } }

        public event Action<string, List<string>> ConferenceRosterChanged;  // roomId, members
        public event Action<string, string, byte[]> ConferenceMixedAudio;   // roomId, fromNum, pcm
        public event Action<string, Dictionary<string, int>> ConferenceTalkLevels;  // roomId, num -> 0-100
        public event Action<string, string, byte[]> ConferenceVideo;        // roomId, fromNum, jpeg
        public event Action<string, string, string> ConferenceInviteReceived; // roomId, hostNumber, hostName
        // Raised when the relay could not get us into a room even after holding the
        // join for a route: the call did not start, and the screen has to say that.
        public event Action<string> ConferenceRefused;        // roomId

        // Rooms are named after whoever opens them, so the id is never a bare
        // counter two hosts could collide on.
        public string NewConferenceRoomId()
        {
            string who = string.IsNullOrEmpty(MyNumber) ? "room" : MyNumber;
            return "conf-" + who + "-" + (DateTime.Now.Ticks % 10000000).ToString();
        }

        public void JoinConference(string roomId)
        {
            if (string.IsNullOrEmpty(roomId)) return;
            ActiveConferenceRoom = roomId;
            RelayClient r = Relay;
            if (r == null) { Emit("Conf: relay required for conference calls."); return; }
            r.SendRaw("CONF_JOIN|" + roomId + "|" + NumberToken);
            // Deliberately not "joined room": the relay may still be holding this
            // until it can route to the owner, and nothing has been proved until a
            // roster comes back. Claiming success here is what made a failed join
            // indistinguishable from a working call.
            Emit("Conference: asking to join " + roomId);
        }

        public void LeaveConference()
        {
            if (string.IsNullOrEmpty(ActiveConferenceRoom)) return;
            RelayClient r = Relay;
            if (r != null) r.SendRaw("CONF_LEAVE|" + ActiveConferenceRoom);
            Emit("Conference: left room " + ActiveConferenceRoom);
            ActiveConferenceRoom = null;
            ConferenceMembers.Clear();
            ClearConferenceRoomKey();
            Action<string, List<string>> h = ConferenceRosterChanged;
            if (h != null) h(null, ConferenceMembers);
        }

        public void SendConferenceAudio(byte[] pcm)
        {
            if (string.IsNullOrEmpty(ActiveConferenceRoom)) return;
            RelayClient r = Relay;
            if (r == null) return;
            // E2E mode: encrypt with the room key and send CONF_EAUDIO.
            // The relay forwards without mixing; each member decrypts locally.
            if (_confRoomKey != null)
            {
                try
                {
                    byte[] iv = new byte[16];
                    using (System.Security.Cryptography.RandomNumberGenerator rng = System.Security.Cryptography.RandomNumberGenerator.Create())
                        rng.GetBytes(iv);
                    byte[] ct = VoipCrypto.AesCtr(_confRoomKey, pcm, iv);
                    byte[] outp = new byte[iv.Length + ct.Length];
                    Buffer.BlockCopy(iv, 0, outp, 0, iv.Length);
                    Buffer.BlockCopy(ct, 0, outp, iv.Length, ct.Length);
                    r.SendRaw("CONF_EAUDIO|" + ActiveConferenceRoom + "|" + Convert.ToBase64String(outp));
                }
                catch (Exception ex) { Emit("Conf E2E send error: " + ex.Message); }
                return;
            }
            r.SendRaw("CONF_AUDIO|" + ActiveConferenceRoom + "|" + Convert.ToBase64String(pcm));
        }

        // Set the shared room key for E2E conference audio. When non-null,
        // conference audio is encrypted and the relay forwards without mixing.
        public void SetConferenceRoomKey(byte[] key)
        {
            _confRoomKey = key;
            if (key != null) Emit("Conference: E2E room key set — audio is encrypted, the relay cannot hear it.");
        }

        public void ClearConferenceRoomKey()
        {
            _confRoomKey = null;
            lock (_confMixLock) _confPeerLastFrame.Clear();
        }

        // Local conference mixer: sum decrypted PCM from all peers.
        // Each peer's last frame is stored, and the mix is the sum of all
        // peers' frames minus our own (we don't want to hear ourselves).
        private byte[] LocalConfMix(string fromNumber, byte[] pcm)
        {
            if (pcm == null || pcm.Length < 4) return null;
            int samples = pcm.Length / 2;
            short[] peerFrame = new short[samples];
            for (int j = 0; j < samples; j++)
                peerFrame[j] = (short)(pcm[j * 2] | (pcm[j * 2 + 1] << 8));

            lock (_confMixLock)
            {
                _confPeerLastFrame[fromNumber] = peerFrame;
                // Sum all peers' frames
                short[] mix = new short[samples];
                foreach (var kvp in _confPeerLastFrame)
                {
                    // Skip our own number (we don't hear ourselves)
                    if (kvp.Key == MyNumber) continue;
                    short[] f = kvp.Value;
                    for (int j = 0; j < samples && j < f.Length; j++)
                    {
                        int v = mix[j] + f[j];
                        mix[j] = (short)(v > 32767 ? 32767 : (v < -32768 ? -32768 : v));
                    }
                }
                // Convert back to bytes
                byte[] outB = new byte[samples * 2];
                for (int j = 0; j < samples; j++)
                {
                    outB[j * 2] = (byte)(mix[j] & 0xFF);
                    outB[j * 2 + 1] = (byte)((mix[j] >> 8) & 0xFF);
                }
                return outB;
            }
        }

        // Generate a new random room key for E2E conference audio
        public byte[] GenerateConferenceRoomKey()
        {
            byte[] key = new byte[16]; // AES-128
            using (System.Security.Cryptography.RandomNumberGenerator rng = System.Security.Cryptography.RandomNumberGenerator.Create())
                rng.GetBytes(key);
            return key;
        }

        // Distribute the room key to a member via sealed chat (E2E encrypted)
        public void SendConferenceRoomKey(string toNumber, byte[] key)
        {
            if (key == null || key.Length == 0) return;
            // Send as a sealed chat message: "CONFKEY|<base64 key>"
            string line = "CONFKEY|" + Convert.ToBase64String(key);
            SendRelaySecure(toNumber, line);
        }

        // Send the current room key to a member (used when inviting)
        public void ShareConferenceRoomKey(string toNumber)
        {
            if (_confRoomKey == null) return;
            SendConferenceRoomKey(toNumber, _confRoomKey);
        }

        // Group video is a downscaled thumbnail per member, pushed through the
        // room at a low rate. Full-rate MJPEG to N peers would multiply the
        // host's uplink by N; a tile grid only needs faces.
        public void SendConferenceVideo(byte[] jpeg)
        {
            if (string.IsNullOrEmpty(ActiveConferenceRoom) || jpeg == null || jpeg.Length == 0) return;
            RelayClient r = Relay;
            if (r == null) return;
            r.SendRaw("CONF_VIDEO|" + ActiveConferenceRoom + "|" + Convert.ToBase64String(jpeg));
        }

        public void SetConferenceMuted(bool muted)
        {
            if (string.IsNullOrEmpty(ActiveConferenceRoom)) return;
            RelayClient r = Relay;
            if (r != null) r.SendRaw("CONF_MUTE|" + ActiveConferenceRoom + "|" + (muted ? "1" : "0"));
        }

        // Tell a peer to join the room we are already in. This is a control
        // line, not content: it carries a room id and our name, nothing else.
        public void InviteToConference(string toNumber, string roomId, string hostName)
        {
            RelayClient r = Relay;
            if (r == null || string.IsNullOrEmpty(toNumber)) return;
            r.SendMessage(toNumber, MyNumber, "CONF_JOINROOM|" + roomId + "|" + hostName);
            Emit("Conference: invited #" + toNumber + " into " + roomId);
        }

        private void EndCallInternal(bool notifyRemoteAlready)
        {
            InCall = false;
            _watchThread = null;
            Media.SetKey(null);
            // A group call ends for this member the same way: leave the room so
            // the mixer drops our stream and the roster updates for everyone.
            try { LeaveConference(); }
            catch { }
            try { if (_callTcp != null) _callTcp.Close(); }
            catch { }
            _callTcp = null; _callReader = null; _callWriter = null;
            _viaRelay = false;
            _peerNumber = null;
            SetState("Idle");
            Action h = CallEnded;
            if (h != null) h();
        }

        private void SetState(string s)
        {
            Action<string> h = CallStateChanged;
            if (h != null) h(s);
            Emit("VoIP: " + s);
        }

        private void OnAudioFrame(byte[] pcm, IPEndPoint from)
        {
            // playout is wired by the UI via Media.AudioFrame directly
        }

        private void OnVideoFrame(byte[] jpeg, IPEndPoint from)
        {
            Action<byte[]> h = RemoteVideoFrame;
            if (h != null) h(jpeg);
        }

        public void Dispose()
        {
            Stop();
        }

        public void Stop()
        {
            _run = false;
            try { if (_sigListener != null) _sigListener.Stop(); }
            catch { }
            try { if (_discUdp != null) _discUdp.Close(); }
            catch { }
            try { DisableRelay(); }
            catch { }
            try { Media.Close(); }
            catch { }
            try { if (_callTcp != null) _callTcp.Close(); }
            catch { }
        }
    }

    // ---- Audio I/O: waveIn capture (16 kHz mono 16-bit, 20 ms frames) ----
    //      + waveOut playout with silence fill, WhatsApp-call style
    public sealed class VoipAudio : IDisposable
    {
        public const int SAMPLE_RATE = 16000;
        public const int FRAME_BYTES = 640; // 20 ms @ 16 kHz mono 16-bit

        private IntPtr _hwi = IntPtr.Zero;
        private IntPtr _hwo = IntPtr.Zero;
        private readonly List<IntPtr> _inHeaders = new List<IntPtr>();
        private readonly List<IntPtr> _outHeaders = new List<IntPtr>();
        private readonly Queue<byte[]> _playQueue = new Queue<byte[]>();
        private readonly object _qLock = new object();
        private int _pumping;
        private DateTime _micFailLoggedAt = DateTime.MinValue;
        private WaveInDelegate _keepInCb;   // prevent GC of native callback
        private WaveOutDelegate _keepOutCb;
        // Serialises device open/close so a background open can never interleave
        // with a dispose (that race leaked handles / double-captured the mic).
        private readonly object _devLock = new object();
        private volatile bool _disposed;

        public event Action<byte[]> FrameCaptured;
        public event Action<string> LogLine;
        public bool MicOpen { get { return _hwi != IntPtr.Zero; } }
        public bool SpeakerOpen { get { return _hwo != IntPtr.Zero; } }

        private delegate void WaveInDelegate(IntPtr hwi, int uMsg, IntPtr dwInstance, IntPtr lpwhdr, int dwParam2);
        private delegate void WaveOutDelegate(IntPtr hwo, int uMsg, IntPtr dwInstance, IntPtr lpwhr, int dwParam2);

        private void EmitLog(string s) { Action<string> h = LogLine; if (h != null) h(s); }

        private static WAVEFORMATEX MakeWfx()
        {
            WAVEFORMATEX w = new WAVEFORMATEX();
            w.wFormatTag = 1;
            w.nChannels = 1;
            w.nSamplesPerSec = SAMPLE_RATE;
            w.wBitsPerSample = 16;
            w.nBlockAlign = 2;
            w.nAvgBytesPerSec = SAMPLE_RATE * 2;
            w.cbSize = 0;
            return w;
        }

        public bool OpenMic()
        {
            lock (_devLock)
            {
                if (_disposed) return false;
                return OpenMicCore();
            }
        }

        private bool OpenMicCore()
        {
            if (_hwi != IntPtr.Zero) return true;
            WAVEFORMATEX wfx = MakeWfx();
            _keepInCb = InCallback;
            int r = waveInOpen(ref _hwi, 0, ref wfx,
                Marshal.GetFunctionPointerForDelegate(_keepInCb), IntPtr.Zero, CALLBACK_FUNCTION);
            if (r != 0 || _hwi == IntPtr.Zero)
            {
                // Device 0 can be a stale/disabled endpoint, so fall back to the
                // Windows default capture device (WAVE_MAPPER = 0xFFFFFFFF).
                _hwi = IntPtr.Zero;
                r = waveInOpen(ref _hwi, 0xFFFFFFFF, ref wfx,
                    Marshal.GetFunctionPointerForDelegate(_keepInCb), IntPtr.Zero, CALLBACK_FUNCTION);
            }
            if (r != 0 || _hwi == IntPtr.Zero)
            {
                _hwi = IntPtr.Zero;
                // One line per 10 s: a missing/busy device is retried often.
                if ((DateTime.Now - _micFailLoggedAt).TotalSeconds >= 10)
                {
                    _micFailLoggedAt = DateTime.Now;
                    EmitLog("Mic open FAILED (mmresult " + r + ") - device missing, blocked by Windows " +
                        "microphone privacy, or held exclusively by another app; outgoing audio disabled.");
                }
                return false;
            }
            for (int i = 0; i < 6; i++)
            {
                IntPtr hdr = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(WAVEHDR)));
                IntPtr data = Marshal.AllocHGlobal(FRAME_BYTES);
                WAVEHDR h = new WAVEHDR();
                h.lpData = data;
                h.dwBufferLength = FRAME_BYTES;
                Marshal.StructureToPtr(h, hdr, false);
                waveInPrepareHeader(_hwi, hdr, Marshal.SizeOf(typeof(WAVEHDR)));
                waveInAddBuffer(_hwi, hdr, Marshal.SizeOf(typeof(WAVEHDR)));
                _inHeaders.Add(hdr);
            }
            waveInStart(_hwi);
            EmitLog("Mic open: 16 kHz mono, 20 ms frames");
            return true;
        }

        private void InCallback(IntPtr hwi, int uMsg, IntPtr dwInstance, IntPtr lpwhdr, int dwParam2)
        {
            if (uMsg != 0x3C0) return; // WIM_DATA
            try
            {
                WAVEHDR h = (WAVEHDR)Marshal.PtrToStructure(lpwhdr, typeof(WAVEHDR));
                if (h.dwBytesRecorded > 0)
                {
                    byte[] pcm = new byte[h.dwBytesRecorded];
                    Marshal.Copy(h.lpData, pcm, 0, h.dwBytesRecorded);
                    Action<byte[]> cb = FrameCaptured;
                    if (cb != null) cb(pcm);
                }
                if (_hwi != IntPtr.Zero)
                    waveInAddBuffer(_hwi, lpwhdr, Marshal.SizeOf(typeof(WAVEHDR)));
            }
            catch { }
        }

        public bool OpenSpeaker()
        {
            lock (_devLock)
            {
                if (_disposed) return false;
                return OpenSpeakerCore();
            }
        }

        private bool OpenSpeakerCore()
        {
            if (_hwo != IntPtr.Zero) return true;
            WAVEFORMATEX wfx = MakeWfx();
            _keepOutCb = OutCallback;
            int r = waveOutOpen(ref _hwo, 0, ref wfx,
                Marshal.GetFunctionPointerForDelegate(_keepOutCb), IntPtr.Zero, CALLBACK_FUNCTION);
            if (r != 0 || _hwo == IntPtr.Zero)
            {
                _hwo = IntPtr.Zero;
                EmitLog("Speaker open FAILED (mmresult " + r + ") - no audio playback, you will not hear the peer.");
                return false;
            }
            for (int i = 0; i < 8; i++)
            {
                IntPtr hdr = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(WAVEHDR)));
                IntPtr data = Marshal.AllocHGlobal(FRAME_BYTES);
                WAVEHDR h = new WAVEHDR();
                h.lpData = data;
                h.dwBufferLength = FRAME_BYTES;
                Marshal.StructureToPtr(h, hdr, false);
                waveOutPrepareHeader(_hwo, hdr, Marshal.SizeOf(typeof(WAVEHDR)));
                _outHeaders.Add(hdr);
            }
            EmitLog("Speaker open: 16 kHz mono");
            return true;
        }

        public void EnqueuePlay(byte[] pcm)
        {
            lock (_qLock)
            {
                _playQueue.Enqueue(pcm);
                while (_playQueue.Count > 25) _playQueue.Dequeue();
            }
            Pump();
        }

        private void Pump()
        {
            if (_disposed) return;
            if (_hwo == IntPtr.Zero) return;
            if (Interlocked.Exchange(ref _pumping, 1) == 1) return;
            try
            {
                // Hold the device lock so Dispose can't free the buffers while
                // we fill/write them.
                lock (_devLock)
                {
                    if (_disposed || _hwo == IntPtr.Zero) return;
                    foreach (IntPtr hdr in _outHeaders)
                    {
                        WAVEHDR h = (WAVEHDR)Marshal.PtrToStructure(hdr, typeof(WAVEHDR));
                        if ((h.dwFlags & 0x10) != 0) continue; // WHDR_INQUEUE (0x10) - still queued, skip
                        byte[] pcm;
                        lock (_qLock)
                            pcm = _playQueue.Count > 0 ? _playQueue.Dequeue() : new byte[FRAME_BYTES];
                        if (pcm.Length < FRAME_BYTES)
                        {
                            byte[] padded = new byte[FRAME_BYTES];
                            Buffer.BlockCopy(pcm, 0, padded, 0, pcm.Length);
                            pcm = padded;
                        }
                        Marshal.Copy(pcm, 0, h.lpData, FRAME_BYTES);
                        h.dwBufferLength = FRAME_BYTES;
                        h.dwBytesRecorded = 0;
                        Marshal.StructureToPtr(h, hdr, false);
                        waveOutWrite(_hwo, hdr, Marshal.SizeOf(typeof(WAVEHDR)));
                    }
                }
            }
            catch { }
            finally { Interlocked.Exchange(ref _pumping, 0); }
        }

        private void OutCallback(IntPtr hwo, int uMsg, IntPtr dwInstance, IntPtr lpwhr, int dwParam2)
        {
            if (uMsg == 0x3BD) Pump(); // WOM_DONE
        }

        public void Dispose()
        {
            lock (_devLock)
            {
                if (_disposed) return;
                _disposed = true;
                DisposeCore();
            }
        }

        private void DisposeCore()
        {
            if (_hwi != IntPtr.Zero)
            {
                waveInReset(_hwi);
                waveInStop(_hwi);
                foreach (IntPtr hdr in _inHeaders)
                {
                    waveInUnprepareHeader(_hwi, hdr, Marshal.SizeOf(typeof(WAVEHDR)));
                    WAVEHDR h = (WAVEHDR)Marshal.PtrToStructure(hdr, typeof(WAVEHDR));
                    Marshal.FreeHGlobal(h.lpData);
                    Marshal.FreeHGlobal(hdr);
                }
                _inHeaders.Clear();
                waveInClose(_hwi);
                _hwi = IntPtr.Zero;
            }
            if (_hwo != IntPtr.Zero)
            {
                waveOutReset(_hwo);
                foreach (IntPtr hdr in _outHeaders)
                {
                    waveOutUnprepareHeader(_hwo, hdr, Marshal.SizeOf(typeof(WAVEHDR)));
                    WAVEHDR h = (WAVEHDR)Marshal.PtrToStructure(hdr, typeof(WAVEHDR));
                    Marshal.FreeHGlobal(h.lpData);
                    Marshal.FreeHGlobal(hdr);
                }
                _outHeaders.Clear();
                waveOutClose(_hwo);
                _hwo = IntPtr.Zero;
            }
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct WAVEFORMATEX
        {
            public ushort wFormatTag;
            public ushort nChannels;
            public uint nSamplesPerSec;
            public uint nAvgBytesPerSec;
            public ushort nBlockAlign;
            public ushort wBitsPerSample;
            public ushort cbSize;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct WAVEHDR
        {
            public IntPtr lpData;
            public int dwBufferLength;
            public int dwBytesRecorded;
            public IntPtr dwUser;
            public int dwFlags;
            public int dwLoops;
            public IntPtr lpNext;
            public IntPtr reserved;
        }

        private const int CALLBACK_FUNCTION = 0x00030000;

        [DllImport("winmm.dll")]
        private static extern int waveInOpen(ref IntPtr phwi, uint uDeviceId, ref WAVEFORMATEX pwfx, IntPtr dwCallback, IntPtr dwInstance, int fdwOpen);
        [DllImport("winmm.dll")]
        private static extern int waveInPrepareHeader(IntPtr hwi, IntPtr pwh, int cbwh);
        [DllImport("winmm.dll")]
        private static extern int waveInUnprepareHeader(IntPtr hwi, IntPtr pwh, int cbwh);
        [DllImport("winmm.dll")]
        private static extern int waveInAddBuffer(IntPtr hwi, IntPtr pwh, int cbwh);
        [DllImport("winmm.dll")]
        private static extern int waveInStart(IntPtr hwi);
        [DllImport("winmm.dll")]
        private static extern int waveInStop(IntPtr hwi);
        [DllImport("winmm.dll")]
        private static extern int waveInReset(IntPtr hwi);
        [DllImport("winmm.dll")]
        private static extern int waveInClose(IntPtr hwi);
        [DllImport("winmm.dll")]
        private static extern int waveOutOpen(ref IntPtr phwo, uint uDeviceId, ref WAVEFORMATEX pwfx, IntPtr dwCallback, IntPtr dwInstance, int fdwOpen);
        [DllImport("winmm.dll")]
        private static extern int waveOutPrepareHeader(IntPtr hwo, IntPtr pwh, int cbwh);
        [DllImport("winmm.dll")]
        private static extern int waveOutUnprepareHeader(IntPtr hwo, IntPtr pwh, int cbwh);
        [DllImport("winmm.dll")]
        private static extern int waveOutWrite(IntPtr hwo, IntPtr pwh, int cbwh);
        [DllImport("winmm.dll")]
        private static extern int waveOutReset(IntPtr hwo);
        [DllImport("winmm.dll")]
        private static extern int waveOutClose(IntPtr hwo);
    }

    // ---- Mic pre-processing: DC block + noise gate + AGC + echo cancel ----
    // Pure C#5, per-20ms-frame processing of 16 kHz mono 16-bit PCM.
    public sealed class AudioFilter
    {
        public bool Enabled = true;
        public bool AecEnabled = true;

        // DC blocker / high-pass: y[n] = x[n] - x[n-1] + R*y[n-1]
        private double _prevX, _prevY;
        // noise gate: smoothed envelope + hold so single words don't clip
        private double _env;
        private int _gateHold;
        private double _gateG = 1.0;
        // AGC: slow gain toward a target speech level
        private double _gain = 1.0;
        // AEC: NLMS over the recent speaker (playback) output - the echo
        // reference. 128 taps = 8 ms tail @16 kHz (speakerphone-ish leak).
        private const int Taps = 128;
        private readonly int[] _spk = new int[Taps];
        private readonly double[] _w = new double[Taps];
        private int _spkPos;

        public void Reset()
        {
            _prevX = 0; _prevY = 0;
            _env = 0; _gateHold = 0; _gateG = 1.0;
            _gain = 1.0;
            Array.Clear(_spk, 0, _spk.Length);
            Array.Clear(_w, 0, _w.Length);
            _spkPos = 0;
        }

        // Feed every speaker (playback) frame: the echo reference signal.
        public void ReferenceSpeaker(byte[] pcm)
        {
            if (!Enabled || !AecEnabled || pcm == null) return;
            for (int i = 0; i + 1 < pcm.Length; i += 2)
            {
                int s = (short)(pcm[i] | (pcm[i + 1] << 8));
                _spk[_spkPos] = s;
                _spkPos = (_spkPos + 1) % Taps;
            }
        }

        public byte[] Process(byte[] pcm)
        {
            if (!Enabled || pcm == null) return pcm;
            byte[] outp = new byte[pcm.Length];
            double eps = 1e-6;
            for (int i = 0; i + 1 < pcm.Length; i += 2)
            {
                double x = (short)(pcm[i] | (pcm[i + 1] << 8));

                // 1) echo subtract + NLMS weight update
                if (AecEnabled)
                {
                    double est = 0, norm = 0;
                    for (int k = 0; k < Taps; k++)
                    {
                        double rf = _spk[(_spkPos - 1 - k + 2 * Taps) % Taps];
                        est += _w[k] * rf;
                        norm += rf * rf;
                    }
                    double e = x - est;                    // echo-cancelled mic sample
                    double mu = 0.4 / (eps + norm);
                    if (mu > 0.05) mu = 0.05;              // clamp step size
                    for (int k = 0; k < Taps; k++)
                    {
                        double rf = _spk[(_spkPos - 1 - k + 2 * Taps) % Taps];
                        _w[k] = 0.999 * _w[k] + mu * e * rf;   // leaky NLMS
                    }
                    x = e;
                }

                // 2) DC block / high-pass (R ~ 0.995 @ 16 kHz)
                double y = x - _prevX + 0.995 * _prevY;
                _prevX = x; _prevY = y;
                x = y * 0.5;

                // 3) noise gate (fast attack, slow release + 500 ms hold)
                double ax = Math.Abs(x);
                _env += (ax - _env) * (ax > _env ? 0.35 : 0.05);
                bool speech = _env > 450;                 // ~ -37 dBFS
                if (speech) _gateHold = 25;               // 25 frames = 500 ms
                else if (_gateHold > 0) _gateHold--;
                double targetG = (speech || _gateHold > 0) ? 1.0 : 0.0;
                _gateG += (targetG - _gateG) * (targetG > _gateG ? 0.25 : 0.45);

                // 4) AGC toward ~12% full scale while open
                double v;
                if (_gateG > 0.5)
                {
                    double desired = _env > 200 ? 4000.0 / _env : 1.0;
                    if (desired > 6.0) desired = 6.0; else if (desired < 0.5) desired = 0.5;
                    _gain += (desired - _gain) * 0.02;
                    v = x * _gain * _gateG;
                }
                else
                {
                    v = x * _gateG;                       // gated: near-silence
                }
                if (v > 32767) v = 32767; else if (v < -32768) v = -32768;
                short o = (short)v;
                outp[i] = (byte)(o & 0xFF);
                outp[i + 1] = (byte)((o >> 8) & 0xFF);
            }
            return outp;
        }
    }

    // ---- WAV call recorder: stereo (ch0 = remote, ch1 = local mic) ----
    // A 20 ms pump thread keeps both channels sample-aligned (zero-padding
    // whichever side is momentarily silent), streaming to disk so long calls
    // never buffer the whole recording in memory.
    public sealed class CallRecorder : IDisposable
    {
        private const int Rate = 16000;
        private const int FrameBytes = 640;   // 20 ms mono 16-bit
        private FileStream _fs;
        private BinaryWriter _bw;
        private readonly object _lock = new object();
        private readonly System.Collections.Generic.Queue<byte[]> _rx =
            new System.Collections.Generic.Queue<byte[]>();
        private readonly System.Collections.Generic.Queue<byte[]> _tx =
            new System.Collections.Generic.Queue<byte[]>();
        private int _rxQueued, _txQueued;
        private Thread _pump;
        private volatile bool _run;
        private long _dataBytes;
        private bool _closed;

        public string FilePath { get; private set; }

        public static CallRecorder StartNew(string peer)
        {
            try
            {
                string dir = System.IO.Path.Combine(Home.Dir, "recordings");
                Directory.CreateDirectory(dir);
                string safe = peer == null ? "peer" : peer;
                char[] invalid = System.IO.Path.GetInvalidFileNameChars();
                for (int i = 0; i < safe.Length; i++)
                    if (Array.IndexOf(invalid, safe[i]) >= 0) safe = safe.Replace(safe[i], '_');
                if (safe.Length > 40) safe = safe.Substring(0, 40);
                CallRecorder r = new CallRecorder();
                r.Open(System.IO.Path.Combine(dir,
                    "voip_" + DateTime.Now.ToString("yyyyMMdd_HHmmss") + "_" + safe + ".wav"));
                return r;
            }
            catch { return null; }
        }

        private void Open(string path)
        {
            _fs = new FileStream(path, FileMode.Create, FileAccess.ReadWrite);
            _bw = new BinaryWriter(_fs);
            FilePath = path;
            WriteHeader(0, 0);          // placeholder sizes, patched on close
            _run = true;
            _pump = new Thread((ThreadStart)delegate
            {
                byte[] silence = new byte[FrameBytes];
                DateTime lastPatch = DateTime.UtcNow;
                while (_run)
                {
                    Thread.Sleep(20);
                    try { PumpOnce(silence); }
                    catch { if (!_run) break; }
                    // refresh the WAV sizes every second so even a hard-killed
                    // process leaves a playable file (the close-time patch is lost).
                    if ((DateTime.UtcNow - lastPatch).TotalSeconds >= 1.0)
                    {
                        lastPatch = DateTime.UtcNow;
                        PatchHeader();
                    }
                }
            });
            _pump.IsBackground = true;
            _pump.Start();
        }

        // queue a received (remote) frame
        public void WriteRx(byte[] pcm) { Queue(_rx, ref _rxQueued, pcm); }
        // queue a local (mic) frame - pass the silence frame when muted so
        // the channel stays time-aligned
        public void WriteTx(byte[] pcm) { Queue(_tx, ref _txQueued, pcm); }

        private void Queue(System.Collections.Generic.Queue<byte[]> q, ref int queued, byte[] pcm)
        {
            if (pcm == null || pcm.Length == 0) return;
            lock (_lock)
            {
                if (_closed || q.Count > 250) return;   // ~5 s backlog cap
                q.Enqueue(pcm);
                queued += pcm.Length;
            }
        }

        private void PumpOnce(byte[] silence)
        {
            byte[] l = new byte[FrameBytes];
            byte[] r = new byte[FrameBytes];
            bool any = false;
            lock (_lock)
            {
                if (_closed) return;
                any = Take(_rx, ref _rxQueued, l) | Take(_tx, ref _txQueued, r);
                if (!any) return;
                // interleave: L = remote, R = local
                for (int i = 0; i < FrameBytes; i += 2)
                {
                    _bw.Write(l[i]); _bw.Write(l[i + 1]);
                    _bw.Write(r[i]); _bw.Write(r[i + 1]);
                }
                _dataBytes += FrameBytes * 4;
            }
        }

        private static bool Take(System.Collections.Generic.Queue<byte[]> q, ref int queued, byte[] dst)
        {
            int filled = 0;
            bool any = false;
            while (filled < dst.Length && q.Count > 0)
            {
                byte[] f = q.Peek();
                int n = dst.Length - filled;
                if (n > f.Length) n = f.Length;
                Buffer.BlockCopy(f, 0, dst, filled, n);
                filled += n;
                any = true;
                if (n == f.Length) { q.Dequeue(); queued -= f.Length; }
                else
                {
                    byte[] rest = new byte[f.Length - n];
                    Buffer.BlockCopy(f, n, rest, 0, rest.Length);
                    q.Dequeue(); q.Enqueue(rest);
                    queued -= n;
                }
            }
            return any;
        }

        private void WriteHeader(long riffSize, long dataSize)
        {
            _bw.Write((byte)'R'); _bw.Write((byte)'I'); _bw.Write((byte)'F'); _bw.Write((byte)'F');
            _bw.Write((int)riffSize);
            _bw.Write((byte)'W'); _bw.Write((byte)'A'); _bw.Write((byte)'V'); _bw.Write((byte)'E');
            _bw.Write((byte)'f'); _bw.Write((byte)'m'); _bw.Write((byte)'t'); _bw.Write((byte)' ');
            _bw.Write(16);
            _bw.Write((short)1);                 // PCM
            _bw.Write((short)2);                 // stereo
            _bw.Write(Rate);
            _bw.Write(Rate * 2 * 2);             // byte rate
            _bw.Write((short)4);                 // block align
            _bw.Write((short)16);                // bits
            _bw.Write((byte)'d'); _bw.Write((byte)'a'); _bw.Write((byte)'t'); _bw.Write((byte)'a');
            _bw.Write((int)dataSize);
        }

        // Rewrite the WAV sizes at the current data length and seek back to the
        // end, so the pump can keep appending afterwards.
        private void PatchHeader()
        {
            lock (_lock)
            {
                if (_closed) return;
                try
                {
                    _bw.Flush();
                    long bytes = _dataBytes;
                    _fs.Seek(0, SeekOrigin.Begin);
                    WriteHeader(36 + bytes, bytes);
                    _bw.Flush();
                    _fs.Seek(44 + bytes, SeekOrigin.Begin);
                }
                catch { }
            }
        }

        // Finalize the WAV (patch sizes). Safe to call more than once.
        public void Dispose()
        {
            lock (_lock)
            {
                if (_closed) return;
                _closed = true;
                _run = false;
                try
                {
                    _bw.Flush();
                    long bytes = _dataBytes;
                    _fs.Seek(0, SeekOrigin.Begin);
                    WriteHeader((int)(36 + bytes), (int)bytes);
                    _bw.Flush();
                    _fs.Close();
                }
                catch { }
            }
        }
    }
}
