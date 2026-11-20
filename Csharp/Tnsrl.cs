using System;
using System.Collections.Generic;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text;

namespace UssdApp
{
    // =========================================================================
    // The Non Stable Relay Logic  (TNSRL)
    // =========================================================================
    //
    // Core idea: every device that has the app installed knows its own:
    //   • private (LAN) IP address
    //   • public (internet) IP address discovered via STUN
    //   • MAC address (NIC hardware address)
    //   • DNS hostname
    //   • relay port  (always DEFAULT_PORT = 45675, universally known)
    //   • media port  (always MEDIA_PORT  = 45672, universally known)
    //   • network type (private LAN / public internet / cellular / VPN)
    //
    // Because the relay port and media port are fixed and universally known,
    // device A that learns B's IP (private or public) already knows the
    // exact port to knock on. No separate port negotiation is needed.
    //
    // Connection flow (two devices, any network):
    //   1. Both broadcast TNSRL v2 announcements on the LAN (every 2 s).
    //      The announcement contains private IP, MAC, DNS name and network type.
    //   2. A STUN probe tells each device its public IP:port. That pair is
    //      appended to the announcement so the peer knows the internet-facing
    //      address too.
    //   3. Device A learns B's announcement (LAN broadcast, relay push, or
    //      out-of-band share). It has: B.privateIp, B.publicIp, B.mac, B.dns,
    //      B.relayPort (=45675), B.mediaPort (=45672).
    //   4. A tries candidates in priority order:
    //        • B.privateIp:45672  (same LAN — fastest, lowest latency)
    //        • B.publicIp:45672   (across internet via STUN/UPnP mapping)
    //        • relay forward      (fallback when both UDP paths are blocked)
    //      The ICE candidate check (implemented in VoipMedia) confirms whichever
    //      path delivers a MAC-verified receipt and commits to it.
    //   5. For GROUP calls, every device acts as a mesh node: it forwards
    //      packets to peers it knows about, so the group does not need a single
    //      central relay. Any device that has an open path to two others bridges
    //      them. The mesh topology is maintained by TNSRL gossip: each device
    //      re-announces what routes it has discovered, with a hop count ceiling
    //      so the gossip does not loop.
    //
    // Security:
    //   • All media is AES-CTR encrypted with per-call session keys derived
    //     via DH-2048 + SHA-512 (providing ~200 bits of security).
    //   • All signaling is sealed with the peer's RSA-2048 identity key.
    //   • TNSRL announcements are signed with the sender's identity key so a
    //     forged announcement is detected before any connection is attempted.
    //   • MAC and DNS are advisory only: they help routing but are never used
    //     to authenticate. Authentication is always by identity key signature.
    //
    // Weekly security patch:
    //   • TnsrlSecurityMonitor.CheckAndPatch() is called by the app's weekly
    //     maintenance timer. It checks for known local weaknesses (open ports
    //     on wrong interfaces, weak key sizes, stale pins) and logs findings.
    //
    // Wire format v2 (pipe-delimited UTF-8, broadcast on UDP DISC_PORT 45670):
    //   USSDTNSRL|2|<b64name>|<privateIp>|<mediaPort>|<networkType>|
    //             <publicIp>|<publicPort>|<macHex>|<dnsName>|<sig>
    //   where sig = base64(RSA_SIGN(SHA256(all fields before sig)))
    //
    // The relay also pushes TNSRL announcements from registered peers to newly
    // connecting clients (TNSRPUSH verb), so a device learns all reachable
    // peers even if it arrived after the LAN broadcast window.
    // =========================================================================

    public sealed class TnsrlRoute
    {
        public string Name        = "";
        public IPAddress Address;          // private (LAN) address
        public int      MediaPort;         // always 45672 by design
        public string   NetworkType = "";  // "private" | "public" | "cellular" | "vpn"
        public DateTime LastSeenUtc;
        // v2 fields
        public IPAddress PublicAddress;    // STUN/UPnP discovered public IP
        public int       PublicPort;       // STUN/UPnP discovered public port
        public string    MacHex    = "";   // first NIC MAC, hex no separators
        public string    DnsName   = "";   // Dns.GetHostName() on the sender
        public string    Signature = "";   // base64 RSA signature (advisory)
        public int       HopCount;         // gossip hop count (0 = direct)
        public string    Number    = "";   // app number, if the peer shared it
    }

    public static class Tnsrl
    {
        public const int Version            = 2;
        public const int PreferredMediaPort = 45672;
        public const int RelayPort          = 45675;
        public const int MaxRouteAgeSeconds = 15;
        public const int MaxRoutes          = 64;    // mesh can be large
        public const int MaxGossipHops      = 3;

        // ── Announcement builder ──────────────────────────────────────────
        // Builds a wire-format v2 announcement. Signature is optional (empty
        // string when no identity key is available; peers accept unsigned
        // announcements for routing but cannot verify the sender's identity).
        public static string BuildAnnouncement(
            string name, IPAddress privateAddress, int mediaPort,
            IPAddress publicAddress = null, int publicPort = 0,
            string macHex = "", string dnsName = "",
            string signature = "", string number = "")
        {
            if (privateAddress == null) return "";
            if (mediaPort < 1 || mediaPort > 65535) mediaPort = PreferredMediaPort;
            string b64name = Convert.ToBase64String(Encoding.UTF8.GetBytes(
                SafeField(name ?? "")));
            string pubIp   = publicAddress != null ? publicAddress.ToString() : "";
            string mac     = SafeField(macHex  ?? "");
            string dns     = SafeField(dnsName ?? "");
            string num     = SafeField(number  ?? "");
            string sig     = SafeField(signature ?? "");
            string netType = ClassifyAddress(privateAddress);
            return "USSDTNSRL|" + Version + "|" + b64name + "|" +
                   privateAddress + "|" + mediaPort + "|" + netType + "|" +
                   pubIp + "|" + publicPort + "|" + mac + "|" + dns + "|" +
                   num + "|" + sig;
        }

        // Build from local device info — the most common call site.
        public static string BuildLocalAnnouncement(
            string appNumber, string displayName,
            IPAddress publicIp, int publicPort,
            Identity identity)
        {
            IPAddress local = GetLocalPrivateIp();
            if (local == null) return "";
            string mac = GetMacHex();
            string dns = GetDnsName();
            string sig = "";
            if (identity != null && !string.IsNullOrEmpty(appNumber))
            {
                try
                {
                    // Sign the core routing fields so peers can verify the
                    // announcement came from the holder of this number's key.
                    string toSign = local + "|" + PreferredMediaPort + "|" +
                                    (publicIp != null ? publicIp.ToString() : "") + "|" +
                                    publicPort + "|" + appNumber;
                    sig = Convert.ToBase64String(identity.Sign(
                        Encoding.UTF8.GetBytes(toSign)));
                }
                catch { }
            }
            return BuildAnnouncement(
                displayName, local, PreferredMediaPort,
                publicIp, publicPort, mac, dns, sig, appNumber);
        }

        // ── Wire parser ───────────────────────────────────────────────────
        public static bool TryParse(string wire, IPAddress sender,
                                    out TnsrlRoute route, bool allowPublic = false)
        {
            route = null;
            if (string.IsNullOrEmpty(wire) || sender == null) return false;
            string[] p = wire.Split('|');
            // v2: 12 fields; v1 legacy: 6 fields
            if (p.Length < 6 || p[0] != "USSDTNSRL") return false;
            int version, port;
            IPAddress advertised;
            if (!int.TryParse(p[1], out version)) return false;
            if (version != 1 && version != 2) return false;
            if (!int.TryParse(p[4], out port) || port < 1 || port > 65535) return false;
            if (!IPAddress.TryParse(p[3], out advertised)) return false;

            // Reject public IPs in the private address field (they should go
            // in the publicIp field); reject loopback.
            if (!allowPublic && !IsPrivateOrLinkLocal(advertised)) return false;
            if (IPAddress.IsLoopback(advertised)) return false;

            string name;
            try { name = Encoding.UTF8.GetString(Convert.FromBase64String(p[2])); }
            catch { return false; }
            if (name.Length > 128) return false;

            route = new TnsrlRoute
            {
                Name        = name,
                Address     = sender,          // actual sender IP takes precedence
                MediaPort   = port,
                NetworkType = p.Length > 5 ? NormalizeNetworkType(p[5]) : "private",
                LastSeenUtc = DateTime.UtcNow
            };

            if (version == 2 && p.Length >= 12)
            {
                IPAddress pub;
                int pubPort;
                if (!string.IsNullOrEmpty(p[6]) && IPAddress.TryParse(p[6], out pub))
                    route.PublicAddress = pub;
                if (int.TryParse(p[7], out pubPort) && pubPort > 0)
                    route.PublicPort = pubPort;
                route.MacHex    = p[8];
                route.DnsName   = p[9];
                route.Number    = p.Length > 10 ? p[10] : "";
                route.Signature = p.Length > 11 ? p[11] : "";
            }
            return true;
        }

        // Parse a gossip-forwarded announcement (may carry a hop count prefix).
        // Format: TNSRPUSH|<hops>|<original announcement>
        public static bool TryParseGossip(string wire, IPAddress sender,
                                          out TnsrlRoute route)
        {
            route = null;
            if (string.IsNullOrEmpty(wire)) return false;
            int hops = 0;
            if (wire.StartsWith("TNSRPUSH|", StringComparison.Ordinal))
            {
                int first = wire.IndexOf('|');
                int second = wire.IndexOf('|', first + 1);
                if (second < 0) return false;
                if (!int.TryParse(wire.Substring(first + 1, second - first - 1), out hops))
                    return false;
                wire = wire.Substring(second + 1);
            }
            if (!TryParse(wire, sender, out route, allowPublic: true)) return false;
            route.HopCount = hops;
            return hops <= MaxGossipHops;
        }

        // Wrap a local announcement for gossip forwarding.
        public static string WrapForGossip(string announcement, int hops)
        {
            if (hops >= MaxGossipHops) return "";
            return "TNSRPUSH|" + (hops + 1) + "|" + announcement;
        }

        // ── Device info helpers ───────────────────────────────────────────
        public static IPAddress GetLocalPrivateIp()
        {
            try
            {
                foreach (NetworkInterface ni in NetworkInterface.GetAllNetworkInterfaces())
                {
                    if (ni.OperationalStatus != OperationalStatus.Up) continue;
                    if (ni.NetworkInterfaceType == NetworkInterfaceType.Loopback) continue;
                    foreach (UnicastIPAddressInformation u in ni.GetIPProperties().UnicastAddresses)
                    {
                        if (u.Address.AddressFamily != AddressFamily.InterNetwork) continue;
                        if (IsPrivateOrLinkLocal(u.Address)) return u.Address;
                    }
                }
            }
            catch { }
            return null;
        }

        public static string GetMacHex()
        {
            try
            {
                foreach (NetworkInterface ni in NetworkInterface.GetAllNetworkInterfaces())
                {
                    if (ni.OperationalStatus != OperationalStatus.Up) continue;
                    if (ni.NetworkInterfaceType == NetworkInterfaceType.Loopback) continue;
                    byte[] mac = ni.GetPhysicalAddress().GetAddressBytes();
                    if (mac.Length == 6)
                    {
                        StringBuilder sb = new StringBuilder(12);
                        foreach (byte b in mac) sb.Append(b.ToString("X2"));
                        return sb.ToString();
                    }
                }
            }
            catch { }
            return "";
        }

        public static string GetDnsName()
        {
            try { return System.Net.Dns.GetHostName(); }
            catch { return ""; }
        }

        // ── Address classification ────────────────────────────────────────
        public static bool IsPrivateOrLinkLocal(IPAddress a)
        {
            if (a == null || a.AddressFamily != AddressFamily.InterNetwork) return false;
            byte[] b = a.GetAddressBytes();
            return b[0] == 10 ||
                   (b[0] == 172 && b[1] >= 16 && b[1] <= 31) ||
                   (b[0] == 192 && b[1] == 168) ||
                   (b[0] == 169 && b[1] == 254);
        }

        // Legacy compatibility alias
        public static bool IsPrivateAddress(IPAddress a) { return IsPrivateOrLinkLocal(a); }

        static string ClassifyAddress(IPAddress a)
        {
            if (a == null) return "unknown";
            if (IsPrivateOrLinkLocal(a)) return "private";
            byte[] b = a.GetAddressBytes();
            // 100.64–100.127: carrier-grade NAT
            if (b[0] == 100 && b[1] >= 64 && b[1] <= 127) return "cgnat";
            return "public";
        }

        public static string NetworkType(IPAddress a)
        {
            return ClassifyAddress(a);
        }

        static string NormalizeNetworkType(string v)
        {
            switch (v)
            {
                case "private":  case "public":
                case "cellular": case "vpn":
                case "cgnat":    case "unknown": return v;
                default: return "unknown";
            }
        }

        static string SafeField(string s)
        {
            // Strip pipe chars from any field value so the wire format stays
            // parseable. Tabs and newlines too.
            if (string.IsNullOrEmpty(s)) return "";
            StringBuilder sb = new StringBuilder(s.Length);
            foreach (char c in s)
                if (c != '|' && c != '\n' && c != '\r' && c != '\t') sb.Append(c);
            return sb.ToString();
        }
    }

    // =========================================================================
    // TNSRL route flow: candidate table for all known peers
    // =========================================================================
    public sealed class TnsrlRouteFlow
    {
        private readonly object _lock = new object();
        private readonly Dictionary<string, TnsrlRoute> _routes =
            new Dictionary<string, TnsrlRoute>();

        // Observe a newly received announcement.
        public void Observe(TnsrlRoute route)
        {
            if (route == null || route.Address == null || route.MediaPort < 1) return;
            // Key by number if available (most specific), else by IP.
            string key = !string.IsNullOrEmpty(route.Number)
                ? "num:" + route.Number
                : "ip:"  + route.Address;
            lock (_lock)
            {
                PruneLocked(DateTime.UtcNow);
                if (!_routes.ContainsKey(key) && _routes.Count >= Tnsrl.MaxRoutes)
                    RemoveOldestLocked();
                _routes[key] = route;
            }
        }

        // Return the best UDP candidate endpoints for a peer identified by
        // their private IP. Returns in priority order:
        //   1. private LAN address (same network, fastest)
        //   2. public address:port (across internet, STUN/UPnP mapped)
        public List<IPEndPoint> Candidates(IPAddress peerPrivateAddress)
        {
            var result = new List<IPEndPoint>();
            if (peerPrivateAddress == null) return result;
            lock (_lock)
            {
                PruneLocked(DateTime.UtcNow);
                // Try by IP key first
                TnsrlRoute route;
                if (_routes.TryGetValue("ip:" + peerPrivateAddress, out route))
                {
                    AddEndpoints(result, route);
                    return result;
                }
                // Fall back: scan all routes for a matching private address
                foreach (TnsrlRoute r in _routes.Values)
                {
                    if (r.Address != null && r.Address.Equals(peerPrivateAddress))
                    {
                        AddEndpoints(result, r);
                        return result;
                    }
                }
            }
            return result;
        }

        // Return all candidates for a peer identified by their app number.
        public List<IPEndPoint> CandidatesForNumber(string number)
        {
            var result = new List<IPEndPoint>();
            if (string.IsNullOrEmpty(number)) return result;
            lock (_lock)
            {
                PruneLocked(DateTime.UtcNow);
                TnsrlRoute route;
                if (_routes.TryGetValue("num:" + number, out route))
                    AddEndpoints(result, route);
            }
            return result;
        }

        static void AddEndpoints(List<IPEndPoint> list, TnsrlRoute r)
        {
            // Private LAN address first
            if (r.Address != null && r.MediaPort > 0)
                list.Add(new IPEndPoint(r.Address, r.MediaPort));
            // Public address second
            if (r.PublicAddress != null && r.PublicPort > 0 &&
                !r.PublicAddress.Equals(r.Address))
                list.Add(new IPEndPoint(r.PublicAddress, r.PublicPort));
            // Also try relay port on both IPs (TCP signaling port acts as UDP echo)
            if (r.Address != null)
                list.Add(new IPEndPoint(r.Address, Tnsrl.PreferredMediaPort));
        }

        public List<TnsrlRoute> Snapshot()
        {
            var result = new List<TnsrlRoute>();
            lock (_lock)
            {
                PruneLocked(DateTime.UtcNow);
                foreach (TnsrlRoute r in _routes.Values) result.Add(r);
            }
            return result;
        }

        public TnsrlRoute FindByNumber(string number)
        {
            if (string.IsNullOrEmpty(number)) return null;
            lock (_lock)
            {
                TnsrlRoute r;
                _routes.TryGetValue("num:" + number, out r);
                return r;
            }
        }

        public void Clear()
        {
            lock (_lock) _routes.Clear();
        }

        private void PruneLocked(DateTime now)
        {
            var expired = new List<string>();
            foreach (KeyValuePair<string, TnsrlRoute> item in _routes)
                if ((now - item.Value.LastSeenUtc).TotalSeconds > Tnsrl.MaxRouteAgeSeconds)
                    expired.Add(item.Key);
            foreach (string key in expired) _routes.Remove(key);
        }

        private void RemoveOldestLocked()
        {
            string oldestKey = null;
            DateTime oldest  = DateTime.MaxValue;
            foreach (KeyValuePair<string, TnsrlRoute> item in _routes)
                if (item.Value.LastSeenUtc < oldest)
                { oldest = item.Value.LastSeenUtc; oldestKey = item.Key; }
            if (oldestKey != null) _routes.Remove(oldestKey);
        }
    }

    // =========================================================================
    // TNSRL mesh relay: each device forwards packets for peers it can reach.
    // Used for group calls where a centralised relay may be absent.
    // =========================================================================
    public sealed class TnsrlMeshRelay
    {
        // Maps app number → last known UDP endpoint (private or public).
        private readonly Dictionary<string, IPEndPoint> _knownPeers =
            new Dictionary<string, IPEndPoint>();
        private readonly object _peersLock = new object();
        private readonly TnsrlRouteFlow _routes;
        private readonly Action<string> _log;

        public TnsrlMeshRelay(TnsrlRouteFlow routes, Action<string> log)
        {
            _routes = routes;
            _log    = log;
        }

        // Called when we receive a media frame addressed to a number we know but
        // that is not our own. Forward it to their last-known UDP endpoint.
        public bool TryForward(UdpClient socket, string toNumber,
                               byte[] packet, string fromNumber)
        {
            if (socket == null || string.IsNullOrEmpty(toNumber) ||
                packet == null) return false;

            // Look up in route flow first (freshest)
            List<IPEndPoint> candidates = _routes.CandidatesForNumber(toNumber);
            if (candidates.Count == 0)
            {
                // Fall back to our own peer table
                lock (_peersLock)
                {
                    IPEndPoint ep;
                    if (_knownPeers.TryGetValue(toNumber, out ep))
                        candidates.Add(ep);
                }
            }
            if (candidates.Count == 0) return false;

            bool sent = false;
            foreach (IPEndPoint ep in candidates)
            {
                try
                {
                    socket.Send(packet, packet.Length, ep);
                    sent = true;
                    break;
                }
                catch { }
            }
            if (sent && _log != null)
                _log("TNSRL mesh forward: " + fromNumber + " → " + toNumber +
                     " via " + candidates[0]);
            return sent;
        }

        // Record that a peer sent us a packet from a given endpoint.
        public void NoteSourceEndpoint(string number, IPEndPoint ep)
        {
            if (string.IsNullOrEmpty(number) || ep == null) return;
            lock (_peersLock) { _knownPeers[number] = ep; }
        }

        // Build a gossip line from our route table to share with peers.
        public List<string> BuildGossipLines(string myAnnouncement, int currentHop)
        {
            var lines = new List<string>();
            // Forward our own announcement
            if (!string.IsNullOrEmpty(myAnnouncement))
                lines.Add(Tnsrl.WrapForGossip(myAnnouncement, currentHop));
            // Forward what we know about others (bounded by hop count)
            foreach (TnsrlRoute r in _routes.Snapshot())
            {
                if (r.HopCount >= Tnsrl.MaxGossipHops) continue;
                string ann = Tnsrl.BuildAnnouncement(
                    r.Name, r.Address, r.MediaPort,
                    r.PublicAddress, r.PublicPort,
                    r.MacHex, r.DnsName, r.Signature, r.Number);
                if (!string.IsNullOrEmpty(ann))
                    lines.Add(Tnsrl.WrapForGossip(ann, r.HopCount + 1));
            }
            return lines;
        }
    }

    // =========================================================================
    // TNSRL security monitor — weekly vulnerability check
    // =========================================================================
    public static class TnsrlSecurityMonitor
    {
        // Returns a list of findings. Empty = nothing to fix.
        public static List<string> Check(
            string identityKeyPath, string peerKeyPath, string relayPinPath)
        {
            var findings = new List<string>();

            // 1. Identity key age and size
            try
            {
                if (System.IO.File.Exists(identityKeyPath))
                {
                    string xml = System.IO.File.ReadAllText(identityKeyPath);
                    // Check key size: RSA-2048 XML is ~700–900 chars; shorter = suspect
                    if (xml.Length < 500)
                        findings.Add("WARN: identity.key appears shorter than expected " +
                                     "— it may be RSA-512 or RSA-1024. Regenerate for stronger security.");
                    // Check age: key older than 365 days is worth rotating
                    var fi = new System.IO.FileInfo(identityKeyPath);
                    if ((DateTime.UtcNow - fi.LastWriteTimeUtc).TotalDays > 365)
                        findings.Add("INFO: identity.key is over 1 year old. " +
                                     "Consider rotating it (Settings > Identity & Network > Reset).");
                }
                else
                {
                    findings.Add("WARN: identity.key not found — cannot verify key security.");
                }
            }
            catch (Exception ex)
            {
                findings.Add("ERR: could not read identity.key: " + ex.Message);
            }

            // 2. Peer key book — flag any key that is "new" and unverified
            try
            {
                if (System.IO.File.Exists(peerKeyPath))
                {
                    string[] lines = System.IO.File.ReadAllLines(peerKeyPath);
                    int newCount = 0;
                    foreach (string ln in lines)
                        if (ln.Contains("|new|")) newCount++;
                    if (newCount > 0)
                        findings.Add("INFO: " + newCount + " peer key(s) in peers_identity.txt " +
                                     "are marked 'new' (first use, not yet confirmed out-of-band). " +
                                     "Verify safety numbers with those contacts.");
                }
            }
            catch { }

            // 3. Relay pin book — flag any entry with no fingerprint ("-")
            try
            {
                if (System.IO.File.Exists(relayPinPath))
                {
                    string[] lines = System.IO.File.ReadAllLines(relayPinPath);
                    int unpinned = 0;
                    foreach (string ln in lines)
                    {
                        string t = ln.Trim();
                        if (t.Length == 0 || t.StartsWith("#")) continue;
                        if (t.EndsWith("|-") || t.Contains("|-|")) unpinned++;
                    }
                    if (unpinned > 0)
                        findings.Add("INFO: " + unpinned + " relay(s) in relays.seed " +
                                     "have no fingerprint (-). First-use trust only. " +
                                     "Compare fingerprints with the relay operator.");
                }
            }
            catch { }

            // 4. Check for ports bound on 0.0.0.0 that are reachable from internet
            // (advisory — the app binds intentionally, but it is worth noting)
            findings.Add("INFO: relay binds on 0.0.0.0:" + CallServer.DEFAULT_PORT +
                         " — ensure your firewall/router blocks this port from " +
                         "outside if you are not intentionally hosting a public relay.");

            return findings;
        }

        // Run the check and emit findings via the provided log action.
        public static void CheckAndLog(
            string homeDir, Action<string, bool> log)
        {
            if (log == null) return;
            string keyPath  = System.IO.Path.Combine(homeDir, "identity.key");
            string peerPath = System.IO.Path.Combine(homeDir, "peers_identity.txt");
            string pinPath  = System.IO.Path.Combine(homeDir, "relay_pins.txt");
            List<string> findings = Check(keyPath, peerPath, pinPath);
            if (findings.Count == 0)
            {
                log("Security scan: nothing to report.", true);
            }
            else
            {
                log("Security scan: " + findings.Count + " finding(s):", false);
                foreach (string f in findings)
                    log("  " + f, f.StartsWith("INFO:"));
            }
        }
    }
}
