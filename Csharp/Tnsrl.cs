using System;
using System.Collections.Generic;
using System.Net;
using System.Text;

namespace UssdApp
{
    // The Non Stable Relay Logic (TNSRL) is a local route hint, not an
    // identity or an internet rendezvous service. It deliberately publishes
    // only a private UDP endpoint and a coarse route class.
    public sealed class TnsrlRoute
    {
        public string Name = "";
        public IPAddress Address;
        public int MediaPort;
        public string NetworkType = "";
        public DateTime LastSeenUtc;
    }

    public static class Tnsrl
    {
        public const int Version = 1;
        public const int PreferredMediaPort = 45672;
        public const int MaxRouteAgeSeconds = 15;
        public const int MaxRoutes = 16;

        public static string BuildAnnouncement(string name, IPAddress address, int mediaPort)
        {
            if (address == null || !IsPrivateAddress(address)) return "";
            if (mediaPort < 1 || mediaPort > 65535) return "";
            string safeName = Convert.ToBase64String(Encoding.UTF8.GetBytes(name ?? ""));
            return "USSDTNSRL|" + Version + "|" + safeName + "|" +
                   address.ToString() + "|" + mediaPort + "|" +
                   NetworkType(address);
        }

        public static bool TryParse(string wire, IPAddress sender, out TnsrlRoute route)
        {
            route = null;
            if (string.IsNullOrEmpty(wire) || sender == null ||
                !IsPrivateAddress(sender)) return false;
            string[] p = wire.Split('|');
            if (p.Length != 6 || p[0] != "USSDTNSRL") return false;
            int version;
            int port;
            IPAddress advertised;
            if (!int.TryParse(p[1], out version) || version != Version) return false;
            if (!int.TryParse(p[4], out port) || port < 1 || port > 65535) return false;
            if (!IPAddress.TryParse(p[3], out advertised) || !IsPrivateAddress(advertised))
                return false;

            string name;
            try
            {
                name = Encoding.UTF8.GetString(Convert.FromBase64String(p[2]));
            }
            catch
            {
                return false;
            }
            if (name.Length > 128) return false;
            route = new TnsrlRoute
            {
                Name = name,
                Address = sender,
                MediaPort = port,
                NetworkType = NormalizeNetworkType(p[5]),
                LastSeenUtc = DateTime.UtcNow
            };
            return true;
        }

        public static bool IsPrivateAddress(IPAddress address)
        {
            if (address == null || address.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork)
                return false;
            byte[] b = address.GetAddressBytes();
            return b[0] == 10 ||
                   (b[0] == 172 && b[1] >= 16 && b[1] <= 31) ||
                   (b[0] == 192 && b[1] == 168) ||
                   (b[0] == 169 && b[1] == 254);
        }

        public static string NetworkType(IPAddress address)
        {
            return IsPrivateAddress(address) ? "private" : "public";
        }

        static string NormalizeNetworkType(string value)
        {
            if (value == "private" || value == "public") return value;
            return "unknown";
        }
    }

    // TNSRL route flow is intentionally bounded and disposable. It is a
    // candidate table for local/direct paths, not a directory or identity
    // service. The authenticated relay remains the fallback for every route.
    public sealed class TnsrlRouteFlow
    {
        private readonly object _lock = new object();
        private readonly Dictionary<string, TnsrlRoute> _routes =
            new Dictionary<string, TnsrlRoute>();

        public void Observe(TnsrlRoute route)
        {
            if (route == null || route.Address == null || route.MediaPort < 1) return;
            string key = route.Address.ToString();
            lock (_lock)
            {
                PruneLocked(DateTime.UtcNow);
                if (!_routes.ContainsKey(key) && _routes.Count >= Tnsrl.MaxRoutes)
                    RemoveOldestLocked();
                _routes[key] = route;
            }
        }

        public List<IPEndPoint> Candidates(IPAddress address)
        {
            List<IPEndPoint> result = new List<IPEndPoint>();
            if (address == null) return result;
            lock (_lock)
            {
                PruneLocked(DateTime.UtcNow);
                TnsrlRoute route;
                if (_routes.TryGetValue(address.ToString(), out route))
                    result.Add(new IPEndPoint(route.Address, route.MediaPort));
            }
            return result;
        }

        public List<TnsrlRoute> Snapshot()
        {
            List<TnsrlRoute> result = new List<TnsrlRoute>();
            lock (_lock)
            {
                PruneLocked(DateTime.UtcNow);
                foreach (TnsrlRoute route in _routes.Values) result.Add(route);
            }
            return result;
        }

        public void Clear()
        {
            lock (_lock) _routes.Clear();
        }

        private void PruneLocked(DateTime now)
        {
            List<string> expired = new List<string>();
            foreach (KeyValuePair<string, TnsrlRoute> item in _routes)
                if ((now - item.Value.LastSeenUtc).TotalSeconds > Tnsrl.MaxRouteAgeSeconds)
                    expired.Add(item.Key);
            foreach (string key in expired) _routes.Remove(key);
        }

        private void RemoveOldestLocked()
        {
            string oldestKey = null;
            DateTime oldest = DateTime.MaxValue;
            foreach (KeyValuePair<string, TnsrlRoute> item in _routes)
            {
                if (item.Value.LastSeenUtc < oldest)
                {
                    oldest = item.Value.LastSeenUtc;
                    oldestKey = item.Key;
                }
            }
            if (oldestKey != null) _routes.Remove(oldestKey);
        }
    }
}
