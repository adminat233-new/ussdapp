using System;
using System.Collections.Generic;
using System.Net.Sockets;
using System.Text;
using System.Threading;

namespace UssdApp
{
    // =====================================================================
    // Transport seam.
    //
    // The app used to assume "the relay is the network". That assumption is
    // what makes a single static hop unavoidable, and it is what a LoRa or
    // Reticulum link would have to fight. This file replaces the assumption
    // with an interface: a transport declares what it can carry, and a router
    // chooses a route by capability instead of by hard-coded preference.
    //
    // Rules the router encodes (from docs/ROADMAP_voip_future.md §10):
    //   - a frame bigger than MaxFrameBytes never goes that way;
    //   - media-class payloads need a bitrate floor; radio transports report
    //     their ceiling and get text only;
    //   - a transport with RequiresConsent is used only after the user opted
    //     in, because it means "my node carries strangers' traffic";
    //   - the relay is always registered and is the last resort, so switching
    //     this seam on cannot cost delivery: a refused direct send falls back
    //     to it in VoipService.LineOut().
    // =====================================================================

    public enum PayloadClass { Text, Control, Media }

    public interface ITransport
    {
        string Name { get; }                  // "relay", "lan", "mesh", "rns"
        int MaxFrameBytes { get; }            // 0 = unknown / unlimited
        int BitRate { get; }                  // bits/sec, 0 = unknown
        bool RequiresConsent { get; }         // radio: my node carries for others
        bool Ready { get; }
        string LastError { get; }

        // false = this transport could not take it (route unavailable).
        bool Send(string to, byte[] frame);

        // Raised with (from, payload) when a frame arrives.
        event Action<string, byte[]> Frame;
    }

    // The existing store-and-forward relay, seen through the seam. It owns no
    // new logic - VoipService already holds the connection and the sealing.
    public sealed class RelayTransport : ITransport
    {
        public event Action<string, byte[]> Frame;

        private readonly Func<string, byte[], bool> _send;
        private readonly Func<bool> _ready;
        private string _error = "";

        public RelayTransport(Func<string, byte[], bool> send, Func<bool> ready)
        {
            _send = send;
            _ready = ready;
        }

        public string Name { get { return "relay"; } }
        public int MaxFrameBytes { get { return 0; } }        // relay already chunks
        public int BitRate { get { return 0; } }              // unknown, treat as fast
        public bool RequiresConsent { get { return false; } }
        public bool Ready { get { return _ready != null && _ready(); } }
        public string LastError { get { return _error; } }

        public bool Send(string to, byte[] frame)
        {
            try
            {
                if (_send == null) return false;
                return _send(to, frame);
            }
            catch (Exception ex) { _error = ex.Message; return false; }
        }

        // Called by the relay client when a sealed line arrives.
        public void Inject(string from, byte[] payload)
        {
            Action<string, byte[]> h = Frame;
            if (h != null) h(from, payload);
        }
    }

    // Loopback transport for tests and for same-machine peers: frames written
    // with Send() appear on the peer's Frame event, in-process. It lets the
    // routing rules be verified without hardware or a network.
    public sealed class LoopTransport : ITransport
    {
        public event Action<string, byte[]> Frame;

        private readonly string _name;
        private readonly int _maxFrame;
        private readonly int _bitRate;
        private readonly List<string> _tx = new List<string>();
        private readonly bool _needsConsent;
        private static readonly object _meshLock = new object();
        private static readonly Dictionary<string, LoopTransport> _Peers = new Dictionary<string, LoopTransport>();
        private string _bindAs;

        public LoopTransport(string name, int maxFrameBytes, int bitRate)
            : this(name, maxFrameBytes, bitRate, false)
        {
        }

        public LoopTransport(string name, int maxFrameBytes, int bitRate, bool requiresConsent)
        {
            _name = name;
            _maxFrame = maxFrameBytes;
            _bitRate = bitRate;
            _needsConsent = requiresConsent;
        }

        public string Name { get { return _name; } }
        public int MaxFrameBytes { get { return _maxFrame; } }
        public int BitRate { get { return _bitRate; } }
        public bool RequiresConsent { get { return _needsConsent; } }
        public bool Ready { get { return true; } }
        public string LastError { get { return ""; } }
        public List<string> Transmitted { get { return _tx; } }

        public void Bind(string id)
        {
            lock (_meshLock) { _Peers[id] = this; }
            _bindAs = id;
        }

        public static void Reset()
        {
            lock (_meshLock) { _Peers.Clear(); }
        }

        public bool Send(string to, byte[] frame)
        {
            LoopTransport peer;
            lock (_meshLock) _Peers.TryGetValue(to, out peer);
            if (peer == null) return false;
            _tx.Add(to + "|" + Encoding.UTF8.GetString(frame));
            peer.Raise(_bindAs, frame);
            return true;
        }

        private void Raise(string from, byte[] frame)
        {
            Action<string, byte[]> h = Frame;
            if (h != null) h(from, frame);
        }
    }

    // One line of the route table, in the words the settings page shows. The
    // display strings come from the same fields the router judged, so what a
    // person reads is what the code did - not a description written afterwards.
    public sealed class RouteRow
    {
        public string Name = "";
        public bool IsReady;
        public int FrameLimit;            // 0 = no ceiling declared
        public int Rate;                  // bits/sec, 0 = unknown
        public bool NeedsConsent;
        public bool ConsentGranted;

        public string Link { get { return Name; } }
        public string Ready { get { return IsReady ? "ready" : "down"; } }
        public string MaxFrame { get { return FrameLimit == 0 ? "any size" : FrameLimit + " B"; } }
        public string BitRate
        {
            get
            {
                if (Rate == 0) return "unknown";
                if (Rate >= 1000) return (Rate / 1000) + " kbps";
                return Rate + " bps";
            }
        }
        public string Consent
        {
            get
            {
                if (!NeedsConsent) return "own traffic only";
                return ConsentGranted ? "carries for peers" : "refused";
            }
        }
    }

    // Route chooser. Selection is deterministic and explainable, because the
    // UI has to tell the user which way a message actually went.
    public sealed class TransportRouter
    {
        private readonly List<ITransport> _transports = new List<ITransport>();
        private readonly Dictionary<string, bool> _consent = new Dictionary<string, bool>();
        private readonly object _lock = new object();

        // What a link that carries for other people does when the user has not
        // been asked about that particular link yet. False is the honest default:
        // "your node will not relay strangers until you say so". The settings
        // page turns it on once, explicitly, and it then covers links that get
        // registered later (a radio adapter plugged in tomorrow).
        public bool DefaultConsentGranted = false;

        public event Action<string, string> RouteNotice;   // transport name, detail

        public void Add(ITransport t)
        {
            if (t == null) return;
            lock (_lock) _transports.Add(t);
        }

        public void SetConsent(string transportName, bool allowed)
        {
            lock (_lock) _consent[transportName] = allowed;
        }

        public bool ConsentFor(string transportName)
        {
            lock (_lock)
            {
                bool v;
                if (_consent.TryGetValue(transportName ?? "", out v)) return v;
                return DefaultConsentGranted;
            }
        }

        public List<RouteRow> Rows()
        {
            List<RouteRow> rows = new List<RouteRow>();
            lock (_lock)
            {
                foreach (ITransport t in _transports)
                {
                    RouteRow r = new RouteRow();
                    r.Name = t.Name;
                    r.IsReady = t.Ready;
                    r.FrameLimit = t.MaxFrameBytes;
                    r.Rate = t.BitRate;
                    r.NeedsConsent = t.RequiresConsent;
                    r.ConsentGranted = ConsentForLocked(t.Name);
                    rows.Add(r);
                }
            }
            return rows;
        }

        public List<string> ConsentLinks()
        {
            List<string> names = new List<string>();
            lock (_lock)
            {
                foreach (ITransport t in _transports)
                    if (t.RequiresConsent) names.Add(t.Name);
            }
            return names;
        }

        private bool ConsentForLocked(string transportName)
        {
            bool v;
            if (_consent.TryGetValue(transportName ?? "", out v)) return v;
            return DefaultConsentGranted;
        }

        // The one-line summary the logs and the selftest read. Derived from Rows()
        // so the table on screen and the router's own decision can never disagree.
        public List<string> Describe()
        {
            List<string> rows = new List<string>();
            foreach (RouteRow r in Rows())
                rows.Add(r.Name + " ready=" + (r.IsReady ? "yes" : "no") +
                         " maxFrame=" + (r.FrameLimit == 0 ? "any" : r.FrameLimit.ToString()) +
                         " bitrate=" + (r.Rate == 0 ? "any" : r.Rate.ToString()) +
                         (r.NeedsConsent ? " consent=" + (r.ConsentGranted ? "granted" : "withheld") : ""));
            return rows;
        }

        // A radio link at these rates cannot carry voice; keep the number in one
        // place so the ceiling is a policy, not a comment.
        public const int MIN_MEDIA_BITRATE = 64000;

        public ITransport Pick(int frameBytes, PayloadClass kind, out string why)
        {
            ITransport best = null;
            int bestScore = int.MinValue;
            string lastReject = "no transport registered";
            lock (_lock)
            {
                foreach (ITransport t in _transports)
                {
                    string reject = Reject(t, frameBytes, kind);
                    if (reject != null) { lastReject = t.Name + " " + reject; continue; }
                    // Order of preference: a link we own (lan / mesh / radio) beats
                    // the relay, because the relay is a third-party hop and removing
                    // those is the point of this app. The relay still wins whenever it
                    // is the only route that can carry the frame, and LineOut() falls
                    // back to the relay socket if a direct link refuses the send, so
                    // this ordering cannot cost delivery.
                    int score = (t.Ready ? 100 : 0) + (t.Name == "relay" ? 0 : 25);
                    if (score > bestScore) { bestScore = score; best = t; }
                }
            }
            why = best != null ? "selected" : lastReject;
            if (best == null && kind == PayloadClass.Media)
                Notice("none", "media has no route - every available link is too narrow or too small for " + frameBytes + " bytes");
            return best;
        }

        private string Reject(ITransport t, int frameBytes, PayloadClass kind)
        {
            if (!t.Ready) return "not ready";
            if (t.MaxFrameBytes > 0 && frameBytes > t.MaxFrameBytes) return "frame too large";
            if (kind == PayloadClass.Media && t.BitRate > 0 && t.BitRate < MIN_MEDIA_BITRATE) return "link too slow for media";
            if (t.RequiresConsent && !ConsentForLocked(t.Name)) return "consent withheld";
            return null;
        }

        public bool TrySend(string to, byte[] frame, PayloadClass kind, out string via)
        {
            string why;
            ITransport t = Pick(frame.Length, kind, out why);
            if (t == null) { via = "none (" + why + ")"; return false; }
            bool ok = t.Send(to, frame);
            via = ok ? t.Name : t.Name + " (send failed: " + t.LastError + ")";
            if (ok) Notice(t.Name, "delivered " + frame.Length + "B to " + to + " over " + t.Name);
            return ok;
        }

        private void Notice(string name, string detail)
        {
            Action<string, string> h = RouteNotice;
            if (h != null) h(name, detail);
        }

        // Convenience for text-sized payloads: tells the caller whether the line
        // could ever fit a radio link, which is how "sent over radio, text only"
        // becomes a fact the UI can assert instead of a hope.
        public bool RadioCanCarry(int frameBytes, PayloadClass kind)
        {
            lock (_lock)
            {
                foreach (ITransport t in _transports)
                {
                    if (t.Name == "relay") continue;
                    if (Reject(t, frameBytes, kind) == null) return true;
                }
            }
            return false;
        }
    }
}
