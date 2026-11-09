using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Net;
using System.Net.Security;
using System.Security.Authentication;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;

namespace UssdApp
{
    // =====================================================================
    // Call server: device directory + signaling/media relay for internet
    // voice/video calls between USSD Manager Pro instances.
    //
    // Line protocol (UTF-8, newline-terminated):
    //   client -> server:
    //     REG|<number>|<token>|<machine>     register this device's number
    //     REG|<number>|<token>|<machine>|<identityPub>|<sig>
    //                                        the last two are the ownership proof:
    //                                        sig = SIGN("OWNS|<number>") by that key,
    //                                        so the number belongs to a key, not to
    //                                        whoever knows the token (field 4 is split
    //                                        again by the relay; old clients work as-is)
    //     KA|                               keepalive (every 20 s)
    //     MSG|<to>|<from>|<line...>          route a signaling line
    //     RM|<to>|<from>|<base64 udp pkt>    route a media datagram
    //     CONF_JOIN|<roomId>|<token>       join a conference room
    //     CONF_LEAVE|<roomId>              leave a conference room
    //     CONF_AUDIO|<roomId>|<base64 pcm> 20 ms mic frame for the room mixer
    //     CONF_EAUDIO|<roomId>|<base64 sealed> E2E conference audio (forwarded
    //                                        without mixing; member decrypts locally)
    //     CONF_VIDEO|<roomId>|<base64 jpeg> group-call thumbnail for the tile grid
    //     CONF_MUTE|<roomId>|<0|1>         this member wants to be silent
    //     QUIT|                              polite disconnect
    //   server -> client:
    //     OK|<number>                        registration accepted
    //     ERR|inuse|<number>                 number claimed by another token
    //     ERR|claimed|<number>               leased to another install's token (see
    //                                        NumberLease.cs): retrying will not help
    //     ERR|badproof|<number>              the OWNS signature did not verify against
    //                                        the key presented - this install does not
    //                                        hold that number's private half
    //     ERR|nokey|<number>                 nothing was stored: the message was
    //                                        unsealed, and a relay keeps no plaintext
    //     ERR|proofneeded|<number>           the number is owned by a key and this
    //                                        install is too old to prove it - update it
    //                                        (not an accusation: it is usually the owner)
    //     ERR|noroom|<roomId>                this relay could not route the room's
    //                                        owner, and did not manage to hold the
    //                                        join until it could
    //     PEERS|num,ip,machine;num,ip,m...   full directory (on every change)
    //     MSG|<to>|<from>|<line...>          forwarded signaling line
    //     RM|<to>|<from>|<base64...>         forwarded media datagram
    //     CONF_MIXED|<roomId>|mix|<b64>    the room mix, with your own voice removed
    //     CONF_EAUDIOR|<roomId>|<from>|<b64>  E2E conference audio forwarded from a peer
    //     CONF_VID|<roomId>|<from>|<b64>   a member's group-call thumbnail
    //     CONF_TALK|<roomId>|n:lvl,n:lvl   per-member speech level (tile highlight)
    //     CONF_ROSTER|<roomId>|n1,n2,...     current conference participants
    //     UNDELIVERABLE|<to>                 target offline
    //
    //   Federation (a relay talking to another relay). Nothing here needs a
    //   vendor server: any user's PC can link to any other, and the merged
    //   directory is what makes a peer on someone else's relay reachable.
    //   relay -> relay only:
    //     RLINK|<relayId>|<name>|<advertise>  I want to carry traffic with you
    //     RLINKOK|<relayId>[|<advertise>]     accepted, deltas follow
    //     RDIST|<origin>|<num,ip,machine,seq>;...   directory delta
    //     RDROP|<origin>|<num>,<num>              these numbers went away
    //     CONF_HOST|<roomId>|<relayId>            this relay is mixing that room
    //                                             (its own host may have hung up)
    //     XF|<hops>|<fromNum>|<line>              a client line, forwarded
    //     RKNEW|<hops>|<endpoint>|<relayId>      "this relay exists too"
    //     ERR|norelay|<reason>                     policy refused the link
    //   client -> server (relay discovery, so a device can find the mesh
    //   without being told one address by hand):
    //     RLIST|                                which relays do you know about?
    //   server -> client:
    //     RLIST|<host:port,...>                 relays reachable from here
    // =====================================================================

    public sealed class CallServer : IDisposable
    {
        public const int DEFAULT_PORT = 45675;
        // Hop ceiling for a forwarded line. Four is enough for a friendly mesh
        // and bounds how far one message can bounce, which bounds both latency
        // and how much of the graph a single frame can learn about.
        public const int MaxHops = 4;

        private TcpListener _lis;
        private Thread _accept;
        private volatile bool _run;
        // Diagnostic seam: called with every raw line this relay reads, before it
        // is parsed. Left null in production, where it costs one null check per
        // line. It exists so a test can prove what an intermediate relay actually
        // received on the wire instead of trusting what the relay logged.
        public Action<string> WireIn;
        private readonly object _mapLock = new object();
        private readonly Dictionary<string, Conn> _byNumber = new Dictionary<string, Conn>();
        public event Action<string> Log;
        public bool Running { get { return _run; } }

        // ── Federation state ──────────────────────────────────────────────
        // Identifies this relay instance to its peers. Random per boot on
        // purpose: a replayed id from an old incarnation would inherit stale
        // directory entries, which is exactly the bug sequence numbers exist
        // to avoid.
        public readonly string RelayId;
        public string RelayName = Environment.MachineName;
        // Who may use this PC as a hop for traffic that is not mine.
        // "everyone" | "allowed" (default) | "nobody". Hosting has always meant
        // serving the clients that register here; this policy is only about
        // linking to other relays, because that is what makes you carry
        // strangers' traffic.
        public string RelayPolicy = "allowed";
        public string RelayAllow = "";        // comma list: hosts, host:port or relay names
        public string RelayLinks = "";        // comma list: relays to dial out to (host:port)
        // What this relay tells others to dial. Left empty it falls back to the
        // address a link happened to arrive on, which is often a private LAN
        // address and therefore useless to a peer elsewhere.
        public string RelayAdvertise = "";
        public bool UseTls = false;
        public string StartError { get; private set; }
        private X509Certificate2 _tlsCert;
        // ── Reachability, asked for rather than assumed ─────────────────
        // Set by whoever hosts the relay. `RelayPortMap` is the request to open the
        // router's port through UPnP; `PublicAddress` is what the router reported after
        // it worked, and becomes the advertised address. Both default to nothing:
        // a relay that has not asked does not touch a router, and does not claim an
        // address it has not proven reachable.
        public bool RelayPortMap = false;
        public string PublicAddress = "";
        public int RelayStoreKb = 2048;       // queue budget for other relays' offline mail
        public int RelayBandwidthKbps = 0;    // 0 = uncapped (courtesy cap, see Forward)
        // ── Mail that outlives the machine that first held it ───────────────
        // A relay used to forget every unread message when its PC restarted, and
        // mail for somebody who never came back to THAT relay was unreachable
        // forever. Two changes fix that: each message is a file, and a consenting
        // relay hands copies to the relays it is linked to, so the message is
        // waiting wherever the recipient next appears. Content is already sealed,
        // so a carrier cannot read what it is storing.
        //   off (default) - hold mail here only, as before
        //   on            - also give copies to links, up to a hop and quota cap
        public bool RelayCarryMail = false;
        // One PC hosting two relays (and any test that does) must not share a mail
        // folder: each node would recover the other's queue from disk and deliver it
        // twice, which is exactly the failure carrying mail is meant to avoid.
        public string MailDirOverride = "";
        public string LedgerFileOverride = "";
        public string LeaseFileOverride = "";
        // ── Number leases ──────────────────────────────────────────────
        // The token check used to be real only while the owner was connected.
        // See NumberLease.cs for what this does and, more usefully, what it does
        // not do about number theft.
        NumberLeaseBook _leases;
        private string _leasePath;
        // Unlike the other lazy paths (which only recompute a string), this one
        // builds an object that holds state: two registrations arriving at the same
        // moment could each read the file into their own book, one would win, and
        // the lease the other just recorded would be gone. So the init is guarded.
        readonly object _leaseInitLock = new object();

        NumberLeaseBook Leases
        {
            get
            {
                NumberLeaseBook b = _leases;
                if (b != null) return b;
                lock (_leaseInitLock)
                {
                    if (_leases == null)
                    {
                        _leasePath = string.IsNullOrEmpty(LeaseFileOverride)
                            ? Path.Combine(Home.Dir, "number_leases.txt") : LeaseFileOverride;
                        _leases = new NumberLeaseBook(_leasePath);
                        // A lease book that cannot write itself down is a number that is
                        // stealable again at the next restart, so say so instead of
                        // accepting the claim and quietly losing it.
                        _leases.Warn += delegate(string m) { Emit(m); };
                    }
                    return _leases;
                }
            }
        }

        public int LeaseCount { get { return Leases.Count; } }

        // Does the presented key really say "this number is mine"? Checked with the
        // key that is claimed to have signed it, the same way the PUBK directory
        // proves a key belongs to a number: nobody who lacks the private half can
        // produce this, and nobody can point a lease at a key that never agreed.
        static bool OwnProofValid(string number, string pubB64, string sigB64)
        {
            if (string.IsNullOrEmpty(number) || string.IsNullOrEmpty(pubB64) ||
                string.IsNullOrEmpty(sigB64)) return false;
            byte[] sig;
            try { sig = Convert.FromBase64String(sigB64); } catch { return false; }
            try
            {
                return Identity.Verify(pubB64,
                    Encoding.UTF8.GetBytes(NumberLeaseBook.OwnClaim(number)), sig);
            }
            catch { return false; }
        }

        // For `--serve --release-number=`: deliberately giving up one lease, so a
        // lockout is always escapable without editing a file by hand.
        public bool ReleaseLease(string number)
        {
            bool gone = Leases.Release((number ?? "").Trim());
            Emit(gone ? "Lease released for " + number + " - the next registration will claim it"
                      : "No lease on file for " + number);
            return gone;
        }

        const int MailMaxHops = 2;
        const int MailMaxPerRecipient = 50;
        const int MailMaxFiles = 2000;            // a hard ceiling on our own disk
        static readonly long MailTtl = 7L * TimeSpan.TicksPerDay;
        public long MailDelivered;                // handed to a client, wherever it turned up
        public long MailReceived;                 // custody accepted from another relay
        // Self-forming mesh: when on, a relay dials the relays its existing links
        // told it about, so two friends who each linked to one common relay end up
        // in one graph without anyone typing a second address. Off by default:
        // dialing out means *this* machine volunteers to carry for a stranger, and
        // only the operator can agree to that. Their side still has to accept us,
        // so turning this on cannot make anyone else carry anything.
        public bool RelayAutoMesh = false;
        const int MaxRelayHops = 3;           // how far one RKNEW may travel

        // ── Onion forwarding ───────────────────────────────────────────────
        // What a forwarded line gives away is not its text - ECHAT seals that -
        // it is the pair: "MSG|<target>|<sender>|..." names both ends to every
        // relay in between. Layering puts each hop's instruction in an envelope
        // only that hop can open, so an intermediate learns who to hand the next
        // layer to and nothing else. Only the ingress relay (which the sender
        // chose, and which therefore already knows both ends) and the exit relay
        // (which is the target's own relay) ever hold both numbers.
        //   off   - forward as now: every hop sees the pair
        //   best  - layer when every hop's key is known, forward plainly otherwise
        //   force - refuse the line rather than leak the pair
        // Off by default because it is a real trade: ~1 KB of envelope per hop per
        // message, and it makes a carried message impossible to explain to the
        // person whose PC carried it.
        public string RelayOnion = "off";
        const int OnionMaxHops = 4;

        // The three accepted spellings, with anything unrecognised collapsing to
        // "off". A typo in a config file must never land on "force", because
        // force is the setting that refuses traffic instead of carrying it.
        public static string NormalizeOnion(string s)
        {
            if (string.IsNullOrEmpty(s)) return "off";
            s = s.Trim().ToLowerInvariant();
            if (s == "best" || s == "on" || s == "try" || s == "true") return "best";
            if (s == "force" || s == "enforce" || s == "strict") return "force";
            return "off";
        }

        public long OnionBuilt;        // circuits this relay started
        public long OnionCarried;      // layers this relay opened for someone else
        public long OnionRefused;      // layers that did not open, or had no route
        // ── Media carried between relays ──────────────────────────────────
        // "The call went through the mesh" is a claim about somebody else's machine,
        // and the two endpoints cannot witness it: on one laptop the direct UDP path
        // works and the call sounds identical either way. So the relay counts it.
        //   MediaForwarded - RM frames this relay handed toward another relay
        //   MediaDelivered - RM frames this relay wrote to a local client
        // Both are on the status line, and a cross-relay call test that grows neither
        // is a call that went direct and proved nothing.
        public long MediaForwarded;
        public long MediaForwardedBytes;
        public long MediaDelivered;
        // How many "is this number online?" questions this relay has answered. It exists
        // for the same reason the media counters do: "the caller's own list was cold and
        // the relay saved it" is a claim about a race, and without a number on it the
        // statement can only be asserted, never observed.
        public long WhoAsked;

        // Per-call media token registry: maps random token → number and back.
        // When a call starts, both sides send their token in INVITE/ACCEPT as
        // "mtoken=<hex>". The relay registers both, so RM lines can carry tokens
        // instead of real numbers and intermediate relays see no identity at all.
        // Tokens are 8 random bytes (16 hex chars), generated per call.
        private readonly Dictionary<string, string> _tokenToNumber = new Dictionary<string, string>();
        private readonly Dictionary<string, string> _numberToToken = new Dictionary<string, string>();
        private readonly object _tokenLock = new object();

        public void RegisterMediaToken(string number, string token)
        {
            if (string.IsNullOrEmpty(number) || string.IsNullOrEmpty(token)) return;
            lock (_tokenLock)
            {
                _tokenToNumber[token] = number;
                _numberToToken[number] = token;
            }
        }

        public void ClearMediaToken(string number)
        {
            if (string.IsNullOrEmpty(number)) return;
            lock (_tokenLock)
            {
                string token;
                if (_numberToToken.TryGetValue(number, out token))
                {
                    _tokenToNumber.Remove(token);
                    _numberToToken.Remove(number);
                }
            }
        }

        private string ResolveToken(string tokenOrNumber)
        {
            lock (_tokenLock)
            {
                string num;
                if (_tokenToNumber.TryGetValue(tokenOrNumber, out num)) return num;
            }
            return tokenOrNumber; // fall back: it's already a number
        }
        public long WhoAnswered;

        private readonly object _keyLock = new object();
        private Identity _relayKey;                  // this relay's long-term key
        private PeerIdentityBook _relayKeys;         // pinned by advertise endpoint
        private string _keyPath, _bookPath;          // where those two live, for the warning text
        // One PC hosting more than one relay (and any test that does) needs a key
        // file per node: if every relay fell back to Home\relay_id.key they would
        // all share one identity, and "an intermediate cannot open the layer meant
        // for the destination" is worthless when the intermediate holds the
        // destination's private key.
        public string RelayKeyFile = "";
        public string RelayBookFile = "";
        private readonly Dictionary<string, string> _relayPubs = new Dictionary<string, string>();  // relayId -> pub b64
        private readonly Dictionary<string, string> _relaySigs = new Dictionary<string, string>();  // relayId -> the owner's own claim over its id
        private readonly Dictionary<string, string> _relayAdv = new Dictionary<string, string>();  // relayId -> advertise endpoint we pin it under
        private readonly Dictionary<string, Conn> _keySrc = new Dictionary<string, Conn>();        // relayId -> link it arrived on

        // Is there any way this node could end up linking? If not, it needs no
        // relay identity yet, and creating one would only put a private key file
        // in a folder that has not asked to be part of a mesh.
        // Public so a headless relay can decide whether it has a relay identity to
        // publish without touching the RelayKey getter, which creates one on demand -
        // and creating a private key because somebody asked is exactly what this gate
        // exists to prevent.
        public bool MayLink()
        {
            if (RelayPolicy == "nobody") return false;
            if ((RelayLinks ?? "").Trim().Length > 0) return true;
            if ((RelayAllow ?? "").Trim().Length > 0) return true;
            if (RelayAutoMesh) return true;
            return RelayPolicy == "everyone";
        }

        // The relay's own keypair, in its own file. Kept separate from the app
        // identity on purpose: pointing a relay at somebody's profile would make
        // the relay sign routing claims with the key that backs their safety
        // numbers, and a relay is a different role with a different lifetime.
        public Identity RelayKey
        {
            get
            {
                lock (_keyLock)
                {
                    if (_relayKey == null)
                    {
                        try
                        {
                            _keyPath = string.IsNullOrEmpty(RelayKeyFile)
                                ? Path.Combine(Home.Dir, "relay_id.key") : RelayKeyFile;
                            _bookPath = string.IsNullOrEmpty(RelayBookFile)
                                ? Path.Combine(Home.Dir, "relay_keys.txt") : RelayBookFile;
                            _relayKey = new Identity(_keyPath);
                            _relayKeys = new PeerIdentityBook(_bookPath);
                        }
                        catch { _relayKey = null; }
                    }
                    return _relayKey;
                }
            }
        }

        // Key we can seal a layer to for one relay, if we have one that opened
        // cleanly. Null means "this hop cannot be part of a circuit".
        string PubOf(string relayId)
        {
            if (string.IsNullOrEmpty(relayId)) return null;
            lock (_keyLock)
            {
                string v;
                return _relayPubs.TryGetValue(relayId, out v) ? v : null;
            }
        }

        private readonly object _linkLock = new object();
        private readonly Dictionary<string, Link> _links = new Dictionary<string, Link>();   // by endpoint
        private readonly Dictionary<string, RemoteRec> _remote = new Dictionary<string, RemoteRec>();
        private readonly Dictionary<string, long> _seenSeq = new Dictionary<string, long>();
        // Other relays we have heard of, by advertised address: from our own
        // links and from RLINK handshakes. Referral is how a device joins the
        // mesh without somebody typing an IP address.
        private readonly Dictionary<string, string> _knownRelays = new Dictionary<string, string>(); // endpoint -> name
        private long _queueBytes;             // what we are holding for peers
        private long _fwdWindowBytes;         // bandwidth counter, reset per second
        private int _fwdWindowTick;
        private long _dirSeq;

        private sealed class RemoteRec
        {
            public string Number;
            public string Ip;
            public string Machine;
            public string Origin;     // relay id that owns this registration
            public string Endpoint;   // how we reach that relay
            public long Seq;
        }

        private sealed class Link
        {
            public string Endpoint;        // host:port we connected to (outbound)
            public string PeerRelayId = "";
            public string PeerName = "";
            public string PeerAdvertise = "";   // where others can dial that relay
            public Conn C;
            public volatile bool Up;
            public Thread Reader;
        }

        public int RemotePeerCount { get { lock (_mapLock) return _remote.Count; } }
        public int LinkCount { get { lock (_linkLock) return _links.Count; } }
        public long QueuedBytesForPeers { get { return Interlocked.Read(ref _queueBytes); } }
        // Endpoints this relay has heard of, for the Settings screen.
        public List<string> KnownRelayEndpoints
        {
            get
            {
                List<string> outp = new List<string>();
                lock (_linkLock) outp.AddRange(_knownRelays.Keys);
                return outp;
            }
        }

        // The address to hand out. An empty setting means "whatever the peers can
        // reach me at", which the operator usually knows best from the Connect
        // pane; falling back to a locally guessed IP is better than saying
        // nothing, but it is very often a private address.
        public string AdvertiseAddress()
        {
            string address = "";
            if (!string.IsNullOrEmpty(RelayAdvertise)) address = RelayAdvertise.Trim();
            // The address the router says this machine is, when the owner asked for a
            // port mapping and got one. It goes above the local guess because a LAN
            // address is exactly what a friend cannot route to - and an advertised
            // address that nobody else can reach is how a relay ends up online for
            // nobody but itself.
            if (address.Length == 0 && !string.IsNullOrEmpty(PublicAddress)) address = PublicAddress.Trim();
            try
            {
                if (address.Length == 0)
                {
                    IPAddress ip = VoipService.GetLocalIp();
                    if (ip != null && !IPAddress.Any.Equals(ip))
                        address = (ip.AddressFamily == AddressFamily.InterNetworkV6 ? "[" + ip.ToString() + "]" : ip.ToString()) +
                            ":" + (_lis != null ? ((IPEndPoint)_lis.LocalEndpoint).Port : DEFAULT_PORT);
                }
            }
            catch { }
            if (address.StartsWith("tls://", StringComparison.OrdinalIgnoreCase))
                address = address.Substring(6);
            else if (address.StartsWith("ssl://", StringComparison.OrdinalIgnoreCase))
                address = address.Substring(6);
            if (UseTls && address.Length > 0) address = "tls://" + address;
            return address;
        }

        internal static bool TryParseRelayEndpoint(string endpoint, out string host, out int port, out bool useTls)
        {
            host = "";
            port = DEFAULT_PORT;
            useTls = false;
            if (string.IsNullOrWhiteSpace(endpoint)) return false;
            string value = endpoint.Trim();
            if (value.StartsWith("tls://", StringComparison.OrdinalIgnoreCase))
            {
                useTls = true;
                value = value.Substring(6);
            }
            else if (value.StartsWith("ssl://", StringComparison.OrdinalIgnoreCase))
            {
                useTls = true;
                value = value.Substring(6);
            }
            if (value.Length == 0) return false;

            if (value[0] == '[')
            {
                int close = value.IndexOf(']');
                if (close <= 1) return false;
                host = value.Substring(1, close - 1);
                IPAddress address;
                if (!IPAddress.TryParse(host, out address) ||
                    address.AddressFamily != AddressFamily.InterNetworkV6) return false;
                string tail = value.Substring(close + 1);
                if (tail.Length > 0 && (tail[0] != ':' || !int.TryParse(tail.Substring(1), out port)))
                    return false;
            }
            else
            {
                int first = value.IndexOf(':');
                int last = value.LastIndexOf(':');
                if (first == 0) return false;
                if (first > 0 && first == last)
                {
                    host = value.Substring(0, last);
                    if (!int.TryParse(value.Substring(last + 1), out port)) return false;
                }
                else
                {
                    if (first >= 0)
                    {
                        IPAddress address;
                        if (!IPAddress.TryParse(value, out address) ||
                            address.AddressFamily != AddressFamily.InterNetworkV6) return false;
                    }
                    host = value;
                }
            }
            return host.Length > 0 && port > 0 && port < 65536;
        }

        void RememberRelay(string endpoint, string name)
        {
            if (string.IsNullOrEmpty(endpoint)) return;
            endpoint = endpoint.Trim();
            if (endpoint.Length == 0) return;
            bool fresh = false;
            lock (_linkLock)
            {
                string had;
                fresh = !_knownRelays.TryGetValue(endpoint, out had) || had != (name ?? "");
                _knownRelays[endpoint] = name ?? "";
            }
            // Only the first sight of an address costs a write; gossip repeats it
            // constantly and rewriting a file per rumour would be all disk and no mesh.
            if (fresh) WriteLedger();
        }

        // ── The relay ledger ────────────────────────────────────────────
        // Every p2p system needs to meet somebody it already trusts, and there is no
        // way to engineer that away - but the app can stop forgetting the answer.
        // Anything this node has heard of with a real diallable address is kept, with
        // its age, so a relay that restarts rejoins the graph it was part of instead
        // of waiting for someone to type an address again. Entries older than a month
        // are dropped: a dead address that is referred forever is worse than none.
        const long LedgerMaxAge = 30L * TimeSpan.TicksPerDay;
        private readonly Dictionary<string, long> _ledgerSeen = new Dictionary<string, long>();
        private string _ledgerPath;

        string LedgerPath
        {
            get
            {
                if (_ledgerPath == null)
                    _ledgerPath = string.IsNullOrEmpty(LedgerFileOverride)
                        ? Path.Combine(Home.Dir, "relay_ledger.txt") : LedgerFileOverride;
                return _ledgerPath;
            }
        }

        void LoadLedger()
        {
            try
            {
                if (!File.Exists(LedgerPath)) return;
                int kept = 0;
                foreach (string ln in File.ReadAllLines(LedgerPath))
                {
                    string[] p = ln.Split('|');
                    if (p.Length < 2 || p[0].Length == 0) continue;
                    long seen;
                    if (!long.TryParse(p[1], NumberStyles.None, CultureInfo.InvariantCulture, out seen)) continue;
                    if (DateTime.Now.Ticks - seen > LedgerMaxAge) continue;
                    if (p[0] == AdvertiseAddress()) continue;
                    lock (_linkLock) _knownRelays[p[0]] = "";
                    _ledgerSeen[p[0]] = seen;
                    kept++;
                }
                if (kept > 0) Emit("Ledger: " + kept + " relay(s) remembered from " + LedgerPath);
            }
            catch { }
        }

        void WriteLedger()
        {
            try
            {
                StringBuilder sb = new StringBuilder();
                long now = DateTime.Now.Ticks;
                lock (_linkLock)
                {
                    foreach (KeyValuePair<string, string> kv in _knownRelays)
                    {
                        if (kv.Key.Length == 0 || kv.Key.StartsWith("in:", StringComparison.Ordinal)) continue;
                        long seen;
                        if (!_ledgerSeen.TryGetValue(kv.Key, out seen))
                        {
                            // A ledger entry we are only now hearing about: it becomes
                            // live the moment we write it, not at some guessed date.
                            _ledgerSeen[kv.Key] = now;
                            seen = now;
                        }
                        sb.Append(kv.Key).Append('|').
                           Append(seen.ToString(CultureInfo.InvariantCulture)).Append('|').
                           Append(kv.Value ?? "").Append('\n');
                    }
                }
                // Same swap the mail, the key sheet and the leases use. Writing this
                // path in place held it open with no sharing, so anything reading the
                // ledger during a save threw; and a half-written ledger loses the
                // relays it was supposed to remember, which is the whole point of it.
                StateFile.WriteAtomic(LedgerPath, sb.ToString());
            }
            catch { }
        }

        // For the Settings screen: what this node would re-dial if the mesh option is
        // on, whether or not this session has heard of them.
        public List<string> LedgerEndpoints
        {
            get
            {
                List<string> outp = new List<string>();
                lock (_linkLock) foreach (string k in _knownRelays.Keys) outp.Add(k);
                return outp;
            }
        }

        // Tell one link about the other relays we know of. This is what turns a
        // set of pairwise friendships into one graph: A and C, who both link to
        // B, each learn the other exists without anybody typing an address.
        void GossipRelays(Conn to)
        {
            if (to == null || !to.IsLink || to.W == null) return;
            string mine = AdvertiseAddress();
            List<string> rows = new List<string>();
            lock (_linkLock)
            {
                foreach (KeyValuePair<string, string> kv in _knownRelays)
                {
                    if (kv.Key == mine) continue;
                    if (kv.Key == to.PeerAdvertise) continue;      // they told us, no echo
                    if (kv.Key == to.PeerEndpoint) continue;
                    // Exactly four fields, like every other line here: the read
                    // loop splits on '|', 4, so a fifth field would be glued
                    // onto the endpoint and register a host that cannot be dialed.
                    rows.Add("0|" + kv.Key + "|" + RelayId);
                }
            }
            foreach (string r in rows) WriteRaw(to.W, "RKNEW|" + r);
        }

        // The other direction, and the one that is easy to miss: a relay learned
        // AFTER a link is already up would otherwise never be announced on that
        // link, so a chain only forms if the middle relay happens to dial out
        // left-to-right. Announce on learning makes the graph converge whatever
        // the dial order.
        void AnnounceRelay(string endpoint, string name, Conn except)
        {
            if (string.IsNullOrEmpty(endpoint)) return;
            string mine = AdvertiseAddress();
            if (endpoint == mine) return;
            foreach (Conn c in LinkConns(except))
            {
                if (c.PeerAdvertise == endpoint || c.PeerEndpoint == endpoint) continue;
                WriteRaw(c.W, "RKNEW|0|" + endpoint + "|" + RelayId);
            }
        }

        // A link named another relay. Recorded as a *hint*: dialling it is the
        // operator's call (RelayAutoMesh), because an outbound link commits this
        // machine to carrying traffic. Trust to be let in is still the other
        // side's policy, so a lie here buys the liar nothing but a failed dial.
        void LearnRelay(Conn from, string[] p)
        {
            int hops = 0;
            int.TryParse(p[1], out hops);
            string endpoint = p[2].Trim();
            string id = p[3].Trim();
            string name = "";
            if (hops >= MaxRelayHops) return;             // bounded flood, not a rumour mill
            if (endpoint.Length == 0 || id == RelayId) return;
            if (endpoint == AdvertiseAddress()) return;   // ourselves
            if (endpoint == from.PeerAdvertise || endpoint == from.PeerEndpoint) return;
            // No "is this from the peer it names" check: a relay re-announces
            // what it learned under its OWN id, so comparing the id with the
            // link peer rejects every useful rumour the moment the mesh is more
            // than two nodes. The hop ceiling and the already-known check bound
            // the flood instead.

            bool alreadyKnown;
            lock (_linkLock) alreadyKnown = _knownRelays.ContainsKey(endpoint);
            if (alreadyKnown) return;
            // Recorded through the ledger writer rather than by touching the map
            // here: a relay that only ever heard of a neighbour by gossip is exactly
            // the neighbour a restart needs to find again, and dialling it stays
            // behind the same consent switch as any other outbound link.
            RememberRelay(endpoint, name);
            Emit("Learned of relay " + name + " at " + endpoint +
                 (RelayAutoMesh ? " - dialling (auto-mesh is on)" : " - not dialling, add it if you want a link"));
            if (RelayAutoMesh) DialLink(endpoint, name);

            // Pass it on, one hop further, so a wide mesh still converges.
            foreach (Conn c in LinkConns(from))
            {
                if (c.PeerAdvertise == endpoint) continue;
                WriteRaw(c.W, "RKNEW|" + (hops + 1) + "|" + endpoint + "|" + id);
            }
        }

        // Turn auto-mesh on and it should act now, not whenever the next rumour
        // happens to arrive: dial everything already known.
        public void ReconsiderMesh()
        {
            if (!RelayAutoMesh || !_run) return;
            string mine = AdvertiseAddress();
            List<KeyValuePair<string, string>> known = new List<KeyValuePair<string, string>>();
            lock (_linkLock)
            {
                foreach (KeyValuePair<string, string> kv in _knownRelays)
                    if (kv.Key != mine) known.Add(kv);
            }
            foreach (KeyValuePair<string, string> kv in known) DialLink(kv.Key, kv.Value);
        }

        // Start one outbound link, if we are not already talking to that address.
        void DialLink(string endpoint, string name)
        {
            if (string.IsNullOrEmpty(endpoint)) return;
            // Committing to an outbound link is the moment this node needs an
            // identity, whether or not the settings looked like that at Start.
            // Done here, on the thread doing the dialling, so the handshake that
            // follows never stops to build a key.
            Identity key = RelayKey;
            if (key == null) Emit("Relay identity is unavailable, so this link cannot be sealed to");
            Link l = new Link { Endpoint = endpoint, PeerName = string.IsNullOrEmpty(name) ? endpoint : name };
            lock (_linkLock)
            {
                if (_links.ContainsKey(endpoint)) return;
                _links[endpoint] = l;
            }
            LinkLoop(l);
        }

        // What we will tell a client about. Our own address is excluded (they
        // are already talking to us) and so is anything we only know because a
        // client told us, to stop a referral loop poisoning the list.
        List<string> ReferrableRelays(Conn asking)
        {
            List<string> outp = new List<string>();
            string mine = AdvertiseAddress();
            lock (_linkLock)
            {
                foreach (KeyValuePair<string, string> kv in _knownRelays)
                    if (kv.Key != mine && !outp.Contains(kv.Key)) outp.Add(kv.Key);
                foreach (Link l in _links.Values)
                {
                    string ep = !string.IsNullOrEmpty(l.PeerAdvertise) ? l.PeerAdvertise : l.Endpoint;
                    if (ep.StartsWith("in:", StringComparison.Ordinal)) continue;   // ephemeral source port, useless
                    if (ep == mine || outp.Contains(ep)) continue;
                    outp.Add(ep);
                }
            }
            return outp;
        }

        public CallServer()
        {
            // Enough entropy that two relays on the same machine, or the same
            // machine restarted, never collide on an id and adopt each other's
            // stale directory rows.
            RelayId = DateTime.Now.Ticks.ToString("x") + "-" +
                      Guid.NewGuid().ToString("N").Substring(0, 8);
        }

        // ── Conference rooms ─────────────────────────────────────────────
        // A room is a set of registered numbers plus a real-time mixer. The
        // mixer runs on the media cadence (20 ms): it takes the newest frame
        // from every member, gates and levels each stream on its own, then
        // sums. Each member receives the sum of everyone *except themselves*,
        // so nobody gets their own voice echoed back.
        //
        // Per-stream AGC is not decoration. In a group the loudest mic would
        // otherwise swallow the room, and N open mics also add N noise floors,
        // so quiet streams are attenuated instead of being summed, and each
        // active stream is levelled toward a target that shrinks as members
        // join (headroom), which keeps the sum inside Int16 without clipping.
        private const int CONF_FRAME_BYTES = 640;        // 20 ms @ 16 kHz mono 16-bit
        private const int CONF_MAX_MEMBERS = 9;
        private const int CONF_MAX_ROOMS = 32;
        private const int CONF_STALE_MS = 120;           // older than this = not speaking
        private const float CONF_TARGET_RMS = 2600f;     // ~8% of full scale
        private const float CONF_GATE_RMS = 260f;        // below this = room tone
        private const float CONF_NOISE_DUCK = 0.2f;      // gain applied to gated streams
        private readonly Dictionary<string, ConferenceRoom> _rooms = new Dictionary<string, ConferenceRoom>();
        private readonly object _roomLock = new object();

        private sealed class ConfStream
        {
            public short[] Mixed;         // last frame, gated + AGC'd, inside room.Total
            public int LastTick;          // Environment.TickCount of that frame
            public float Gain = 1f;       // AGC state, carried between frames
            public bool Muted;
            public int Level;             // 0-100 speech level for the UI
        }

        private sealed class ConferenceRoom
        {
            public string RoomId;
            // Members and Streams are mutated/joined under MixLock. _roomLock
            // guards the room dictionary only, so the mix thread never sees a
            // List<string> change mid-iteration.
            public readonly List<string> Members = new List<string>();
            public readonly Dictionary<string, ConfStream> Streams = new Dictionary<string, ConfStream>();
            // Members that live on ANOTHER relay. Each is a shadow connection: it
            // has no socket of its own, it writes through the link to the relay
            // that hosts them. One mixer per room, however many relays the
            // members sit on - and the roster therefore has one source of truth.
            public readonly Dictionary<string, Conn> Shadow = new Dictionary<string, Conn>();
            public readonly object MixLock = new object();
            public int[] Total;             // running sum of every live stream
            public int TotalLen;
            public int TalkTickCounter;     // arrivals since the last CONF_TALK

            public ConfStream GetOrCreate(string num)
            {
                ConfStream s;
                if (!Streams.TryGetValue(num, out s)) { s = new ConfStream(); Streams[num] = s; }
                return s;
            }
        }

        // ── Rooms that span relays ──────────────────────────────────────
        // The room id already names whoever opened it ("conf-<number>-<ticks>"),
        // and the federated directory can already route to that number wherever
        // it registered. So a cross-relay room needs no new protocol at all: a
        // line for a room owned elsewhere is forwarded to the owner's relay,
        // which keeps a shadow connection for that member so the mixed audio and
        // the roster come back the same way they went out.
        //
        // Ownership is derived, not negotiated: the room is ours to mix exactly
        // when its owner number is registered here locally. Nothing to agree on,
        // nothing to keep in sync, and it self-heals if the owner reconnects.
        static string RoomOwnerNumber(string roomId)
        {
            if (string.IsNullOrEmpty(roomId) || !roomId.StartsWith("conf-", StringComparison.Ordinal)) return "";
            string rest = roomId.Substring(5);
            int dash = rest.IndexOf('-');
            if (dash <= 0) return "";
            string num = rest.Substring(0, dash);
            return RegexIsNumber(num) ? num : "";
        }

        bool IsLocalNumber(string number)
        {
            Conn c;
            lock (_mapLock) return _byNumber.TryGetValue(number, out c) && c != null && !c.IsLink;
        }

        bool IsRemoteNumber(string number)
        {
            RemoteRec r;
            lock (_mapLock) return _remote.TryGetValue(number, out r);
        }

        // The connection that reaches a member: their own socket if they are
        // registered here, otherwise the shadow standing in for their relay.
        Conn MemberConn(ConferenceRoom room, string number)
        {
            Conn c;
            if (room != null)
            {
                // Shadow is guarded by MixLock like everything else room-scoped.
                lock (room.MixLock) { if (room.Shadow.TryGetValue(number, out c)) return c; }
            }
            lock (_mapLock) { if (_byNumber.TryGetValue(number, out c)) return c; }
            return null;
        }

        // Write a room line to one member, wrapping it for the link when that
        // member lives somewhere else.
        void SendTo(Conn c, string line)
        {
            if (c == null || c.W == null) return;
            if (c.ShadowMember) WriteRaw(c.W, "XF|1|" + c.Number + "|" + line);
            else WriteRaw(c.W, line);
        }

        // The room verbs, routed: ours to mix, or onwards to whoever owns them.
        // Returns false when nobody could take it.
        bool ConfDispatch(Conn conn, string inner, string roomId) { return ConfDispatch(conn, inner, roomId, 0); }

        bool ConfDispatch(Conn conn, string inner, string roomId, int hops)
        {
            string owner = RoomOwnerNumber(roomId);
            string verb = inner.Split('|')[0];
            // A room is mixed where it lives. The owner hanging up does not stop the
            // mixer - the other members are still talking to it right now - so routing
            // purely by the owner's number made a live call unreachable, which is
            // worse than ending it because nobody was told.
            bool ours = owner.Length == 0 || IsLocalNumber(owner) || RoomLivesHere(roomId);
            if (!ours)
            {
                if (IsRemoteNumber(owner))
                {
                    // Forwarded as a client line addressed to the owner: their
                    // relay recognises the room and keeps a shadow for this member.
                    return Forward(conn, owner, conn.Number, hops, inner);
                }
                // The owner is unreachable, but a relay has told us it is mixing this
                // room anyway. That route is the only way a member who joins after the
                // host hung up can get in.
                if (ForwardToRoomHost(roomId, conn.Number, hops, inner)) return true;
                // The owner is nobody this relay can reach *yet*. A join is not
                // noise: somebody pressed "join" and is waiting. Directory gossip
                // normally lands within a few hundred milliseconds of this, so the
                // join is parked and replayed when the route appears, and only
                // refused if it does not.
                //
                // It used to be refused here, once, with ERR|noroom - which no
                // client even read. The member sat in a room of one, believing they
                // had joined, and the only way out was to hang up and dial again.
                if (verb == "CONF_JOIN" && ParkJoin(owner, roomId, conn, inner, hops))
                    return true;
                // A leave cancels a join that is still waiting: without this the
                // member who hung up before the gossip landed would be walked back
                // into the room by the replay, believing they were in a call.
                if (verb == "CONF_LEAVE") UnparkJoin(owner, roomId, conn.Number);
                SendTo(conn, "ERR|noroom|" + roomId);
                Emit("Room " + roomId + " is owned by " + owner + ", which is reachable from nowhere here");
                return false;
            }
            ConferenceRoom room;
            lock (_roomLock) { if (!_rooms.TryGetValue(roomId, out room)) room = null; }
            if (verb == "CONF_JOIN")
            {
                ConfJoin(roomId, conn);
                // Joining a room whose owner is away makes us its de-facto host as far
                // as the mesh is concerned; say so, or the next member's relay turns
                // them away for the same reason the owner's absence turned us away.
                if (!IsLocalNumber(owner)) AnnounceRoomHost(roomId);
                return true;
            }
            if (room == null) return false;                    // not ours, nothing to do
            if (verb == "CONF_LEAVE") { ConfLeave(roomId, conn.Number); return true; }
            if (verb == "CONF_MUTE")
            {
                string[] p = inner.Split('|');
                if (p.Length >= 3) ConfMute(roomId, conn.Number, p[2].Trim() == "1");
                return true;
            }
            if (verb == "CONF_AUDIO")
            {
                string[] p = inner.Split(new char[] { '|' }, 3);
                if (p.Length >= 3) { try { ConfAudio(roomId, conn.Number, Convert.FromBase64String(p[2])); } catch { } }
                return true;
            }
            // E2E conference audio: the relay forwards the encrypted blob to all
            // other members without decoding or mixing. Each member decrypts and
            // mixes locally, so the relay never sees plaintext audio. The room
            // key is distributed out-of-band via sealed chat.
            if (verb == "CONF_EAUDIO")
            {
                string[] p = inner.Split(new char[] { '|' }, 3);
                if (p.Length >= 3)
                {
                    ConferenceRoom eroom;
                    lock (_roomLock) { if (!_rooms.TryGetValue(roomId, out eroom)) return true; }
                    List<string> others;
                    lock (eroom.MixLock) others = new List<string>(eroom.Members);
                    others.Remove(conn.Number);
                    if (others.Count == 0) return true;
                    string msg = "CONF_EAUDIOR|" + roomId + "|" + conn.Number + "|" + p[2];
                    ConferenceRoom rr;
                    lock (_roomLock) { if (!_rooms.TryGetValue(roomId, out rr)) return true; }
                    lock (rr.MixLock)
                    {
                        foreach (string num in others)
                        {
                            Conn c = MemberConn(rr, num);
                            if (c != null) SendTo(c, msg);
                        }
                    }
                }
                return true;
            }
            if (verb == "CONF_VIDEO")
            {
                string[] p = inner.Split(new char[] { '|' }, 3);
                if (p.Length >= 3) { try { ConfVideo(roomId, conn.Number, Convert.FromBase64String(p[2])); } catch { } }
                return true;
            }
            return false;
        }

        // ── Joins that arrived before the route did ────────────────────────
        // A member whose relay has not yet learned the room owner has not failed:
        // the directory gossip normally lands a few hundred milliseconds later. So
        // the join is held briefly and replayed by whoever learns the route - the
        // link reader when an RDIST arrives, or a registration when the owner
        // connects here. Everything about holding a wish is bounded: a TTL, a cap
        // per owner, a cap in total, and a sweep that says so when it gives up.
        sealed class PendingJoin
        {
            public string Owner = "";
            public string Room = "";
            public string Member = "";
            public string Inner = "";
            public int Hops;
            public Conn Held;         // the member's conn, or the shadow standing for their relay
            public bool Remote;       // true when the member is not registered on this relay
            public long Expires;
        }

        readonly object _pendingLock = new object();
        readonly Dictionary<string, List<PendingJoin>> _pending = new Dictionary<string, List<PendingJoin>>();
        // Long enough for gossip on a cold mesh, short enough that a real failure is
        // admitted while the person is still looking at the screen. Public so a test
        // can prove the expiry instead of waiting twelve seconds for it.
        public long PendingJoinTtlMs = 12000;
        const int PendingJoinMaxOwner = 32;
        const int PendingJoinMaxTotal = 256;
        public long JoinsParked;
        public long JoinsReplayed;

        public int PendingJoinCount
        {
            get
            {
                int n = 0;
                lock (_pendingLock) foreach (List<PendingJoin> l in _pending.Values) n += l.Count;
                return n;
            }
        }

        // True when this relay has taken responsibility for the join - parked, or
        // already waiting. False when the caps are full, and the caller refuses it
        // out loud rather than holding a queue that cannot drain.
        bool ParkJoin(string owner, string roomId, Conn conn, string inner, int hops)
        {
            if (conn == null || string.IsNullOrEmpty(conn.Number) || string.IsNullOrEmpty(roomId)) return false;
            bool full = false;
            lock (_pendingLock)
            {
                List<PendingJoin> forOwner;
                if (!_pending.TryGetValue(owner, out forOwner))
                {
                    forOwner = new List<PendingJoin>();
                    _pending[owner] = forOwner;
                }
                for (int i = 0; i < forOwner.Count; i++)
                    if (forOwner[i].Room == roomId && forOwner[i].Member == conn.Number) return true;
                int total = 0;
                foreach (KeyValuePair<string, List<PendingJoin>> kv in _pending) total += kv.Value.Count;
                if (forOwner.Count >= PendingJoinMaxOwner || total >= PendingJoinMaxTotal) full = true;
                else
                {
                    forOwner.Add(new PendingJoin
                    {
                        Owner = owner,
                        Room = roomId,
                        Member = conn.Number,
                        Inner = inner,
                        Hops = hops,
                        Held = conn,
                        Remote = conn.ShadowMember,
                        Expires = DateTime.Now.Ticks + PendingJoinTtlMs * TimeSpan.TicksPerMillisecond
                    });
                    Interlocked.Increment(ref JoinsParked);
                }
            }
            if (full)
            {
                Emit("Not parking the join for " + roomId + ": already holding too many waits");
                return false;
            }
            Emit("Holding the join for " + roomId + ": #" + owner +
                 " is not routable from here yet");
            return true;
        }

        void UnparkJoin(string owner, string roomId, string member)
        {
            if (string.IsNullOrEmpty(owner)) return;
            lock (_pendingLock)
            {
                List<PendingJoin> forOwner;
                if (!_pending.TryGetValue(owner, out forOwner)) return;
                for (int i = forOwner.Count - 1; i >= 0; i--)
                    if (forOwner[i].Room == roomId && forOwner[i].Member == member) forOwner.RemoveAt(i);
                if (forOwner.Count == 0) _pending.Remove(owner);
            }
        }

        // The route just appeared (or the owner connected here): send everything
        // that was waiting for it, once. Locks are released before any writing, so
        // a peer on a saturated line cannot stop the rest of the mesh with it.
        void ReplayPendingFor(string owner)
        {
            if (string.IsNullOrEmpty(owner)) return;
            List<PendingJoin> due;
            lock (_pendingLock)
            {
                List<PendingJoin> l;
                if (!_pending.TryGetValue(owner, out l) || l.Count == 0) return;
                due = new List<PendingJoin>(l);
                _pending.Remove(owner);
            }
            bool local = IsLocalNumber(owner);
            foreach (PendingJoin pj in due)
            {
                if (pj.Held == null) continue;
                Conn c = pj.Held;
                if (!pj.Remote)
                {
                    // Re-looked-up: they may have re-registered in the meantime, and
                    // the socket parked a moment ago is then a dead one.
                    Conn fresh;
                    lock (_mapLock) { _byNumber.TryGetValue(pj.Member, out fresh); }
                    if (fresh == null || fresh.IsLink) continue;    // they hung up; nothing to join
                    c = fresh;
                }
                if (local)
                {
                    ConfJoin(pj.Room, c);
                    Interlocked.Increment(ref JoinsReplayed);
                    Emit("Replayed the held join of " + pj.Member + " into " + pj.Room);
                }
                else if (IsRemoteNumber(owner))
                {
                    if (Forward(c, owner, pj.Member, pj.Hops, pj.Inner))
                    {
                        Interlocked.Increment(ref JoinsReplayed);
                        Emit("Replayed the held join of " + pj.Member + " toward " + pj.Room);
                    }
                    else SendTo(c, "ERR|noroom|" + pj.Room);
                }
                else SendTo(c, "ERR|noroom|" + pj.Room);
            }
        }

        // Waiting is not permanent. Anything that ran out its hold is refused out
        // loud, on the relay's existing 5 s upkeep beat.
        void SweepPendingJoins()
        {
            List<PendingJoin> expired;
            lock (_pendingLock)
            {
                expired = null;
                long now = DateTime.Now.Ticks;
                foreach (KeyValuePair<string, List<PendingJoin>> kv in _pending)
                    for (int i = kv.Value.Count - 1; i >= 0; i--)
                        if (kv.Value[i].Expires <= now)
                        {
                            if (expired == null) expired = new List<PendingJoin>();
                            expired.Add(kv.Value[i]);
                            kv.Value.RemoveAt(i);
                        }
                List<string> empty = null;
                foreach (KeyValuePair<string, List<PendingJoin>> kv in _pending)
                    if (kv.Value.Count == 0) { if (empty == null) empty = new List<string>(); empty.Add(kv.Key); }
                if (empty != null) foreach (string k in empty) _pending.Remove(k);
            }
            if (expired == null) return;
            foreach (PendingJoin pj in expired)
            {
                if (pj.Held == null) continue;
                SendTo(pj.Held, "ERR|noroom|" + pj.Room);
                Emit("Gave up on the held join for " + pj.Room + ": #" + pj.Owner +
                     " never became reachable from here");
            }
        }

        // The same replay for the case the room id cannot express: the host relay
        // announced itself, so joins parked waiting for *that* can go now. Keyed by
        // room rather than by owner number, because the owner may never route at all.
        void ReplayPendingRoom(string roomId)
        {
            if (string.IsNullOrEmpty(roomId)) return;
            List<PendingJoin> due = null;
            lock (_pendingLock)
            {
                foreach (KeyValuePair<string, List<PendingJoin>> kv in _pending)
                {
                    for (int i = kv.Value.Count - 1; i >= 0; i--)
                    {
                        if (kv.Value[i].Room != roomId) continue;
                        if (due == null) due = new List<PendingJoin>();
                        due.Add(kv.Value[i]);
                        kv.Value.RemoveAt(i);
                    }
                }
                List<string> empty = null;
                foreach (KeyValuePair<string, List<PendingJoin>> kv in _pending)
                    if (kv.Value.Count == 0) { if (empty == null) empty = new List<string>(); empty.Add(kv.Key); }
                if (empty != null) foreach (string k in empty) _pending.Remove(k);
            }
            if (due == null) return;
            foreach (PendingJoin pj in due)
            {
                if (pj.Held == null) continue;
                if (ForwardToRoomHost(roomId, pj.Member, pj.Hops, pj.Inner))
                {
                    Interlocked.Increment(ref JoinsReplayed);
                    Emit("Replayed the held join of " + pj.Member + " into " + roomId + " via its host relay");
                }
                else SendTo(pj.Held, "ERR|noroom|" + roomId);
            }
        }

        // ── A room lives where it is mixed, not where its host sits ───────
        // The room id names its owner and the directory routes to that number,
        // which is elegant while the host is connected and wrong the moment they
        // are not: the mixer is still running, still holding every other member's
        // audio and shadows, but any relay looking for the room now looks for the
        // *person*, finds no route, and turns new joins away. The call does not end
        // for the members - it becomes unreachable, which is worse, because nobody
        // is told.
        //
        // So a relay that is mixing a room announces itself as that room's host,
        // and a room is handled where it lives even if its owner has gone. The
        // announcement is a routing hint, not authority: it says "the mixer for this
        // id is reachable over this link", nothing more, and it expires.
        sealed class RoomRoute
        {
            public string Room = "";
            public string Host = "";        // relay id that is mixing it
            public Conn Link;               // how to reach that relay
            public long Seen;
        }

        readonly object _roomRouteLock = new object();
        readonly Dictionary<string, RoomRoute> _roomRoutes = new Dictionary<string, RoomRoute>();
        const long RoomRouteMaxAge = 5L * TimeSpan.TicksPerMinute;
        const int RoomRouteMax = 512;
        public long RoomsAnnounced;
        public long RoomsLearned;
        public int RoomRouteCount
        {
            get { lock (_roomRouteLock) return _roomRoutes.Count; }
        }

        // Members live in the room's own lock; this is the question the routing
        // asks, phrased once so no caller guesses at it.
        bool RoomLivesHere(string roomId)
        {
            ConferenceRoom r;
            lock (_roomLock) { if (!_rooms.TryGetValue(roomId, out r)) return false; }
            lock (r.MixLock) return r.Members.Count > 0;
        }

        Conn RoomHostLink(string roomId)
        {
            RoomRoute rt;
            lock (_roomRouteLock) { if (!_roomRoutes.TryGetValue(roomId, out rt)) return null; }
            if (rt.Link == null || rt.Link.W == null) return null;
            // A link that has since dropped cannot carry it; say nothing rather than
            // forward into a hole and let the member believe the join worked.
            if (!LinkIsLive(rt.Link)) { lock (_roomRouteLock) _roomRoutes.Remove(roomId); return null; }
            return rt.Link;
        }

        bool LinkIsLive(Conn c)
        {
            if (c == null) return false;
            lock (_linkLock)
            {
                foreach (Link l in _links.Values)
                    if (l.Up && l.C == c) return true;
            }
            return false;
        }

        // Tell everybody we are linked to that this room is mixed here. Repeated on
        // the upkeep beat while it is true, because a relay that was not linked yet
        // when the host left would otherwise never learn it - the same reason the
        // relay gossip repeats instead of only catching moments.
        void AnnounceRoomHost(string roomId)
        {
            if (string.IsNullOrEmpty(roomId)) return;
            List<Conn> links = LinkConns(null);
            if (links.Count == 0) return;
            foreach (Conn c in links) WriteRaw(c.W, "CONF_HOST|" + roomId + "|" + RelayId);
            Interlocked.Increment(ref RoomsAnnounced);
        }

        void LearnRoomHost(Conn from, string roomId, string hostId)
        {
            if (from == null || !from.IsLink) return;
            if (string.IsNullOrEmpty(roomId) || string.IsNullOrEmpty(hostId)) return;
            if (hostId == RelayId) return;              // our own echo
            bool fresh = false;
            lock (_roomRouteLock)
            {
                RoomRoute rt;
                if (!_roomRoutes.TryGetValue(roomId, out rt))
                {
                    if (_roomRoutes.Count >= RoomRouteMax) return;
                    _roomRoutes[roomId] = new RoomRoute { Room = roomId, Host = hostId, Link = from, Seen = DateTime.Now.Ticks };
                    fresh = true;
                }
                else if (rt.Host != hostId || rt.Link != from)
                {
                    rt.Host = hostId; rt.Link = from; rt.Seen = DateTime.Now.Ticks;
                    fresh = true;
                }
                else rt.Seen = DateTime.Now.Ticks;
            }
            if (!fresh) return;
            Interlocked.Increment(ref RoomsLearned);
            Emit("Room " + roomId + " is mixed on " + hostId + " over " + from.PeerEndpoint);
            foreach (Conn c in LinkConns(from))
            {
                if (c.PeerRelayId == hostId) continue;   // split horizon
                WriteRaw(c.W, "CONF_HOST|" + roomId + "|" + hostId);
            }
            // Somebody may have been waiting for exactly this.
            ReplayPendingRoom(roomId);
        }

        void DropRoomRoutesFor(string origin)
        {
            List<string> gone = null;
            lock (_roomRouteLock)
            {
                foreach (KeyValuePair<string, RoomRoute> kv in _roomRoutes)
                    if (kv.Value.Host == origin) { if (gone == null) gone = new List<string>(); gone.Add(kv.Key); }
                if (gone != null) foreach (string r in gone) _roomRoutes.Remove(r);
            }
        }

        void SweepRoomRoutes()
        {
            lock (_roomRouteLock)
            {
                long now = DateTime.Now.Ticks;
                List<string> dead = null;
                foreach (KeyValuePair<string, RoomRoute> kv in _roomRoutes)
                    if (now - kv.Value.Seen > RoomRouteMaxAge) { if (dead == null) dead = new List<string>(); dead.Add(kv.Key); }
                if (dead != null) foreach (string r in dead) _roomRoutes.Remove(r);
            }
        }

        // Forward a room line straight to the relay that announced it mixes this
        // room. Same envelope as Forward(), aimed by room id instead of by number.
        bool ForwardToRoomHost(string roomId, string envelope, int hops, string inner)
        {
            Conn target = RoomHostLink(roomId);
            if (target == null) return false;
            if (hops + 1 >= MaxHops) return false;
            WriteRaw(target.W, "XF|" + (hops + 1) + "|" + (envelope ?? "") + "|" + inner);
            return true;
        }

        // Keep the mesh told about rooms that are still live without their host, and
        // let stale routes die. Rooms are collected first and released before the
        // directory is consulted, so no room lock is ever held across a map lock.
        void UpkeepRooms()
        {
            Dictionary<string, int> live = new Dictionary<string, int>();
            lock (_roomLock)
            {
                foreach (KeyValuePair<string, ConferenceRoom> kv in _rooms)
                {
                    int n;
                    lock (kv.Value.MixLock) n = kv.Value.Members.Count;
                    if (n > 0) live[kv.Key] = n;
                }
            }
            foreach (KeyValuePair<string, int> kv in live)
            {
                string owner = RoomOwnerNumber(kv.Key);
                if (owner.Length == 0 || IsLocalNumber(owner)) continue;   // the id still routes
                AnnounceRoomHost(kv.Key);
            }
            SweepRoomRoutes();
        }

        // A member who joined through a link, seen from the room's own relay.
        Conn ShadowFor(Conn link, string number)
        {
            Conn s = new Conn { Number = number, Token = "", Machine = link.Machine, Ip = link.Ip, IsLink = true, ShadowMember = true, W = link.W };
            return s;
        }

        private void ConfJoin(string roomId, Conn conn)
        {
            ConferenceRoom room;
            int members;
            lock (_roomLock)
            {
                if (!_rooms.TryGetValue(roomId, out room))
                {
                    if (_rooms.Count >= CONF_MAX_ROOMS)
                    {
                        SendTo(conn, "ERR|conf_full|" + roomId);
                        return;
                    }
                    room = new ConferenceRoom { RoomId = roomId };
                    _rooms[roomId] = room;
                }
                lock (room.MixLock)
                {
                    if (!room.Members.Contains(conn.Number))
                    {
                        if (room.Members.Count >= CONF_MAX_MEMBERS)
                        {
                            SendTo(conn, "ERR|conf_full|" + roomId);
                            return;
                        }
                        room.Members.Add(conn.Number);
                    }
                    room.GetOrCreate(conn.Number);
                    // A member who arrived through a link needs a shadow so the
                    // mixer can send to them; a local member needs none.
                    if (conn.ShadowMember) room.Shadow[conn.Number] = conn;
                    // Counted here, not after the lock: two peers joining at the
                    // same instant otherwise report each other's totals.
                    members = room.Members.Count;
                }
            }
            Emit("Conf " + roomId + ": " + conn.Number + " joined (" + members + " members)");
            BroadcastRoster(room);
        }

        private void ConfLeave(string roomId, string number)
        {
            ConferenceRoom room;
            int remaining;
            lock (_roomLock)
            {
                if (!_rooms.TryGetValue(roomId, out room)) return;
                lock (room.MixLock)
                {
                    ConfStream gone;
                    if (room.Streams.TryGetValue(number, out gone) && gone.Mixed != null)
                        Subtract(room.Total, gone.Mixed);   // never leave a ghost in the sum
                    room.Members.Remove(number);
                    room.Streams.Remove(number);
                    room.Shadow.Remove(number);
                    remaining = room.Members.Count;
                    if (remaining == 0) _rooms.Remove(roomId);
                }
            }
            if (remaining == 0)
            {
                Emit("Conf " + roomId + ": closed (no members)");
                return;
            }
            BroadcastRoster(room);
            Emit("Conf " + roomId + ": " + number + " left (" + remaining + " remaining)");
            // The host hanging up used to be the end of the call in disguise: this
            // relay went on mixing, but every other relay routed the room by the
            // host's number and could no longer find it. Say who is mixing it now.
            if (number == RoomOwnerNumber(roomId))
            {
                AnnounceRoomHost(roomId);
                Emit("Conf " + roomId + ": the host left but " + remaining +
                     " member(s) remain - this relay is still mixing it");
            }
        }

        private void ConfMute(string roomId, string number, bool muted)
        {
            ConferenceRoom room;
            lock (_roomLock)
            {
                if (!_rooms.TryGetValue(roomId, out room)) return;
            }
            lock (room.MixLock)
            {
                ConfStream s = room.GetOrCreate(number);
                s.Muted = muted;
                if (muted)
                {
                    // Take them out of the sum now, not on their next frame: a
                    // muted member may stop transmitting altogether.
                    if (s.Mixed != null)
                    {
                        Subtract(room.Total, s.Mixed);
                        s.Mixed = null;
                    }
                    s.Level = 0;
                }
            }
        }

        // The mixer is driven by arrivals, not by a timer: every client already
        // captures on a 20 ms cadence, so a member's frame *is* the tick. A
        // server-side timer would fight Windows' ~15.6 ms sleep granularity and
        // either burst frames or starve the playout buffer.
        //
        // Each arrival refreshes that stream's slot in a running sum, then the
        // sum is shipped to every member with their own slot subtracted back off.
        // That is O(members x samples) per arrival and costs no extra latency.
        private void ConfAudio(string roomId, string fromNumber, byte[] pcm)
        {
            if (pcm == null || pcm.Length < 4) return;
            ConferenceRoom room;
            lock (_roomLock)
            {
                if (!_rooms.TryGetValue(roomId, out room)) return;
            }

            List<Conn> targets = null;
            List<string> lines = null;
            string talk = null;

            lock (room.MixLock)
            {
                if (!room.Members.Contains(fromNumber)) return;
                int samples = Math.Min(pcm.Length, CONF_FRAME_BYTES) / 2;
                if (samples <= 0) return;
                if (room.Total == null || room.TotalLen != samples)
                {
                    // Frame size changed (different client /Settings): rebuild the sum.
                    room.Total = new int[samples];
                    room.TotalLen = samples;
                    room.Streams.Clear();
                    foreach (string m in room.Members) room.Streams[m] = new ConfStream();
                }

                int now = Environment.TickCount;
                ConfStream self = room.GetOrCreate(fromNumber);

                // A muted member's frames never enter the sum. Returning early
                // still lets them hear the room, because everyone else's
                // arrivals fan out to them on their own.
                if (self.Muted)
                {
                    if (self.Mixed != null)
                    {
                        Subtract(room.Total, self.Mixed);
                        self.Mixed = null;
                    }
                    self.Level = 0;
                    return;
                }

                // Anyone who stopped transmitting must leave the running sum,
                // or the room keeps hearing their last frame on a loop.
                // unchecked: TickCount rolls to int.MinValue after ~25 days of
                // uptime, and a signed delta would then read as hugely negative.
                foreach (string m in room.Members)
                {
                    ConfStream s;
                    if (!room.Streams.TryGetValue(m, out s)) continue;
                    if (m != fromNumber && s.Mixed != null && unchecked(now - s.LastTick) > CONF_STALE_MS)
                    {
                        Subtract(room.Total, s.Mixed);
                        s.Mixed = null;
                        s.Level = 0;
                    }
                }

                // Decode this frame and level it independently of everyone else.
                short[] buf = new short[samples];
                double acc = 0;
                for (int j = 0; j < samples; j++)
                {
                    short v = (short)(pcm[j * 2] | (pcm[j * 2 + 1] << 8));
                    buf[j] = v;
                    acc += (double)v * v;
                }
                float rms = (float)Math.Sqrt(acc / samples);

                if (rms < CONF_GATE_RMS)
                {
                    // Room tone: duck it instead of summing it raw, otherwise N
                    // open-but-quiet mics raise the floor for the whole group.
                    for (int j = 0; j < samples; j++) buf[j] = (short)(buf[j] * CONF_NOISE_DUCK);
                    self.Level = 0;
                }
                else
                {
                    // Attack fast, release slow: catch a shout before it clips the
                    // room, but do not let a pause make the mix pump.
                    float want = CONF_TARGET_RMS / (rms + 1f);
                    if (want > 4f) want = 4f;
                    else if (want < 0.35f) want = 0.35f;
                    self.Gain += (want - self.Gain) * (want > self.Gain ? 0.08f : 0.02f);
                    for (int j = 0; j < samples; j++)
                    {
                        int v = (int)(buf[j] * self.Gain);
                        buf[j] = (short)(v > 32767 ? 32767 : (v < -32768 ? -32768 : v));
                    }
                    self.Level = (int)Math.Min(100, rms / CONF_TARGET_RMS * 55);
                }

                if (self.Mixed != null) Subtract(room.Total, self.Mixed);
                self.Mixed = buf;
                self.LastTick = now;
                Add(room.Total, buf);

                int speaking = 0;
                foreach (ConfStream s in room.Streams.Values) if (s.Level > 0) speaking++;

                // Headroom shrinks as more voices join: k streams at target level
                // would sum past full scale and clip hard.
                float head = speaking > 1 ? (float)(1.0 / Math.Sqrt(speaking)) * 1.4f : 1f;
                if (head > 1f) head = 1f;

                targets = new List<Conn>();
                lines = new List<string>();
                for (int r = 0; r < room.Members.Count; r++)
                {
                    string num = room.Members[r];
                    ConfStream rs;
                    if (!room.Streams.TryGetValue(num, out rs)) continue;
                    short[] own = rs.Mixed;
                    // Nothing to hear: skip the send rather than push 640 bytes of
                    // silence per tick (a group call idles a lot).
                    if (speaking == 0) continue;
                    if (speaking == 1 && rs.Level > 0) continue;   // only they are talking

                    byte[] outB = new byte[samples * 2];
                    for (int j = 0; j < samples; j++)
                    {
                        int v = (int)((room.Total[j] - (own != null && j < own.Length ? own[j] : 0)) * head);
                        if (v > 32767) v = 32767;
                        else if (v < -32768) v = -32768;
                        outB[j * 2] = (byte)(v & 0xFF);
                        outB[j * 2 + 1] = (byte)((v >> 8) & 0xFF);
                    }
                    Conn c = MemberConn(room, num);
                    if (c == null) continue;
                    targets.Add(c);
                    lines.Add("CONF_MIXED|" + roomId + "|mix|" + Convert.ToBase64String(outB));
                }

                // Throttled talking-indicator for the tile grid (level per speaker).
                // Counted in arrivals rather than clock time: one arrival per
                // member every 20 ms, so 5 arrivals is roughly 100 ms of room.
                room.TalkTickCounter++;
                if (room.TalkTickCounter >= 5)
                {
                    room.TalkTickCounter = 0;
                    StringBuilder sb = new StringBuilder();
                    sb.Append("CONF_TALK|").Append(roomId).Append('|');
                    int appended = 0;
                    foreach (string m in room.Members)
                    {
                        ConfStream s;
                        if (!room.Streams.TryGetValue(m, out s) || s.Level <= 0) continue;
                        if (appended > 0) sb.Append(',');
                        sb.Append(m).Append(':').Append(s.Level);
                        appended++;
                    }
                    talk = sb.ToString();
                }
            }

            // Sockets are written after MixLock is released: one stalled member
            // must not block the arrivals that feed the room.
            if (targets != null)
                for (int i = 0; i < targets.Count; i++) SendTo(targets[i], lines[i]);
            if (talk != null) BroadcastText(roomId, talk);
        }

        // Group video is fan-out only - the server never decodes or restitches
        // JPEGs, so a thumbnail from one member costs one write per peer.
        private void ConfVideo(string roomId, string fromNumber, byte[] jpeg)
        {
            if (jpeg == null || jpeg.Length == 0) return;
            ConferenceRoom room;
            lock (_roomLock)
            {
                if (!_rooms.TryGetValue(roomId, out room)) return;
            }
            List<string> others;
            lock (room.MixLock) others = new List<string>(room.Members);
            others.Remove(fromNumber);
            if (others.Count == 0) return;
            string msg = "CONF_VID|" + roomId + "|" + fromNumber + "|" + Convert.ToBase64String(jpeg);
            ConferenceRoom rr;
            lock (_roomLock) { if (!_rooms.TryGetValue(roomId, out rr)) return; }
            foreach (string num in others)
            {
                Conn c = MemberConn(rr, num);
                if (c != null) SendTo(c, msg);
            }
        }

        private static void Add(int[] total, short[] samples)
        {
            int n = Math.Min(total.Length, samples.Length);
            for (int j = 0; j < n; j++) total[j] += samples[j];
        }

        private static void Subtract(int[] total, short[] samples)
        {
            int n = Math.Min(total.Length, samples.Length);
            for (int j = 0; j < n; j++) total[j] -= samples[j];
        }

        private void BroadcastText(string roomId, string line)
        {
            ConferenceRoom room;
            lock (_roomLock)
            {
                if (!_rooms.TryGetValue(roomId, out room)) return;
            }
            List<string> members;
            lock (room.MixLock) members = new List<string>(room.Members);
            foreach (string num in members)
            {
                Conn c = MemberConn(room, num);
                if (c != null) SendTo(c, line);
            }
        }

        private void BroadcastRoster(ConferenceRoom room)
        {
            // Snapshot under MixLock: the mix thread iterates the same list, and
            // a join landing mid-enumeration would throw.
            List<string> members;
            lock (room.MixLock) members = new List<string>(room.Members);
            string roster = "CONF_ROSTER|" + room.RoomId + "|" + string.Join(",", members.ToArray());
            foreach (string num in members)
            {
                Conn c = MemberConn(room, num);
                if (c != null) SendTo(c, roster);
            }
        }

        private sealed class Conn
        {
            public string Number;
            public string Token;
            public string Machine;
            public string Ip;
            public TcpClient Tcp;
            public StreamWriter W;
            public readonly object WriteLock = new object();
            public long DirSeq;             // last sequence advertised for this number
            // A link is a peer relay, not a user. It never appears in the
            // directory of its own accord and cannot be the target of a call.
            public bool IsLink;
            // True when this Conn stands in for a room member that lives on
            // another relay: writes must be wrapped for the link to find them.
            public bool ShadowMember;
            public string PeerRelayId = "";
            public string PeerEndpoint = "";
            // What the peer relay said it can be dialled on. Gossip needs it on
            // the Conn, because LinkConns() hands out Conns, not Links.
            public string PeerAdvertise = "";
            // Per-call media token: randomized per call setup, used as the
            // to/from on RM lines so intermediate relays see tokens not numbers.
            // Both sides learn each other's token in the INVITE/ACCEPT exchange.
            public string MediaToken = "";
        }

        private X509Certificate2 LoadTlsCertificate()
        {
            string profileDir = Home.Dir;
            string path = Path.Combine(profileDir, "relay_tls.pfx");
            if (!File.Exists(path)) return null;
            try
            {
                string password = Environment.GetEnvironmentVariable("USSD_RELAY_TLS_PFX_PASSWORD");
                if (string.IsNullOrEmpty(password))
                {
                    Emit("Set USSD_RELAY_TLS_PFX_PASSWORD before starting a TLS relay.");
                    return null;
                }
                X509Certificate2 cert = new X509Certificate2(path, password ?? "");
                if (!cert.HasPrivateKey || DateTime.Now < cert.NotBefore || DateTime.Now > cert.NotAfter)
                {
                    cert.Dispose();
                    Emit("TLS certificate must have a private key and be currently valid.");
                    return null;
                }
                return cert;
            }
            catch (Exception ex)
            {
                Emit("TLS certificate could not be loaded: " + ex.Message);
                return null;
            }
        }

        private void Emit(string s)
        {
            Hang.Trace("CallSrv emit: " + s);
            Action<string> h = Log;
            if (h != null) h(s);
        }

        public bool Start(int port)
        {
            return Start(port, false);
        }

        public bool Start(int port, bool useTls)
        {
            if (_run) return true;
            StartError = "";
            UseTls = useTls;
            if (UseTls)
            {
                _tlsCert = LoadTlsCertificate();
                if (_tlsCert == null)
                {
                    StartError = "TLS: relay_tls.pfx is missing or unusable, or its password is unavailable.";
                    Emit("TLS relay requested, but relay_tls.pfx is missing or unusable; refusing to start without TLS.");
                    return false;
                }
            }
            try
            {
                _lis = new TcpListener(IPAddress.Any, port);
                _lis.Start();
            }
            catch (Exception ex)
            {
                StartError = ex.Message;
                Emit("Call server start failed: " + ex.Message);
                if (_tlsCert != null) { _tlsCert.Dispose(); _tlsCert = null; }
                return false;
            }
            _run = true;
            // Build the relay's identity now, on the thread that is starting the
            // node, rather than lazily inside a link handshake. Making a 2048-bit
            // key costs a few hundred milliseconds on a fresh profile, and the
            // thread that pays for it is the one that has to send the directory
            // snapshot next - which looks, to everyone else, like a slow mesh.
            // Only for a node that may actually link, though: a private key is not
            // something to drop into somebody's folder because they opened the app.
            // The fingerprint is printed because a relay key is only meaningful
            // out-of-band: it is what an operator reads to a friend over the phone
            // before letting it carry their traffic.
            if (MayLink())
            {
                Identity k = RelayKey;
                if (k != null) Emit("Relay identity " + k.Fingerprint);
            }
            _accept = new Thread(AcceptLoop);
            _accept.IsBackground = true;
            _accept.Start();
            // The peer list is pushed by one dedicated thread, never inline by whoever
            // noticed a change. Its 30 s beat is the directory re-broadcast clients use
            // to self-heal if a registration was ever silently lost.
            Thread bcast = new Thread(PeersNotifyLoop);
            bcast.IsBackground = true;
            bcast.Start();
            // Anti-entropy. Announcing only on events loses information whenever a
            // relay is learned while its only possible carrier link is still down
            // - which is the normal case while a mesh is starting up. Real gossip
            // converges by repeating, not by catching every moment, and repeats
            // are free here: LearnRelay ignores anything it has already seen.
            Thread mesh = new Thread((ThreadStart)delegate
            {
                while (_run)
                {
                    Thread.Sleep(5000);
                    if (!_run) break;
                    try { foreach (Conn c in LinkConns(null)) GossipRelays(c); }
                    catch { }
                    // Same beat, other upkeep: a join that has waited long enough is
                    // refused out loud rather than held until the relay restarts.
                    try { SweepPendingJoins(); } catch { }
                    // ...and a room that outlived its host keeps announcing itself,
                    // because a relay that linked up after the host hung up has never
                    // heard the hint and would turn the next member away.
                    try { UpkeepRooms(); } catch { }
                }
            });
            mesh.IsBackground = true;
            mesh.Start();
            Emit("Call server hosting on port " + port + (UseTls ? " with TLS 1.2" : " with cleartext TCP"));
            // Anything stored while this node was off comes back before the first
            // client registers, or the first person to arrive finds an empty queue
            // and the sender got QUEUED for nothing.
            LoadMail();
            LoadLedger();
            LoadPeerKeys();
            OpenConfiguredLinks();
            // A relay that reboots should rejoin the mesh it already knew, under the
            // same consent that let it dial out before.
            ReconsiderMesh();
            return true;
        }

        public void Stop()
        {
            _run = false;
            // Wake the peer-push thread rather than letting it sit out its wait, so a
            // relay that is being torn down cannot write a directory to sockets that
            // are about to close. The tests stop relays a lot.
            lock (_peersSignal) Monitor.PulseAll(_peersSignal);
            try { if (_lis != null) _lis.Stop(); } catch { }
            _lis = null;
            // Drop every link first: their reader threads reconnect while
            // _run is true, and an accepted link socket would otherwise linger.
            lock (_linkLock)
            {
                foreach (Link l in _links.Values)
                {
                    l.Up = false;
                    try { if (l.C != null && l.C.Tcp != null) l.C.Tcp.Close(); } catch { }
                }
                _links.Clear();
            }
            lock (_mapLock)
            {
                foreach (Conn c in _byNumber.Values)
                    try { c.Tcp.Close(); } catch { }
                _byNumber.Clear();
            }
            // Rooms are pure state now (no per-room thread), so dropping the map
            // is enough; members re-join on their next CONF_JOIN after a restart.
            lock (_roomLock) { _rooms.Clear(); }
            if (_tlsCert != null)
            {
                try { _tlsCert.Dispose(); } catch { }
                _tlsCert = null;
            }
            Emit("Call server stopped.");
        }

        public void Dispose() { Stop(); }

        private void AcceptLoop()
        {
            while (_run)
            {
                TcpClient tc = null;
                try { tc = _lis.AcceptTcpClient(); }
                catch { if (!_run) return; continue; }
                TcpClient t2 = tc;
                Thread t = new Thread((ThreadStart)delegate { HandleClient(t2); });
                t.IsBackground = true;
                t.Start();
            }
        }

        private void HandleClient(TcpClient tc)
        {
            Conn conn = null;
            SslStream ssl = null;
            try
            {
                tc.ReceiveTimeout = 95000;   // clients KA every 20 s
                try { tc.Client.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.KeepAlive, true); } catch { }
                Stream transport = tc.GetStream();
                if (UseTls)
                {
                    ssl = new SslStream(transport, false);
                    ssl.AuthenticateAsServer(_tlsCert, false, (SslProtocols)3072, false);
                    transport = ssl;
                }
                StreamReader r = new StreamReader(transport, Encoding.UTF8);
                StreamWriter w = new StreamWriter(transport, Encoding.UTF8);
                w.AutoFlush = true;
                string line;
                while ((line = r.ReadLine()) != null)
                {
                    Action<string> tap = WireIn;
                    if (tap != null) tap(line);
                    string[] p = line.Split(new char[] { '|' }, 4);
                    if (p[0] == "REG" && p.Length >= 4)
                    {
                        string num = p[1].Trim();
                        string tok = (p[2] ?? "").Trim();
                        if (!RegexIsNumber(num)) { WriteRaw(w, "ERR|badnumber"); continue; }
                        // Ownership proof rides on the fourth field. The read loop splits
                        // into four, so everything a client appends after the machine name
                        // arrives glued into p[3] - which is why it is re-split here and
                        // why the machine name is the first thing in it.
                        string[] tail = (p[3] ?? "").Split('|');
                        string mach = tail.Length > 0 ? tail[0].Trim() : "";
                        string ownPub = tail.Length >= 3 ? tail[1].Trim() : "";
                        string ownSig = tail.Length >= 3 ? tail[2].Trim() : "";
                        // A presented proof that does not verify is worse than no proof:
                        // it means somebody named this number with a key that did not sign
                        // the claim. Register nothing, and say which of the two it was.
                        if (ownPub.Length > 0 && !OwnProofValid(num, ownPub, ownSig))
                        {
                            Leases.NoteFailedClaim(num);
                            WriteRaw(w, "ERR|badproof|" + num);
                            Emit("Refused registration for " + num + ": the OWNS signature does not verify"
                                 + " against the key presented (key " + Identity.FingerprintOf(ownPub) + ").");
                            continue;
                        }
                        // The lease check, not the connected-session check, is what makes
                        // an absent owner's number hard to take. Order matters: this runs
                        // before anything about this connection is recorded, so a refused
                        // claim cannot receive mail, join a room, or appear in anyone's
                        // peer list by having registered first.
                        NumberLeaseBook.Lease held = Leases.Lookup(num);
                        bool hadKeyOnFile = held != null && held.IdentityPub.Length > 0;
                        if (hadKeyOnFile && ownPub.Length == 0)
                        {
                            // Said apart from "claimed" on purpose. This caller is not an
                            // attacker - it is the real owner running an install from
                            // before ownership proofs existed. Telling them somebody else
                            // owns their number would send them chasing a thief.
                            Leases.NoteFailedClaim(num);
                            WriteRaw(w, "ERR|proofneeded|" + num);
                            Emit("Refused registration for " + num + ": it is owned by key " +
                                 Identity.FingerprintOf(held.IdentityPub) + " and this caller sent no" +
                                 " ownership proof, which an install from before that feature cannot do." +
                                 " Update that install, or start the relay with --release-number=" + num);
                            continue;
                        }
                        if (!Leases.Owns(held, tok, ownPub))
                        {
                            Leases.NoteFailedClaim(num);
                            WriteRaw(w, "ERR|claimed|" + num);
                            Emit("Refused registration for " + num + (held != null && held.IdentityPub.Length > 0
                                 ? ": this number belongs to key " + Identity.FingerprintOf(held.IdentityPub) +
                                   ", and the caller presented " +
                                   (ownPub.Length > 0 ? Identity.FingerprintOf(ownPub) : "no ownership proof at all") +
                                   ". Knowing the number_token is no longer enough."
                                 : ": the token does not match the owner on file.")
                                 + " If this install is the owner after a config reset, delete " + _leasePath
                                 + " or start the relay with --release-number=" + num);
                            continue;
                        }
                        Conn old = null;
                        bool conflict = false;
                        lock (_mapLock)
                        {
                            Conn cur;
                            if (_byNumber.TryGetValue(num, out cur) && cur != null &&
                                cur.Token != p[2] && cur.Tcp != tc)
                            {
                                // claimed by a different token (same token = reconnect, replace)
                                conflict = true;
                            }
                            if (!conflict)
                            {
                                if (cur != null && cur != conn) old = cur;
                                conn = new Conn
                                {
                                    Number = num,
                                    Token = p[2],
                                    Machine = mach,
                                    Ip = ((IPEndPoint)tc.Client.RemoteEndPoint).Address.ToString(),
                                    Tcp = tc,
                                    W = w
                                };
                                _byNumber[num] = conn;
                            }
                        }
                        if (conflict)
                        {
                            WriteRaw(w, "ERR|inuse|" + num);
                            continue;
                        }
                        if (old != null)
                        {
                            try { old.Tcp.Close(); } catch { }
                            Emit("Replaced stale session for " + num);
                        }
                        WriteRaw(w, "OK|" + num);
                        Emit("Registered " + num + " (" + conn.Machine + " from " + conn.Ip + ")");
                        // Claim last: the lease only records a number that is genuinely
                        // registered now. And if anybody tried to take it while this
                        // owner was away, they hear about it rather than reading it out of
                        // a log file they were never told to open.
                        int owed = Leases.Claim(num, tok, conn.Machine, ownPub, ownSig);
                        if (ownPub.Length > 0 && !hadKeyOnFile)
                            Emit("Number " + num + " is now owned by key " + Identity.FingerprintOf(ownPub) +
                                 " - it was leased on the shared token alone until this registration.");
                        if (owed > 0)
                        {
                            WriteRaw(w, "NOTICE|claimed-attempts|" + num + "|" + owed);
                            Emit(owed + " registration attempt(s) for " + num
                                 + " were refused since this number last connected");
                        }
                        MarkPeersDirty();
                        // Announce to linked relays so peers elsewhere can reach us.
                        Advertise(num, conn.Ip, conn.Machine);
                        // Deliver any queued messages that arrived while peer was offline
                        FlushOfflineQueue(conn);
                        // And let anybody who was waiting for this number in a room
                        // come in now: this registration is the route appearing.
                        ReplayPendingFor(num);
                        continue;
                    }
                    // ── Federation: a peer relay asking to link ─────────────
                    if (p[0] == "RLINK")
                    {
                        string rip = "";
                        try { rip = ((IPEndPoint)tc.Client.RemoteEndPoint).Address.ToString(); } catch { }
                        string remote = rip + ":" + ((IPEndPoint)tc.Client.RemoteEndPoint).Port;
                        string deny = LinkPolicyDeny(p, remote);
                        if (deny != null)
                        {
                            WriteRaw(w, "ERR|norelay|" + deny);
                            Emit("Link refused from " + remote + " (" + deny + ")");
                            continue;
                        }
                        string adv = p.Length >= 4 ? p[3].Trim() : "";
                        conn = new Conn
                        {
                            IsLink = true,
                            Number = "",
                            Token = "",
                            Machine = p.Length >= 3 ? p[2] : "relay",
                            PeerRelayId = p.Length >= 2 ? p[1] : "",
                            PeerAdvertise = p.Length >= 4 ? p[3].Trim() : "",
                            Ip = rip,
                            Tcp = tc,
                            W = w
                        };
                        Link l = new Link
                        {
                            Endpoint = "in:" + remote,
                            PeerRelayId = conn.PeerRelayId,
                            PeerName = conn.Machine,
                            PeerAdvertise = adv,
                            C = conn,
                            Up = true
                        };
                        // The directory row records how to reach a remote number,
                        // so it has to hold the same string _links is keyed by.
                        // Leaving it as the bare address made every forwarded
                        // line on an inbound link fall through to the queue.
                        conn.PeerEndpoint = l.Endpoint;
                        lock (_linkLock) _links[l.Endpoint] = l;
                        RememberRelay(adv, conn.Machine);
                        if (adv.Length > 0) AnnounceRelay(adv, conn.Machine, conn);
                        WriteRaw(w, "RLINKOK|" + RelayId + "|" + AdvertiseAddress());
                        Emit("Link up (incoming): relay " + conn.PeerRelayId + " from " + remote +
                             (adv.Length > 0 ? " (advises " + adv + ")" : ""));
                        // Tell them who we can reach, so they can route to us.
                        SendDirSnapshot(conn);
                        GossipRelays(conn);
                        AnnounceKey(conn);
                        SendKeySnapshot(conn);
                        SendPeerKeySnapshot(conn);
                        GossipKeys(conn);
                        continue;
                    }

                    // ── "Who are you?" - this relay's key, shown to anyone ─────
                    // Checked BEFORE the registration gate, on purpose: the whole
                    // point is to decide whether to hand this machine your number,
                    // your peer list and your queued mail, so an answer that required
                    // registering first would be no protection at all.
                    //
                    // It is the SAME self-bound claim relays already exchange
                    // (sig = SIGN("RLID|<relayId>"), verified with the key being
                    // presented) rather than a new kind of assertion to trust. A relay
                    // configured to link to nobody has no relay key by design - it
                    // should not acquire a private key just because something asked -
                    // and it says so instead of minting one.
                    if (p[0] == "WHOAMI")
                    {
                        if (!MayLink()) { WriteRaw(w, "ERR|norelaykey"); continue; }
                        string kl = OwnKeyLine();
                        if (kl != null) WriteRaw(w, kl);
                        else WriteRaw(w, "ERR|norelaykey");
                        continue;
                    }
                    if (conn == null) { WriteRaw(w, "ERR|registerfirst"); continue; }

                    if (p[0] == "KA") continue;

                    // ── "is this number online right now?" ───────────────────
                    // A client that connected a second ago has no directory yet: the
                    // PEERS snapshot arrives on its own schedule, so "your friend is
                    // offline" would be a fact about how long this connection has been
                    // open rather than about the friend. The relay is the only party that
                    // can answer, and answering is cheap - so ask it instead of letting a
                    // cold cache refuse a call.
                    if (p[0] == "WHO" && p.Length >= 2)
                    {
                        string num = p[1].Trim();
                        bool here = false, far = false;
                        lock (_mapLock) { here = _byNumber.ContainsKey(num); far = _remote.ContainsKey(num); }
                        Interlocked.Increment(ref WhoAsked);
                        // Counted separately from WhoAsked on purpose. Asked-but-answered
                        // with the caller still timing out puts the delay on the CALLER's
                        // side - its thread busy doing something else - while asked-but-
                        // not-answered would put it here. Guessing which is what the WHO
                        // timeouts were diagnosed by for a whole session.
                        // `remote` is said out loud because the caller cannot reach that
                        // number directly: it lives on somebody else's relay, and a media
                        // path to it goes through the mesh or nowhere.
                        WriteRaw(w, "WHO|" + num + "|" + ((here || far) ? "yes" : "no") +
                                   (far ? "|remote" : ""));
                        Interlocked.Increment(ref WhoAnswered);
                        continue;
                    }

                    // ── Relay referral: tell a client about other relays ─────
                    if (p[0] == "RLIST")
                    {
                        WriteRaw(w, "RLIST|" + string.Join(",", ReferrableRelays(conn)));
                        continue;
                    }

                    // ── Federation frames, accepted only on a link ──────────
                    if (conn.IsLink && p[0] == "RDIST") { Absorb(conn, p); continue; }
                    if (conn.IsLink && p[0] == "RDROP") { AbsorbDrop(conn, p); continue; }
                    // "This room is mixed over here, its host has hung up" - a routing
                    // hint keyed by room id, because the owner's number no longer leads
                    // anywhere useful.
                    if (conn.IsLink && p[0] == "CONF_HOST" && p.Length >= 3)
                    {
                        LearnRoomHost(conn, p[1].Trim(), p[2].Trim());
                        continue;
                    }
                    if (conn.IsLink && p[0] == "RKNEW" && p.Length >= 4)
                    {
                        LearnRelay(conn, p);
                        continue;
                    }
                    // ── Onion: relay keys and layers, both accepted on a link ─
                    if (p[0] == "RPUB") { TryKeyLine(conn, p); continue; }
                    // ── Published peer keys: publish, ask, and relay gossip ──
                    if (p[0] == "PUBK" || p[0] == "PKQ" || p[0] == "PKDIST")
                    {
                        TryPeerKeyLine(conn, p, line, conn.IsLink);
                        continue;
                    }
                    if (p[0] == "MWHO" || p[0] == "MDROP") { TryMailLine(conn, p, line); continue; }
                    if (p[0] == "MRCVD")
                    {
                        // Re-split from the raw line: the loop handed us four fields,
                        // and a carried message needs six with its payload intact.
                        TryMailLine(conn, line.Split(new char[] { '|' }, 6), line);
                        continue;
                    }
                    if (p[0] == "ONION" && p.Length >= 2 && conn.IsLink)
                    {
                        TryOnionLine(conn, p[1]);
                        continue;
                    }
                    if (conn.IsLink && p[0] == "XF" && p.Length >= 4)
                    {
                        int hops = 0;
                        int.TryParse(p[1], out hops);
                        if (hops >= MaxHops)
                        {
                            Emit("Dropping forwarded line after " + hops + " hops (loop or long chain)");
                            continue;
                        }
                        {
                            string inner = p[3];
                            // Split without a limit: field 1 is the target number,
                            // and the payload after it may itself contain pipes.
                            string[] ip = inner.Split('|');
                            if (ip.Length >= 2 && (ip[0] == "MSG" || ip[0] == "RM"))
                                Route(conn, ip[1], inner, hops);
                            else if (ip[0] != null && (ip[0].StartsWith("CONF_", StringComparison.Ordinal) ||
                                     ip[0] == "ERR"))
                                // ERR belongs in the room path because that is where it
                                // is generated: "noroom" is a reply to a member's join,
                                // and a member who is not registered on the relay that
                                // refused them can only hear it by being routed. It used
                                // to fall through to the line below, so a refused join
                                // was not merely unread by the client - it never arrived.
                                HandleForwardedConf(conn, hops, p[2], inner);
                            else
                                Emit("Ignoring forwarded " + ip[0] + " line (not routable here)");
                        }
                        continue;
                    }
                    // A relay must never register a number as a user.
                    if (conn.IsLink && p[0] == "REG") continue;

                    if ((p[0] == "MSG" || p[0] == "RM") && p.Length >= 3)
                    {
                        // ── Token validation on RM (media relay) ──────────
                        // The token is embedded in the registered connection —
                        // only a registered connection can relay media.
                        if (conn == null) { WriteRaw(w, "ERR|registerfirst"); continue; }
                        Route(conn, p[1].Trim(), line);
                        continue;
                    }
                    // ── Conference commands ────────────────────────────────
                    // One door for every room verb: it decides whether this relay
                    // owns the room or must hand the line to the one that does.
                    if (p[0] != null && p[0].StartsWith("CONF_", StringComparison.Ordinal) && conn != null && !conn.IsLink)
                    {
                        string roomId = p.Length >= 2 ? p[1].Trim() : "";
                        if (roomId.Length > 0) ConfDispatch(conn, line, roomId);
                        continue;
                    }
                    if (p[0] == "QUIT") break;
                }
            }
            catch (Exception ex)
            {
                // read timeout or connection drop - fall through to cleanup
                if (UseTls && conn == null) Emit("TLS client connection rejected: " + ex.Message);
            }
            finally
            {
                if (conn != null && conn.IsLink)
                {
                    // The peer went away: everything we learned through it is
                    // unreachable, so drop it and tell our other links.
                    DropOrigin(conn.PeerRelayId);
                    lock (_linkLock) _links.Remove(conn.PeerEndpoint);
                    Emit("Link down: relay " + conn.PeerRelayId);
                    MarkPeersDirty();
                }
                else if (conn != null)
                {
                    lock (_mapLock)
                    {
                        Conn cur;
                        if (_byNumber.TryGetValue(conn.Number, out cur) && cur == conn)
                            _byNumber.Remove(conn.Number);
                    }
                    // Leave all conferences this connection was in
                    List<string> roomsToLeave;
                    lock (_roomLock)
                    {
                        roomsToLeave = new List<string>();
                        foreach (string rid in _rooms.Keys)
                            if (_rooms[rid].Members.Contains(conn.Number))
                                roomsToLeave.Add(rid);
                    }
                    foreach (string rid in roomsToLeave)
                    {
                        ConfLeave(rid, conn.Number);
                        // A room owner whose host just vanished cannot keep
                        // mixing silence for it forever.
                        ConferenceRoom r;
                        lock (_roomLock) { if (_rooms.TryGetValue(rid, out r) && r.Shadow.ContainsKey(conn.Number)) r.Shadow.Remove(conn.Number); }
                    }
                    Emit("Unregistered " + conn.Number);
                    // Peers must stop routing to a number that is gone here.
                    AdvertiseDrop(conn.Number);
                    MarkPeersDirty();
                }
                if (ssl != null) try { ssl.Dispose(); } catch { }
                try { tc.Close(); } catch { }
            }
        }

        // A room line that arrived over a link. Upstream verbs (a member joining,
        // talking, muting) are re-dispatched as if that member sent them. The
        // downstream ones (mix, roster, talk levels, a thumbnail) go to the member:
        // delivered if they are registered here, otherwise passed on toward their
        // own relay, bounded by the hop ceiling. Point-to-point either way, so a
        // mixed frame cannot circulate the mesh forever.
        void HandleForwardedConf(Conn link, int hops, string envelopeNumber, string inner)
        {
            if (string.IsNullOrEmpty(envelopeNumber)) return;
            string[] ip = inner.Split('|');
            string verb = ip[0];
            bool downstream = verb == "CONF_MIXED" || verb == "CONF_ROSTER" ||
                              verb == "CONF_TALK" || verb == "CONF_VID" || verb == "ERR";
            Conn local = null;
            lock (_mapLock) { _byNumber.TryGetValue(envelopeNumber, out local); }
            if (local != null && !local.IsLink) { WriteRaw(local.W, inner); return; }   // their own relay
            if (downstream)
            {
                if (hops + 1 >= MaxHops) return;
                Forward(link, envelopeNumber, envelopeNumber, hops, inner);
                return;
            }
            if (ip.Length < 2) return;
            ConfDispatch(ShadowFor(link, envelopeNumber), inner, ip[1], hops);
        }

        private void Route(Conn from, string toNumber, string line) { Route(from, toNumber, line, 0); }

        private void Route(Conn from, string toNumber, string line, int hops)
        {
            // ── Media token resolution ────────────────────────────────────
            // RM lines may carry per-call tokens instead of real numbers so that
            // intermediate relays cannot correlate the call pair. Resolve the
            // token to the real number before routing; the token remains in the
            // line so the recipient can route back using their own token.
            string resolvedTo = toNumber;
            if (line.StartsWith("RM|", StringComparison.Ordinal))
            {
                string realNum = ResolveToken(toNumber);
                if (realNum != toNumber)
                {
                    resolvedTo = realNum;
                    // Rewrite the line with the real number so the client can
                    // route replies back. The from-field is kept as the token.
                    line = "RM|" + realNum + "|" + line.Substring(line.IndexOf('|', 3) + 1);
                }
            }
            Conn target = null;
            lock (_mapLock) _byNumber.TryGetValue(resolvedTo, out target);
            if (target != null && !target.IsLink)
            {
                if (line.StartsWith("RM|", StringComparison.Ordinal))
                    Interlocked.Increment(ref MediaDelivered);
                WriteRaw(target.W, line);
                return;
            }

            // ── Not registered here. Is it reachable through a linked relay? ──
            // Tried before the queue on purpose: a number that exists on a
            // friend's relay is deliverable, not offline, and quietly queueing it
            // here instead would mean two copies of the same message with two
            // different delivery times.
            bool knownRemote;
            RemoteRec rec = null;
            lock (_mapLock) knownRemote = _remote.TryGetValue(resolvedTo, out rec);
            if (knownRemote)
            {
                // ── Is there somebody in between who should not see this pair? ──
                // Only a locally originating MSG qualifies, for three reasons:
                // a line that arrived from another relay is somebody else's
                // routing decision, RM carries media frames where ~1 KB of
                // envelope per frame would double a call's bandwidth, and hops>0
                // means an intermediate already holds the pair in clear.
                if (RelayOnion != "off" && hops == 0 &&
                    line.StartsWith("MSG|", StringComparison.Ordinal) &&
                    from != null && !from.IsLink)
                {
                    string why;
                    Conn hop;
                    string tok = BuildOnion(rec, toNumber, line, out hop, out why);
                    if (tok != null && hop != null && hop.W != null)
                    {
                        WriteRaw(hop.W, "ONION|" + tok);
                        Interlocked.Increment(ref OnionBuilt);
                        Emit("ONION built for #" + toNumber + ": an intermediate relay will not see this pair");
                        return;
                    }
                    // An empty reason means BuildOnion declined because there is
                    // nobody in between to hide from - a one-hop route. That is
                    // not a privacy failure, and treating it as one would make
                    // force mode refuse every message that needed no onion at all.
                    if (why.Length == 0) { }
                    else if (RelayOnion == "force")
                    {
                        if (from.W != null) WriteRaw(from.W, "ERR|onoroute");
                        Emit("Refused to forward #" + toNumber + " in clear: " + why);
                        Interlocked.Increment(ref OnionRefused);
                        return;
                    }
                    else Emit("Forwarding #" + toNumber + " in clear: " + why);
                }
                if (Forward(from, toNumber, hops, line)) return;
                // The route exists but the link is down mid-flight. Fall through
                // and queue it: that is what makes a link blip invisible to users.
            }

            // ── Offline message queue ────────────────────────────────
            // Never file mail under something that is not a number: a malformed
            // or hostile target would otherwise grow the queue dictionary without
            // bound, since no registration can ever match it and flush it.
            if (!RegexIsNumber(toNumber))
            {
                if (from != null && from.W != null) WriteRaw(from.W, "UNDELIVERABLE|" + toNumber);
                return;
            }
            // Store up to 50 messages per offline recipient.
            // Flushed to the peer the moment they reconnect (REG).
            // Call invitations (INVITE) are time-bound: queueing them would
            // ring the peer long after the caller gave up, so those are
            // reported as undeliverable instead while plain chat lines
            // (CHAT / CHATACK / CTYP / VAUD) wait in the queue.
            string payload = "";
            if (line.StartsWith("MSG|"))
            {
                string[] mp = line.Split(new char[] { '|' }, 4);
                if (mp.Length >= 4) payload = mp[3];
            }
            bool invites = payload.StartsWith("INVITE|");
            // A key exchange is not mail either. Stored for an off-line peer it sits
            // in the queue like a message, uses one of the same slots, and arrives as
            // a handshake from hours ago - which the peer then completes, giving a
            // session nobody asked for at a time nobody meant. Offline sealing made
            // it unnecessary: mail to an absent peer now goes in ECHATK, and a fresh
            // KEYX happens by itself the next time both are connected.
            bool handshakes = payload.StartsWith("KEYX|") || payload.StartsWith("KEYXOK|");
            bool ephemeral = invites || handshakes;
            bool queuedHere = false;
            if (line.StartsWith("MSG|") && !ephemeral && from != null && from.W != null)
            {
                // Nothing unsealed is ever stored. There is a difference between a relay
                // that cannot read a message and one that simply does not bother: mail
                // now waits on more than one disk, may sit there for a week, and is
                // readable by whoever holds that machine - and offline sealing already
                // works, so plaintext in the queue is a choice, not a limitation. The
                // sender is told in words instead of being promised QUEUED for bytes
                // anybody can open.
                if (!MailCarriable(line))
                {
                    Emit("Refused to store unsealed mail for " + toNumber + ": " +
                         (payload.IndexOf('|') > 0 ? payload.Split('|')[0] : payload) +
                         " arrived in the clear. Nothing was kept, nothing was carried.");
                    WriteRaw(from.W, "ERR|nokey|" + toNumber);
                    return;
                }
                // Carrying mail for another relay spends *our* disk, so it has a
                // ceiling. Local clients keep the plain per-recipient allowance:
                // that queue is the feature they signed up for by hosting.
                bool forPeer = from.IsLink;
                long cap = RelayStoreKb * 1024L;
                if (!forPeer || cap <= 0 || QueuedBytesForPeers + line.Length <= cap)
                {
                    string sender = from.Number ?? "";
                    if (sender.Length == 0)
                    {
                        string[] ip = line.Split(new char[] { '|' }, 4);
                        if (ip.Length >= 3) sender = ip[2];
                    }
                    Mail m = new Mail
                    {
                        Id = NewMailId(), To = toNumber, From = sender, Line = line,
                        Expires = DateTime.Now.Ticks + MailTtl, Hops = 0
                    };
                    if (StoreMail(m, forPeer) != null)
                    {
                        queuedHere = true;
                        Emit("Queued offline message for " + toNumber +
                             " from " + (sender.Length > 0 ? sender : "a linked relay") +
                             (forPeer ? " (carrying for a peer)" : ""));
                        // Tell the sender it is safely queued (not lost).
                        try { WriteRaw(from.W, "QUEUED|" + toNumber); } catch { }
                        // A queued message that only lives here is unreachable if this
                        // PC goes off-line or the recipient never comes back to it.
                        PushMailToLinks(m);
                    }
                }
                else
                {
                    Emit("Store quota full: dropping mail for " + toNumber + " (" + RelayStoreKb + " KB cap)");
                    try { WriteRaw(from.W, "UNDELIVERABLE|" + toNumber); } catch { }
                    return;
                }
            }
            if (!queuedHere && from != null && from.W != null)
            {
                // A dropped handshake must not look like a lost message: the sender
                // has to be able to tell "they are off-line" from "it was corrupted".
                if (handshakes && !invites) WriteRaw(from.W, "PEEROFFLINE|" + toNumber);
                else WriteRaw(from.W, "UNDELIVERABLE|" + toNumber);
            }
        }

        // Flush any queued offline messages to a newly-registered peer.
        private void FlushOfflineQueue(Conn conn)
        {
            List<Mail> q = null;
            lock (_queueLock)
            {
                _offlineQueue.TryGetValue(conn.Number, out q);
                if (q != null) _offlineQueue.Remove(conn.Number);
            }
            int local = q == null ? 0 : q.Count;
            // Ask the relays we are linked to as well: the message may be sitting on
            // one of them, because the sender's relay handed it to whoever would hold
            // it. This is what makes delivery independent of which relay a person
            // happens to come back on.
            AskLinksForMail(conn.Number);
            if (local == 0) return;
            long bytes = 0;
            foreach (Mail m in q) bytes += m.Line.Length;
            Interlocked.Add(ref _queueBytes, -bytes);
            Emit("Flushing " + local + " queued message(s) to " + conn.Number);
            foreach (Mail m in q)
            {
                // A copy pulled from a link may have been handed over already: the
                // ask above can be answered before this loop runs, and then our own
                // store is the second copy of the same message. The claim is what
                // makes that a decision one thread can win, not a window two can.
                if (!TryClaimMail(m.Id))
                {
                    DeleteMailFile(m.Id);
                    continue;
                }
                WriteRaw(conn.W, m.Line);
                DeleteMailFile(m.Id);
                Interlocked.Increment(ref MailDelivered);
                // Copies handed to other relays before this restart are still out
                // there. Say so, or the recipient reads the same message again the
                // next time they touch a relay that kept one.
                foreach (Conn c in LinkConns(null)) WriteRaw(c.W, "MDROP|" + m.Id + "|0");
            }
            // That number is now ours; other relays must stop holding routes to
            // their own copy of it.
            Advertise(conn.Number, conn.Ip, conn.Machine);
        }

        // Offline queue storage
        private readonly Dictionary<string, List<Mail>> _offlineQueue = new Dictionary<string, List<Mail>>();
        private readonly object _queueLock = new object();
        // Delivery notices already passed on, so the mesh does not spend a week
        // re-announcing that one message arrived.
        private readonly HashSet<string> _mailDrops = new HashSet<string>();
        // Ids this relay has already handed to a client. The same message can reach us
        // twice by design - pulled from a link while our own recovered store was being
        // flushed - and "it arrived, twice" is not delivery working, it is the user
        // reading one message two times. Local to this relay: it cannot speak for what
        // some other node did while we were switched off.
        private readonly HashSet<string> _mailDone = new HashSet<string>();

        bool MailAlreadyDelivered(string id)
        {
            if (string.IsNullOrEmpty(id)) return false;
            lock (_queueLock) return _mailDone.Contains(id);
        }

        // Claim the right to hand this message to a client. It has to be one atomic
        // step: the local flush and a copy arriving on a link run on different threads
        // and hold the same id at the same instant, so "check, write, then mark" lets
        // both deliver and the user reads the message twice - which is what this was
        // caught doing in a test. Claiming before writing means exactly one winner.
        bool TryClaimMail(string id)
        {
            if (string.IsNullOrEmpty(id)) return true;      // nothing to key on: do not block delivery
            lock (_queueLock)
            {
                if (_mailDone.Contains(id)) return false;
                if (_mailDone.Count > 5000) _mailDone.Clear();
                _mailDone.Add(id);
                return true;
            }
        }

        // One stored message. It carries an id rather than being identified by
        // content, because two relays must be able to agree they hold the SAME
        // message without comparing bodies - that is all dedup needs, and it is
        // what stops a message being delivered three times as it travels.
        private sealed class Mail
        {
            public string Id = "";
            public string To = "";
            public string From = "";
            public string Line = "";
            public long Expires;
            public int Hops;
            public bool Live { get { return DateTime.Now.Ticks <= Expires; } }
        }

        string MailDir
        {
            get
            {
                if (_mailDir == null)
                    _mailDir = string.IsNullOrEmpty(MailDirOverride)
                        ? Path.Combine(Home.Dir, "mail") : MailDirOverride;
                return _mailDir;
            }
        }
        private string _mailDir;

        // Read the mail folder back into the queue. Anything expired is deleted
        // rather than counted, so a relay that was off for a fortnight does not
        // come back holding week-old messages.
        void LoadMail()
        {
            try
            {
                if (!Directory.Exists(MailDir)) return;
                string[] files = Directory.GetFiles(MailDir, "*.mail");
                int loaded = 0;
                foreach (string f in files)
                {
                    // The pattern is matched by the OS, and its rules about a name
                    // that merely CONTAINS .mail (a half-written file, an 8.3 alias)
                    // are not something to trust with other people's messages.
                    if (!f.EndsWith(".mail", StringComparison.OrdinalIgnoreCase)) continue;
                    Mail m = ParseMailFile(f);
                    if (m == null)
                    {
                        try { File.Delete(f); } catch { }        // unreadable: drop it
                        continue;
                    }
                    if (!m.Live) { try { File.Delete(f); } catch { } continue; }
                    List<Mail> q;
                    lock (_queueLock)
                    {
                        if (!_offlineQueue.TryGetValue(m.To, out q))
                        {
                            q = new List<Mail>();
                            _offlineQueue[m.To] = q;
                        }
                        if (q.Count < MailMaxPerRecipient) { q.Add(m); loaded++; }
                    }
                }
                if (loaded > 0)
                    Emit("Recovered " + loaded + " stored message(s) for " + _offlineQueue.Count +
                         " recipient(s) from " + MailDir);
            }
            catch { }
        }

        static Mail ParseMailFile(string path)
        {
            try
            {
                string[] rows = File.ReadAllLines(path);
                if (rows.Length < 5) return null;
                Mail m = new Mail();
                m.To = rows[0];
                m.From = rows[1];
                long exp; int hops;
                if (!long.TryParse(rows[2], NumberStyles.None, CultureInfo.InvariantCulture, out exp)) return null;
                int.TryParse(rows[3], NumberStyles.None, CultureInfo.InvariantCulture, out hops);
                m.Expires = exp;
                m.Hops = hops;
                m.Line = rows[4];
                m.Id = Path.GetFileNameWithoutExtension(path);
                if (!RegexIsNumber(m.To) || m.Line.Length == 0) return null;
                return m;
            }
            catch { return null; }
        }

        // One file per message, written as a temp and moved into place: the same
        // discipline as the wake hand-off. A half-written file would otherwise be a
        // message that exists on disk but cannot be parsed, i.e. silently lost.
        void WriteMailFile(Mail m)
        {
            try
            {
                Directory.CreateDirectory(MailDir);
                string final = Path.Combine(MailDir, m.Id + ".mail");
                // WriteAllLines wrote the temp file with the platform newline, and
                // this keeps the bytes identical while moving the swap into the one
                // helper that retries it. A mail file is somebody's message: losing
                // the store after promising QUEUED is the failure this whole feature
                // was built to stop.
                string body = string.Join(Environment.NewLine, new string[] { m.To, m.From,
                    m.Expires.ToString(CultureInfo.InvariantCulture),
                    m.Hops.ToString(CultureInfo.InvariantCulture), m.Line }) + Environment.NewLine;
                if (!StateFile.WriteAtomic(final, body))
                    Emit("Mail could not be stored at " + final +
                         " - it is in memory only here, so a restart loses it");
            }
            catch (Exception ex) { Emit("Mail could not be stored: " + ex.Message); }
        }

        void DeleteMailFile(string id)
        {
            if (string.IsNullOrEmpty(id)) return;
            try { File.Delete(Path.Combine(MailDir, id + ".mail")); } catch { }
        }

        static string NewMailId()
        {
            return DateTime.Now.Ticks.ToString("x") +
                   Guid.NewGuid().ToString("N").Substring(0, 6);
        }

        public int QueuedMailCount
        {
            get
            {
                int n = 0;
                lock (_queueLock) foreach (List<Mail> q in _offlineQueue.Values) n += q.Count;
                return n;
            }
        }

        // Add one message to our keeping: indexed, written to disk, counted, and
        // bounded by the sender's origin. Mail that arrived from another relay
        // spends OUR disk for people we will never meet, so it is the part that has
        // to obey the store quota; a local client's own queue is the service it
        // signed up to provide by hosting.
        // Returns the mail accepted, or null when it was a duplicate or we are full.
        Mail StoreMail(Mail m, bool forPeer)
        {
            if (m == null || !RegexIsNumber(m.To)) return null;
            if (string.IsNullOrEmpty(m.Id)) m.Id = NewMailId();
            if (m.Expires <= DateTime.Now.Ticks) m.Expires = DateTime.Now.Ticks + MailTtl;
            bool dup = false, full = false, capped = false;
            long bytes = 0;
            lock (_queueLock)
            {
                foreach (List<Mail> q in _offlineQueue.Values)
                    foreach (Mail e in q)
                        if (e.Id == m.Id) { dup = true; break; }
                if (!dup)
                {
                    List<Mail> q;
                    if (!_offlineQueue.TryGetValue(m.To, out q))
                    {
                        q = new List<Mail>();
                        _offlineQueue[m.To] = q;
                    }
                    if (q.Count >= MailMaxPerRecipient) capped = true;
                    else if (TotalMailFiles() >= MailMaxFiles) full = true;
                    else { q.Add(m); bytes = m.Line.Length; }
                }
            }
            if (dup) return null;
            if (capped || full)
            {
                Emit((full ? "Mail store is full (" + MailMaxFiles + " messages)" : "That recipient already has " + MailMaxPerRecipient + " waiting") +
                     ": dropping mail for " + m.To);
                return null;
            }
            WriteMailFile(m);
            if (forPeer) Interlocked.Add(ref _queueBytes, bytes);
            return m;
        }

        // Counted off disk rather than from the index, because the ceiling we are
        // protecting against (a filled drive) is a fact about the folder.
        int TotalMailFiles()
        {
            try { return Directory.Exists(MailDir) ? Directory.GetFiles(MailDir, "*.mail").Length : 0; }
            catch { return 0; }
        }

        // Remove one message from the index and the disk, whatever it was keyed by.
        bool TakeMailById(string id)
        {
            if (string.IsNullOrEmpty(id)) return false;
            Mail found = null;
            lock (_queueLock)
            {
                foreach (List<Mail> q in _offlineQueue.Values)
                    foreach (Mail e in q) if (e.Id == id) { found = e; break; }
                if (found != null)
                    foreach (List<Mail> q in _offlineQueue.Values) q.Remove(found);
            }
            if (found == null) return false;
            if (found.Line.StartsWith("MSG|", StringComparison.Ordinal))
                Interlocked.Add(ref _queueBytes, -found.Line.Length);
            DeleteMailFile(found.Id);
            return true;
        }

        bool HoldsMailFor(string id)
        {
            lock (_queueLock)
                foreach (List<Mail> q in _offlineQueue.Values)
                    foreach (Mail e in q) if (e.Id == id) return true;
            return false;
        }

        List<Mail> MailFor(string number)
        {
            List<Mail> outp = new List<Mail>();
            lock (_queueLock)
            {
                List<Mail> q;
                if (_offlineQueue.TryGetValue(number ?? "", out q)) outp.AddRange(q);
            }
            return outp;
        }

        // The wire form of a carried message, six fields with the payload last so
        // the pipes inside it cannot shift a field:
        //   MRCVD|<id>|<expires>|<to>|<hops>|<line>
        static string MailLine(Mail m)
        {
            return "MRCVD|" + m.Id + "|" +
                   m.Expires.ToString(CultureInfo.InvariantCulture) + "|" +
                   m.To + "|" + m.Hops.ToString(CultureInfo.InvariantCulture) + "|" + m.Line;
        }

        // Offer our copy to every link that is willing to hold it. This is the part
        // that makes a message reachable from a relay the sender never heard of: the
        // copy is waiting on whichever node the recipient next registers with.
        //
        // Sealed traffic only. Mail for somebody who is off-line usually has NO key
        // yet - there was no session to build one from - so it is plaintext inside the
        // envelope. Spreading plaintext copies to machines this user never chose would
        // be a privacy regression dressed up as a feature, so an unsealed message stays
        // on the relay it was addressed to, exactly as it was before carrying existed.
        // Public because the rule deserves a test of its own: it is the line between
        // "reachable later" and "readable by whoever happens to hold a copy".
        public static bool MailCarriable(string line)
        {
            if (!line.StartsWith("MSG|", StringComparison.Ordinal)) return false;
            string[] p = line.Split(new char[] { '|' }, 4);
            if (p.Length < 4) return false;
            // Either sealing works: a session key from a live exchange, or the
            // published identity key for a peer that is off-line. Nothing else may
            // leave this relay, because nothing else is private.
            return p[3].StartsWith("ECHAT|", StringComparison.Ordinal) ||
                   p[3].StartsWith(OfflineSeal.Verb + "|", StringComparison.Ordinal);
        }

        // ── Published identity keys (the offline-sealing directory) ─────────
        //
        // A client hands over its identity key when it registers, and any peer may
        // ask for it later. That is what lets a message be sealed to somebody who is
        // not connected - without it, offline mail is plaintext by necessity.
        //
        // The relay stores a CLAIM, not a fact: `PUBK|<number>|<pub>|<sig>` is
        // verified with the presented key before it is kept, so the key itself says
        // "I am the key for #<number>". A relay cannot forge that binding without the
        // private half. What a relay CAN do is refuse to answer, or answer with a key
        // it has never seen before - which is the same first-use gap as the peer book,
        // and is why a key that changes is reported rather than quietly swapped.
        private readonly Dictionary<string, string[]> _peerKeys = new Dictionary<string, string[]>();
        private readonly object _pkLock = new object();
        public string PeerKeyFileOverride = "";
        private string _peerKeyPath;

        string PeerKeyPath
        {
            get
            {
                if (_peerKeyPath == null)
                    _peerKeyPath = string.IsNullOrEmpty(PeerKeyFileOverride)
                        ? Path.Combine(Home.Dir, "peer_keys.txt") : PeerKeyFileOverride;
                return _peerKeyPath;
            }
        }

        static string PeerKeyClaim(string number) { return "PUBK|" + number; }

        bool TryPeerKeyLine(Conn conn, string[] p, string line, bool fromLink)
        {
            if (p[0] == "PUBK" && p.Length >= 4 && conn != null && !conn.IsLink)
            {
                // A client publishing its own key. Re-publishing is normal (it
                // happens on every re-REG), so no write unless it actually changed.
                string num = p[1].Trim();
                if (num != conn.Number) { Emit("PUBK refused: it claims #" + num + " on a session registered as #" + conn.Number); return true; }
                NotePeerKey(num, p[2].Trim(), p[3].Trim(), null);
                return true;
            }
            if (p[0] == "PKDIST" && p.Length >= 4 && fromLink)
            {
                NotePeerKey(p[1].Trim(), p[2].Trim(), p[3].Trim(), conn);
                return true;
            }
            if (p[0] == "PKQ" && p.Length >= 2 && conn != null && !conn.IsLink)
            {
                string num = p[1].Trim();
                if (!RegexIsNumber(num)) { WriteRaw(conn.W, "PKNONE|" + num); return true; }
                string[] rec = PeerKeyFor(num);
                if (rec == null) { WriteRaw(conn.W, "PKNONE|" + num); return true; }
                WriteRaw(conn.W, "PKPUB|" + num + "|" + rec[0] + "|" + rec[1]);
                return true;
            }
            return false;
        }

        // Verify, store, and pass on. `sigB64` travels with the key it belongs to:
        // re-signing somebody else's key with ours would make the receiver check our
        // signature against their key and reject a perfectly good entry.
        void NotePeerKey(string number, string pubB64, string sigB64, Conn cameFrom)
        {
            if (!RegexIsNumber(number) || string.IsNullOrEmpty(pubB64)) return;
            byte[] sig;
            try { sig = Convert.FromBase64String(sigB64 ?? ""); } catch { return; }
            if (!Identity.Verify(pubB64, Encoding.UTF8.GetBytes(PeerKeyClaim(number)), sig))
            {
                Emit("Peer key for #" + number + " does not prove that number; dropped");
                return;
            }
            // Bind the key to the lease. It proves nothing about who is allowed to
            // register - the token decides that - but it is what a peer's own
            // fingerprint comparison is checked against, so a takeover that got past
            // the lease still has to show its face.
            int bound = Leases.NoteIdentity(number, pubB64);
            if (bound == 2)
                Emit("WARNING: identity key for #" + number + " changed since it was leased. Peers who "
                     + "sealed to the old key will report a changed safety number - confirm with the "
                     + "owner over another channel before carrying on.");
            bool changed = false, same = false;
            lock (_pkLock)
            {
                string[] old;
                if (_peerKeys.TryGetValue(number, out old))
                {
                    same = old[0] == pubB64;
                    changed = !same;
                    if (!same) _peerKeys[number] = new string[] { pubB64, sigB64 };
                }
                else _peerKeys[number] = new string[] { pubB64, sigB64 };
            }
            if (same) return;
            if (changed)
                Emit("Peer key for #" + number + " CHANGED (" + Identity.FingerprintOf(pubB64) +
                     "). Kept the new one - a reinstalled app legitimately has one - but peers " +
                     "who saw the old fingerprint should be told over another channel.");
            else
                Emit("Peer key stored for #" + number + " (" + Identity.FingerprintOf(pubB64) + ")");
            SavePeerKeys();
            string ln = "PKDIST|" + number + "|" + pubB64 + "|" + sigB64;
            foreach (Conn c in LinkConns(cameFrom)) WriteRaw(c.W, ln);
        }

        string[] PeerKeyFor(string number)
        {
            lock (_pkLock)
            {
                string[] v;
                return _peerKeys.TryGetValue(number ?? "", out v) ? v : null;
            }
        }

        public int PeerKeyCount { get { lock (_pkLock) return _peerKeys.Count; } }

        void LoadPeerKeys()
        {
            try
            {
                if (!File.Exists(PeerKeyPath)) return;
                int kept = 0;
                foreach (string ln in File.ReadAllLines(PeerKeyPath))
                {
                    string[] p = ln.Split('|');
                    if (p.Length < 3) continue;
                    // Re-verified on load, not trusted because it is on our own disk:
                    // a hand-edited or corrupted sheet must not become a directory of
                    // keys that senders seal to.
                    byte[] sig;
                    try { sig = Convert.FromBase64String(p[2]); } catch { continue; }
                    if (!Identity.Verify(p[1], Encoding.UTF8.GetBytes(PeerKeyClaim(p[0])), sig)) continue;
                    lock (_pkLock) _peerKeys[p[0]] = new string[] { p[1], p[2] };
                    kept++;
                }
                if (kept > 0) Emit("Peer keys: " + kept + " loaded from " + PeerKeyPath);
            }
            catch { }
        }

        void SavePeerKeys()
        {
            try
            {
                StringBuilder sb = new StringBuilder();
                lock (_pkLock)
                    foreach (KeyValuePair<string, string[]> kv in _peerKeys)
                        sb.Append(kv.Key).Append('|').Append(kv.Value[0]).Append('|').Append(kv.Value[1]).Append('\n');
                if (!StateFile.WriteAtomic(PeerKeyPath, sb.ToString()))
                    Emit("WARNING: peer keys could not be written to " + PeerKeyPath +
                         " - a key met this session may not survive a restart, and the "
                         + "next meeting would then look like a first one");
            }
            catch { }
        }

        // Tell a link about the keys we hold, so a sender on the far side can seal to
        // a peer that only ever registered here.
        void SendPeerKeySnapshot(Conn to)
        {
            if (to == null || !to.IsLink || to.W == null) return;
            List<string> rows = new List<string>();
            lock (_pkLock)
                foreach (KeyValuePair<string, string[]> kv in _peerKeys)
                    rows.Add("PKDIST|" + kv.Key + "|" + kv.Value[0] + "|" + kv.Value[1]);
            foreach (string r in rows) WriteRaw(to.W, r);
        }


        void PushMailToLinks(Mail m)
        {
            if (!RelayCarryMail || m == null) return;
            if (!MailCarriable(m.Line)) return;
            if (m.Hops >= MailMaxHops) return;
            Mail copy = new Mail
            {
                Id = m.Id, To = m.To, From = m.From, Line = m.Line,
                Expires = m.Expires, Hops = m.Hops + 1
            };
            string ln = MailLine(copy);
            foreach (Conn c in LinkConns(null)) WriteRaw(c.W, ln);
        }

        void AskLinksForMail(string number)
        {
            foreach (Conn c in LinkConns(null)) WriteRaw(c.W, "MWHO|" + number);
        }

        // Consumed by a link only: a client has no business claiming other
        // people's mail.
        bool TryMailLine(Conn conn, string[] p, string line)
        {
            if (conn == null || !conn.IsLink) return false;
            if (p[0] == "MWHO" && p.Length >= 2)
            {
                string num = p[1].Trim();
                if (!RegexIsNumber(num)) return true;
                List<Mail> mine = MailFor(num);
                foreach (Mail m in mine)
                {
                    if (!m.Live) { TakeMailById(m.Id); continue; }
                    WriteRaw(conn.W, MailLine(m));
                    // Custody moves with the copy: keeping it here as well would
                    // mean the same message delivered twice from two places.
                    TakeMailById(m.Id);
                }
                if (mine.Count > 0)
                    Emit("Handed " + mine.Count + " carried message(s) for " + num + " to a linked relay");
                return true;
            }
            if (p[0] == "MDROP" && p.Length >= 2)
            {
                // Somebody delivered this message. Every copy still sitting on a
                // relay is now a duplicate waiting to happen, so the notice has to
                // travel further than the relay that heard it: the copy that will
                // arrive twice is the one on a node three hops away that never met
                // this one. A hop ceiling and a seen-set both bound it, because a
                // notice that is forwarded unconditionally is a loop with good
                // intentions.
                string id = p[1].Trim();
                if (id.Length == 0) return true;
                int hops = 0;
                if (p.Length >= 3) int.TryParse(p[2], NumberStyles.None, CultureInfo.InvariantCulture, out hops);
                TakeMailById(id);
                bool firstTime;
                lock (_queueLock)
                {
                    firstTime = !_mailDrops.Contains(id);
                    if (firstTime)
                    {
                        if (_mailDrops.Count > 5000) _mailDrops.Clear();
                        _mailDrops.Add(id);
                    }
                }
                if (firstTime && hops <= MailMaxHops)
                    foreach (Conn other in LinkConns(conn))
                        WriteRaw(other.W, "MDROP|" + id + "|" +
                               (hops + 1).ToString(CultureInfo.InvariantCulture));
                return true;
            }
            if (p[0] == "MRCVD" && p.Length >= 6)
            {
                Mail m = new Mail();
                m.Id = p[1].Trim();
                long exp; int hops;
                if (!long.TryParse(p[2], NumberStyles.None, CultureInfo.InvariantCulture, out exp)) return true;
                int.TryParse(p[4], NumberStyles.None, CultureInfo.InvariantCulture, out hops);
                m.Expires = exp;
                m.Hops = hops;
                m.To = p[3].Trim();
                m.Line = p[5];
                string[] ip = m.Line.Split(new char[] { '|' }, 4);
                m.From = ip.Length >= 3 ? ip[2] : "";
                if (!RegexIsNumber(m.To) || !m.Line.StartsWith("MSG|", StringComparison.Ordinal)) return true;
                if (!m.Live) return true;                     // expired in transit
                // Already handed to this recipient: decline the copy and tell the
                // holder it is finished, which is how a duplicate stops at the first
                // relay that saw it rather than travelling on to a second one.
                if (MailAlreadyDelivered(m.Id)) { WriteRaw(conn.W, "MDROP|" + m.Id + "|0"); return true; }
                // Holding it already is not evidence that it was delivered, so this
                // must not ask anyone to drop anything - it only declines a copy.
                if (HoldsMailFor(m.Id)) return true;

                Conn target = null;
                lock (_mapLock) _byNumber.TryGetValue(m.To, out target);
                if (target != null && !target.IsLink && target.W != null)
                {
                    // It is addressed to somebody standing here right now. Claim it
                    // before writing: the local flush may be delivering the same
                    // message on another thread at this exact moment.
                    if (!TryClaimMail(m.Id)) { WriteRaw(conn.W, "MDROP|" + m.Id + "|0"); return true; }
                    WriteRaw(target.W, m.Line);
                    Interlocked.Increment(ref MailDelivered);
                    WriteRaw(conn.W, "MDROP|" + m.Id + "|0");
                    Emit("Carried mail delivered to #" + m.To + " (msg " + m.Id + ")");
                    return true;
                }
                if (StoreMail(m, true) == null) return true;
                Interlocked.Increment(ref MailReceived);
                Emit("Carrying mail for #" + m.To + " (" + m.Hops + " hop(s) from home, msg " + m.Id + ")");
                PushMailToLinks(m);       // keep it moving, so it is waiting where they show up
                return true;
            }
            return false;
        }

        // How many pushes the notifier thread has actually sent. Less than the number
        // of events that asked for one is the whole point, and "it coalesces" is not a
        // claim anybody should have to take on trust.
        public long PeerBroadcasts;
        private volatile bool _peersDirty;
        private readonly object _peersSignal = new object();

        // Ask for the peer list to be pushed. Returns immediately.
        //
        // This exists because the inline version ran on whichever thread noticed the
        // change - and for a registration that is the registering client's OWN
        // connection thread, holding _mapLock across a blocking write to every other
        // socket. Two consequences, both measured before both were fixed: a client that
        // had just registered could not get an answer to its own next command, because
        // that command's handler was busy writing to other people's TCP buffers (this is
        // where the `WHO` timeouts came from), and every route lookup on this relay was
        // stalled for the duration of a push to N peers.
        //
        // Repeated marks during one pass collapse into a single push. That is sound for
        // PEERS specifically because it is a full snapshot and not a delta: a client that
        // misses an intermediate state simply receives the newer list.
        void MarkPeersDirty()
        {
            _peersDirty = true;
            lock (_peersSignal) Monitor.PulseAll(_peersSignal);
        }

        // One thread, one sender. Also carries the 30 s re-broadcast that lets clients
        // self-heal if a registration was ever silently lost, so there is exactly one
        // place in the process that writes PEERS.
        void PeersNotifyLoop()
        {
            int quietSeconds = 0;
            while (_run)
            {
                bool due;
                lock (_peersSignal)
                {
                    Monitor.Wait(_peersSignal, 1000);
                    quietSeconds++;
                    due = _peersDirty || quietSeconds >= 30;
                    if (due) { _peersDirty = false; quietSeconds = 0; }
                }
                if (!_run) break;
                if (!due) continue;
                try { PushPeersOnce(); }
                catch (Exception ex) { Emit("Peer push failed: " + ex.Message); }
            }
        }

        void PushPeersOnce()
        {
            Hang.Trace("CallSrv PushPeersOnce enter");
            string msg;
            List<StreamWriter> to;
            lock (_mapLock)
            {
                StringBuilder sb = new StringBuilder("PEERS|");
                bool first = true;
                foreach (Conn c in _byNumber.Values)
                {
                    if (c.IsLink) continue;
                    if (!first) sb.Append(";");
                    first = false;
                    sb.Append(c.Number).Append(',').Append(c.Ip).Append(',').Append(c.Machine);
                }
                // Federated peers are listed with a 4th field: which relay owns
                // them. Old clients read the first three and ignore it, and they
                // still try the direct address first, then fall back to the
                // relay - which is exactly the behaviour wanted.
                foreach (RemoteRec r in _remote.Values)
                {
                    if (!first) sb.Append(";");
                    first = false;
                    sb.Append(r.Number).Append(',').Append(r.Ip).Append(',')
                      .Append(r.Machine).Append(",via=").Append(r.Origin);
                }
                msg = sb.ToString();
                to = new List<StreamWriter>();
                foreach (Conn c in _byNumber.Values) if (c.W != null) to.Add(c.W);
            }
            // Written only AFTER the map lock is released. A peer whose socket is stuck
            // behind a wifi stall must not be able to hold up routing for everybody else
            // - that was the second half of the bug, and the less visible one.
            foreach (StreamWriter w in to) WriteRaw(w, msg);
            Interlocked.Increment(ref PeerBroadcasts);
        }

        // ── Federation ────────────────────────────────────────────────────

        // Dial out to every relay the operator listed. One thread per link, so
        // a friend's PC being offline cannot hold up the ones that are up.
        private void OpenConfiguredLinks()
        {
            foreach (string raw in (RelayLinks ?? "").Split(new char[] { ',', ';' }, StringSplitOptions.RemoveEmptyEntries))
            {
                string ep = raw.Trim();
                if (ep.Length > 0) DialLink(ep, ep);
            }
        }

        // Apply a changed link list without bouncing the server: relays that
        // were added get dialled, relays that were removed are closed and their
        // routes dropped. Restarting hosting would disconnect every client on
        // this PC, which is a far bigger punishment than the user asked for.
        public void SyncLinks()
        {
            if (!_run) return;
            HashSet<string> want = new HashSet<string>();
            foreach (string raw in (RelayLinks ?? "").Split(new char[] { ',', ';' }, StringSplitOptions.RemoveEmptyEntries))
            {
                string ep = raw.Trim();
                if (ep.Length > 0) want.Add(ep);
            }
            List<Link> extra = new List<Link>();
            lock (_linkLock)
            {
                foreach (KeyValuePair<string, Link> kv in _links)
                    if (!kv.Key.StartsWith("in:", StringComparison.Ordinal) && !want.Contains(kv.Key)) extra.Add(kv.Value);
            }
            foreach (Link l in extra)
            {
                lock (_linkLock) _links.Remove(l.Endpoint);
                l.Up = false;
                string goneId = l.C != null ? l.C.PeerRelayId : "";
                DropOrigin(goneId);
                try { if (l.C != null && l.C.Tcp != null) l.C.Tcp.Close(); } catch { }
                Emit("Link removed: " + l.Endpoint);
            }
            OpenConfiguredLinks();
        }

        // Connect, handshake, then read. Reconnects on any failure: a mesh of
        // laptops going in and out of wifi is the normal case, not the error.
        private void LinkLoop(Link l)
        {
            Thread t = new Thread((ThreadStart)delegate
            {
                while (_run)
                {
                    TcpClient tc = null;
                    SslStream ssl = null;
                    bool useTls = false;
                    try
                    {
                        string host;
                        int port;
                        if (!TryParseRelayEndpoint(l.Endpoint, out host, out port, out useTls))
                            throw new FormatException("invalid relay endpoint");
                        tc = new TcpClient();
                        tc.Connect(host, port);
                        Stream transport = tc.GetStream();
                        if (useTls)
                        {
                            ssl = new SslStream(transport, false);
                            ssl.AuthenticateAsClient(host, null, (SslProtocols)3072, false);
                            transport = ssl;
                        }
                        StreamReader r = new StreamReader(transport, Encoding.UTF8);
                        StreamWriter w = new StreamWriter(transport, Encoding.UTF8);
                        w.AutoFlush = true;
                        l.C = new Conn { IsLink = true, Number = "", Tcp = tc, W = w, PeerEndpoint = l.Endpoint };
                        WriteRaw(w, "RLINK|" + RelayId + "|" + RelayName + "|" + AdvertiseAddress());
                        string line;
                        bool ok = false;
                        while ((line = r.ReadLine()) != null)
                        {
                            Action<string> tap = WireIn;
                            if (tap != null) tap(line);
                            string[] p = line.Split(new char[] { '|' }, 4);
                            if (!ok)
                            {
                                if (p[0] == "RLINKOK" && p.Length >= 2)
                                {
                                    ok = true;
                                    l.Up = true;
                                    l.PeerRelayId = p[1];
                                    l.PeerAdvertise = p.Length >= 3 ? p[2] : "";
                                    l.C.PeerRelayId = p[1];
                                    l.C.PeerAdvertise = l.PeerAdvertise;
                                    RememberRelay(l.PeerAdvertise, l.PeerName);
                                    if (l.PeerAdvertise.Length > 0) AnnounceRelay(l.PeerAdvertise, l.PeerName, l.C);
                                    Emit("Link up (outgoing): relay " + p[1] + " at " + l.Endpoint +
                                         (l.PeerAdvertise.Length > 0 ? ", diallable as " + l.PeerAdvertise : ""));
                                    SendDirSnapshot(l.C);
                                    GossipRelays(l.C);
                                    AnnounceKey(l.C);
                                    SendKeySnapshot(l.C);
                                    SendPeerKeySnapshot(l.C);
                                    GossipKeys(l.C);
                                }
                                else if (p[0] == "ERR" && p.Length >= 2 && p[1] == "norelay")
                                {
                                    Emit("Link to " + l.Endpoint + " refused: " +
                                         (p.Length >= 3 ? p[2] : "their policy"));
                                    break;
                                }
                                continue;
                            }
                            if (p[0] == "RDIST") Absorb(l.C, p);
                            else if (p[0] == "RDROP") AbsorbDrop(l.C, p);
                            else if (p[0] == "CONF_HOST" && p.Length >= 3) LearnRoomHost(l.C, p[1].Trim(), p[2].Trim());
                            // Gossip about OTHER relays has to be absorbed on an
                            // outbound link too. It was only handled on inbound ones,
                            // so a relay that dialled out never learned what its peer
                            // told it about everyone else - the mesh could not self-form
                            // for the majority of links, which are dialled by definition.
                            else if (p[0] == "RKNEW" && p.Length >= 4) LearnRelay(l.C, p);
                            else if (p[0] == "RPUB") TryKeyLine(l.C, p);
                            else if (p[0] == "PKDIST") TryPeerKeyLine(l.C, p, line, true);
                            else if (p[0] == "MWHO" || p[0] == "MDROP") TryMailLine(l.C, p, line);
                            else if (p[0] == "MRCVD") TryMailLine(l.C, line.Split(new char[] { '|' }, 6), line);
                            else if (p[0] == "ONION" && p.Length >= 2) TryOnionLine(l.C, p[1]);
                            else if (p[0] == "XF" && p.Length >= 4)
                            {
                                int hops = 0; int.TryParse(p[1], out hops);
                                if (hops >= MaxHops) continue;
                                string inner = p[3];
                                string[] ip = inner.Split('|');
                                if (ip.Length >= 2 && (ip[0] == "MSG" || ip[0] == "RM"))
                                    Route(l.C, ip[1], inner, hops);
                                else if (ip[0] != null && (ip[0].StartsWith("CONF_", StringComparison.Ordinal) ||
                                         ip[0] == "ERR"))
                                    // As on the inbound link: a room error belongs to the
                                    // member it was addressed to, not to the relay that
                                    // happens to be carrying it.
                                    HandleForwardedConf(l.C, hops, p[2], inner);
                            }
                        }
                        if (!ok) { /* refused or dropped before handshake */ }
                    }
                    catch (Exception ex)
                    {
                        // A relay that is simply switched off is expected; say it
                        // once per attempt, not once per second.
                        if (l.Up || useTls) Emit("Link to " + l.Endpoint + " failed: " + ex.Message);
                    }
                    finally
                    {
                        if (ssl != null) try { ssl.Dispose(); } catch { }
                        if (tc != null) try { tc.Close(); } catch { }
                    }
                    l.Up = false;
                    if (l.C != null && l.C.PeerRelayId.Length > 0) DropOrigin(l.C.PeerRelayId);
                    l.C = null;
                    if (!_run) break;
                    // 3 s, not 10: a relay whose peer restarted a second later
                    // should rejoin the mesh promptly, and this loop still costs
                    // nothing worth worrying about while the address is down.
                    for (int i = 0; i < 3 && _run && !l.Up; i++) Thread.Sleep(1000);
                }
            });
            t.IsBackground = true;
            l.Reader = t;
            t.Start();
        }

        // null = accepted. Anything else is the reason we will not carry for them.
        string LinkPolicyDeny(string[] p, string remoteEndpoint)
        {
            string id = p.Length >= 2 ? p[1].Trim() : "";
            string name = p.Length >= 3 ? p[2].Trim() : "";
            if (id.Length == 0) return "badlink";
            if (string.Equals(id, RelayId, StringComparison.Ordinal)) return "selflink";
            string pol = (RelayPolicy ?? "allowed").Trim().ToLowerInvariant();
            if (pol == "nobody") return "policy-nobody";
            if (pol == "everyone") return null;
            // "allowed": match on something the operator can actually type and
            // that survives a restart. The relay id is random per boot, so it is
            // deliberately NOT the key here. Neither is the address the peer
            // *claims* to be diallable from: that is self-asserted and a
            // stranger could name an allowed host, so only the observed source
            // address and the claimed name are trusted.
            string hostOnly = remoteEndpoint;
            int colon = hostOnly.LastIndexOf(':');
            if (colon > 0) hostOnly = hostOnly.Substring(0, colon);
            if (AllowListed(hostOnly) || AllowListed(remoteEndpoint) ||
                (name.Length > 0 && AllowListed(name))) return null;
            return "not-allowed";
        }

        bool AllowListed(string probe)
        {
            if (string.IsNullOrEmpty(probe)) return false;
            foreach (string a in (RelayAllow ?? "").Split(new char[] { ',', ';' }, StringSplitOptions.RemoveEmptyEntries))
                if (string.Equals(a.Trim(), probe, StringComparison.OrdinalIgnoreCase)) return true;
            return false;
        }

        // Our whole view of who is reachable, minus anything this link already
        // told us about (split horizon: never send a route back where it came
        // from, which is what keeps a chain of relays from echoing forever).
        void SendDirSnapshot(Conn to)
        {
            List<string> local = new List<string>();
            List<RemoteRec> viaOther = new List<RemoteRec>();
            lock (_mapLock)
            {
                foreach (Conn c in _byNumber.Values)
                    if (!c.IsLink) local.Add(c.Number + "," + c.Ip + "," + c.Machine + "," + c.DirSeq);
                foreach (RemoteRec r in _remote.Values)
                    if (r.Origin != to.PeerRelayId) viaOther.Add(r);
            }
            if (local.Count > 0) WriteRaw(to.W, "RDIST|" + RelayId + "|" + string.Join(";", local.ToArray()));
            // Forwarded rows keep their own origin, so a 3-relay chain still
            // resolves end to end and each hop can drop the right rows on teardown.
            Dictionary<string, List<string>> byOrigin = new Dictionary<string, List<string>>();
            foreach (RemoteRec r in viaOther)
            {
                List<string> rows;
                if (!byOrigin.TryGetValue(r.Origin, out rows)) { rows = new List<string>(); byOrigin[r.Origin] = rows; }
                rows.Add(r.Number + "," + r.Ip + "," + r.Machine + "," + r.Seq);
            }
            foreach (KeyValuePair<string, List<string>> kv in byOrigin)
                WriteRaw(to.W, "RDIST|" + kv.Key + "|" + string.Join(";", kv.Value.ToArray()));
        }

        long NextSeq() { return Interlocked.Increment(ref _dirSeq); }

        // A number became reachable here: tell every link except none (new
        // registrations always originate from us).
        void Advertise(string number, string ip, string machine)
        {
            long seq = NextSeq();
            lock (_mapLock)
            {
                Conn c;
                if (_byNumber.TryGetValue(number, out c) && c != null) c.DirSeq = seq;
            }
            string row = number + "," + ip + "," + machine + "," + seq;
            foreach (Conn c in LinkConns(null))
                WriteRaw(c.W, "RDIST|" + RelayId + "|" + row);
        }

        void AdvertiseDrop(string number)
        {
            foreach (Conn c in LinkConns(null))
                WriteRaw(c.W, "RDROP|" + RelayId + "|" + number);
        }

        // A snapshot of live links, optionally excluding one. Taken under the
        // lock and written to *after* it is released: a peer on a saturated
        // home line can block a socket write for seconds, and holding _linkLock
        // across that would freeze every other link with it.
        List<Conn> LinkConns(Conn exclude)
        {
            List<Conn> outp = new List<Conn>();
            lock (_linkLock)
            {
                foreach (Link l in _links.Values)
                    if (l.Up && l.C != null && l.C != exclude) outp.Add(l.C);
            }
            return outp;
        }

        // Absorb a delta from a link. Sequence numbers make it idempotent and
        // order-safe: a row is applied only if it is newer than the last one we
        // saw from that (origin, number), so re-delivery after a reconnect and
        // out-of-order arrival cannot leave a stale route pointing at a dead relay.
        void Absorb(Conn from, string[] p)
        {
            if (p.Length < 3) return;
            string origin = p[1].Trim();
            if (origin.Length == 0 || origin == RelayId) return;
            bool changed = false;
            List<string> learned = null;
            foreach (string rec in p[2].Split(';'))
            {
                if (rec.Length == 0) continue;
                string[] f = rec.Split(',');
                if (f.Length < 1 || f[0].Length == 0) continue;
                string num = f[0].Trim();
                if (!RegexIsNumber(num)) continue;
                long seq = 0;
                if (f.Length >= 4) long.TryParse(f[3], out seq);
                string key = origin + "|" + num;
                lock (_mapLock)
                {
                    long seen;
                    if (_seenSeq.TryGetValue(key, out seen) && seq <= seen) continue;
                    _seenSeq[key] = seq;
                    // A local registration always wins: this PC hosts that number.
                    if (_byNumber.ContainsKey(num)) continue;
                    RemoteRec old;
                    if (_remote.TryGetValue(num, out old) && old.Origin == origin && old.Seq == seq) continue;
                    _remote[num] = new RemoteRec
                    {
                        Number = num,
                        Ip = f.Length >= 2 ? f[1] : "",
                        Machine = f.Length >= 3 ? f[2] : "",
                        Origin = origin,
                        Endpoint = from.PeerEndpoint,
                        Seq = seq
                    };
                    changed = true;
                    if (learned == null) learned = new List<string>();
                    learned.Add(num);
                    // Worth a line: a mesh that merged its directory one way only
                    // looks identical from the sending side, and the queue is the
                    // only trace that the other relay never learned the number.
                    Emit("Learned " + num + " is reachable via " + origin + " over " + from.PeerEndpoint);
                }
                // Carry the news to the other links so a chain learns too.
                foreach (Conn c in LinkConns(from))
                {
                    if (c.PeerRelayId == origin) continue;    // split horizon
                    WriteRaw(c.W, "RDIST|" + origin + "|" + rec);
                }
            }
            if (changed) MarkPeersDirty();
            // The other half of holding a join: this route is exactly what the
            // waiting member was missing. Replayed outside the map lock, because a
            // write to a slow peer must not hold the directory up for everybody.
            if (learned != null) foreach (string n in learned) ReplayPendingFor(n);
        }

        void AbsorbDrop(Conn from, string[] p)
        {
            if (p.Length < 3) return;
            string origin = p[1].Trim();
            bool changed = false;
            foreach (string num in p[2].Split(','))
            {
                string n = num.Trim();
                if (n.Length == 0) continue;
                lock (_mapLock)
                {
                    RemoteRec r;
                    if (_remote.TryGetValue(n, out r) && r.Origin == origin)
                    {
                        _remote.Remove(n);
                        changed = true;
                    }
                }
                // Forward the removal too. Without this, a relay that learned a
                // number through us would keep routing to a peer that left, and
                // the sender's mail would vanish into a dead route instead of
                // being queued where it can actually be delivered.
                foreach (Conn c in LinkConns(from))
                {
                    if (c.PeerRelayId == origin) continue;    // split horizon
                    WriteRaw(c.W, "RDROP|" + origin + "|" + n);
                }
            }
            if (changed) MarkPeersDirty();
        }

        // A link went away: every route that depended on it is invalid, and the
        // other links must be told before they keep forwarding into a hole.
        void DropOrigin(string origin)
        {
            if (string.IsNullOrEmpty(origin)) return;
            List<string> gone = new List<string>();
            lock (_mapLock)
            {
                foreach (RemoteRec r in _remote.Values) if (r.Origin == origin) gone.Add(r.Number);
                foreach (string n in gone) _remote.Remove(n);
            }
            foreach (Conn c in LinkConns(null))
            {
                if (c.PeerRelayId == origin) continue;
                foreach (string n in gone) WriteRaw(c.W, "RDROP|" + origin + "|" + n);
            }
            // A room routed through that relay is not reachable through it any more.
            DropRoomRoutesFor(origin);
        }

        // ── Onion: relay keys, circuit building, layer carrying ────────────
        //
        // A circuit can only be sealed to a hop whose key we hold, so the keys
        // have to travel. They are announced once per link, self-bound to the
        // relay id, and re-gossiped for relays a link has told us about.
        void AnnounceKey(Conn to)
        {
            if (to == null || !to.IsLink || to.W == null) return;
            string ln = OwnKeyLine();
            if (ln != null) WriteRaw(to.W, ln);
        }

        // This relay's own RPUB line, or null. One place builds it, because the
        // claim a client checks has to be exactly the claim a peer relay checks -
        // two implementations of "sign my relay id" would drift, and the day they
        // drift is the day a legitimate relay fails its own bootstrap check.
        string OwnKeyLine()
        {
            Identity k = RelayKey;
            if (k == null) return null;
            byte[] sig = k.Sign(Encoding.UTF8.GetBytes("RLID|" + RelayId));
            if (sig == null) return null;
            return KeyLine(RelayId, AdvertiseAddress(), k.PublicBase64, Convert.ToBase64String(sig));
        }

        // The wire form of a key:
        //   RPUB|<relayId>|<advertise>|<pubB64>|<sigB64>
        // Exactly the four fields the read loop splits into, with the signature
        // last so the glued remainder is one base64 blob that cannot swallow a
        // field. sigB64 is always the OWNING relay's claim over its own id: a
        // gossiped key has to carry that claim verbatim, because re-signing it
        // here would have the receiver check our signature against somebody
        // else's key and reject a perfectly good hop.
        static string KeyLine(string relayId, string adv, string pubB64, string sigB64)
        {
            if (string.IsNullOrEmpty(relayId) || string.IsNullOrEmpty(pubB64) ||
                string.IsNullOrEmpty(sigB64)) return null;
            return "RPUB|" + relayId + "|" + (adv ?? "") + "|" + pubB64 + "|" + sigB64;
        }

        // Hand every key we hold to the links that did not bring it. Split horizon
        // is what keeps this from looping forever in a ring of relays.
        void GossipKeys(Conn except)
        {
            List<string[]> rows = new List<string[]>();
            lock (_keyLock)
            {
                foreach (KeyValuePair<string, string> kv in _relayPubs)
                {
                    if (kv.Key == RelayId) continue;
                    string sig;
                    if (!_relaySigs.TryGetValue(kv.Key, out sig)) continue;
                    string adv;
                    if (!_relayAdv.TryGetValue(kv.Key, out adv)) adv = "";
                    rows.Add(new string[] { kv.Key, KeyLine(kv.Key, adv, kv.Value, sig) });
                }
            }
            if (rows.Count == 0) return;
            foreach (Conn c in LinkConns(except))
            {
                foreach (string[] r in rows)
                {
                    if (r[1] == null) continue;
                    if (c.PeerRelayId == r[0]) continue;         // the owner: no echo
                    Conn src;
                    lock (_keyLock) { if (_keySrc.TryGetValue(r[0], out src) && src == c) continue; }
                    WriteRaw(c.W, r[1]);
                }
            }
        }

        // ...and the direction GossipKeys deliberately skips. A brand-new link has
        // to be told the keys we already hold, or a relay that joined the chain last
        // can never seal a circuit through it: it would only ever learn a key if it
        // happened to be announced after that link came up, which is a race, not a
        // design. This is the same gap the relay gossip had, in the same shape.
        void SendKeySnapshot(Conn to)
        {
            if (to == null || !to.IsLink || to.W == null) return;
            List<string> rows = new List<string>();
            lock (_keyLock)
            {
                foreach (KeyValuePair<string, string> kv in _relayPubs)
                {
                    if (kv.Key == RelayId || kv.Key == to.PeerRelayId) continue;
                    string sig;
                    if (!_relaySigs.TryGetValue(kv.Key, out sig)) continue;
                    string adv;
                    if (!_relayAdv.TryGetValue(kv.Key, out adv)) adv = "";
                    string ln = KeyLine(kv.Key, adv, kv.Value, sig);
                    if (ln != null) rows.Add(ln);
                }
            }
            foreach (string ln in rows) WriteRaw(to.W, ln);
        }

        bool TryKeyLine(Conn conn, string[] p)
        {
            if (p[0] != "RPUB" || p.Length < 4) return false;
            if (conn == null || !conn.IsLink) return true;     // a user has no business announcing relay keys
            string[] rest = p[3].Split('|');
            if (rest.Length != 2) return true;
            NoteRelayKey(conn, p[1].Trim(), p[2].Trim(), rest[0].Trim(), rest[1].Trim());
            return true;
        }

        // Trust model, stated plainly: the signature proves a key *claims* this
        // relay id, and pinning by advertise endpoint proves the claim survived
        // from one boot to the next. Neither can catch a gossiping peer that
        // introduces a brand-new keypair for a relay id we have never seen
        // directly - that is the same first-use gap the peer book has, and it is
        // why a key change here is a refusal rather than a warning.
        void NoteRelayKey(Conn from, string relayId, string adv, string pubB64, string sigB64)
        {
            if (string.IsNullOrEmpty(relayId) || relayId == RelayId) return;
            if (string.IsNullOrEmpty(pubB64)) return;
            byte[] sig;
            try { sig = Convert.FromBase64String(sigB64 ?? ""); } catch { return; }
            if (!Identity.Verify(pubB64, Encoding.UTF8.GetBytes("RLID|" + relayId), sig))
            {
                Emit("Relay key for " + relayId + " does not prove that id; ignored");
                Interlocked.Increment(ref OnionRefused);
                return;
            }
            string handle = !string.IsNullOrEmpty(adv) ? adv
                        : (!string.IsNullOrEmpty(from.PeerAdvertise) ? from.PeerAdvertise : from.PeerEndpoint);
            bool known = false;
            if (!string.IsNullOrEmpty(handle))
            {
                Identity book = RelayKey;                        // makes sure the book exists
                string before = LookupPinned(handle);
                PeerIdentityBook.Trust t;
                lock (_keyLock) t = _relayKeys == null
                    ? PeerIdentityBook.Trust.New : _relayKeys.Check(handle, pubB64);
                if (t == PeerIdentityBook.Trust.Changed)
                {
                    // Read before Check(): after it the old key is already gone,
                    // and a "changed" warning that prints the new fingerprint
                    // twice tells the operator nothing.
                    Emit("RELAY KEY CHANGED for " + handle + " (was " +
                         Identity.FingerprintOf(before) + ", now " +
                         Identity.FingerprintOf(pubB64) + "). Refusing to seal through it - " +
                         "confirm over another channel before deleting " + (_bookPath ?? "relay_keys.txt"));
                    lock (_keyLock) { _relayPubs.Remove(relayId); _relaySigs.Remove(relayId); }
                    Interlocked.Increment(ref OnionRefused);
                    return;
                }
                if (t == PeerIdentityBook.Trust.New)
                    Emit("Pinned relay key " + Identity.FingerprintOf(pubB64) + " for " + handle);
            }
            lock (_keyLock)
            {
                string had;
                known = _relayPubs.TryGetValue(relayId, out had) && had == pubB64;
                _relayPubs[relayId] = pubB64;
                if (!string.IsNullOrEmpty(sigB64)) _relaySigs[relayId] = sigB64;
                _relayAdv[relayId] = handle ?? "";
                _keySrc[relayId] = from;
            }
            if (!known) GossipKeys(from);
            Emit("Relay key ready for " + relayId + " (" + Identity.FingerprintOf(pubB64) + ")");
        }

        string LookupPinned(string handle)
        {
            if (string.IsNullOrEmpty(handle)) return "";
            Identity book = RelayKey;
            lock (_keyLock) return _relayKeys == null ? "" : (_relayKeys.Lookup(handle) ?? "");
        }

        Conn LinkByRelayId(string relayId)
        {
            if (string.IsNullOrEmpty(relayId)) return null;
            lock (_linkLock)
            {
                foreach (Link l in _links.Values)
                    if (l.Up && l.C != null && l.C.PeerRelayId == relayId) return l.C;
            }
            return null;
        }

        // Which link carries traffic toward a given relay. The direct link wins
        // when there is one; otherwise the answer is already in the directory,
        // because every row says which relay owns it and which link reaches that
        // relay. That is what lets a circuit cross a chain the sender's relay has
        // never seen the shape of: each hop resolves one step further.
        Conn LinkTowardRelay(string relayId, Conn exclude)
        {
            Conn direct = LinkByRelayId(relayId);
            if (direct != null && direct != exclude) return direct;
            string endpoint = "";
            lock (_mapLock)
            {
                foreach (RemoteRec r in _remote.Values)
                    if (r != null && r.Origin == relayId && !string.IsNullOrEmpty(r.Endpoint))
                    { endpoint = r.Endpoint; break; }
            }
            if (endpoint.Length == 0) return null;
            Conn c = null;
            lock (_linkLock)
            {
                Link l;
                if (_links.TryGetValue(endpoint, out l) && l.Up && l.C != null) c = l.C;
            }
            return c == exclude ? null : c;
        }

        // Build the layered envelope for a line that has an intermediate hop in
        // front of it. Returns null with a reason when it cannot, which is the
        // common case on a one-hop route - there is nothing to hide there.
        string BuildOnion(RemoteRec r, string toNumber, string line, out Conn nextHop, out string why)
        {
            why = "";
            nextHop = null;
            if (r == null) { why = "no route"; return null; }
            Conn next = null;
            string nextId = "";
            lock (_linkLock)
            {
                Link l;
                if (_links.TryGetValue(r.Endpoint, out l) && l.Up && l.C != null)
                {
                    next = l.C;
                    nextId = l.C.PeerRelayId;
                }
            }
            if (next == null || nextId.Length == 0) { why = "the link is down"; return null; }
            if (nextId == r.Origin) return null;              // one hop: no intermediate to hide from
            string pubA = PubOf(nextId);
            if (string.IsNullOrEmpty(pubA)) { why = "no key for hop " + nextId; return null; }
            string pubB = PubOf(r.Origin);
            if (string.IsNullOrEmpty(pubB)) { why = "no key for the destination relay " + r.Origin; return null; }
            List<string> pubs = new List<string>();
            pubs.Add(pubA);
            pubs.Add(pubB);
            List<string> nexts = new List<string>();
            nexts.Add(r.Origin);
            nexts.Add("");
            string tok = Onion.Build(pubs, nexts, toNumber, line);
            if (tok == null) { why = "the message is too large for a layer"; return null; }
            nextHop = next;
            return tok;
        }

        // Open one layer. Consumes the line in every case: a layer we cannot open
        // is not something to hand to the ordinary router, which would learn the
        // pair we were trying to keep hidden.
        bool TryOnionLine(Conn conn, string token)
        {
            if (conn == null || !conn.IsLink) return false;
            Identity me = RelayKey;
            if (me == null) return true;
            OnionHop h = Onion.Peel(me, token);
            if (h == null)
            {
                Emit("ONION layer did not open here (not our circuit, edited, or garbage)");
                Interlocked.Increment(ref OnionRefused);
                return true;
            }
            if (h.Expired)
            {
                Emit("ONION layer at hop " + h.Index + " had aged out; dropped");
                Interlocked.Increment(ref OnionRefused);
                return true;
            }
            if (h.Kind == "END")
            {
                Conn target = null;
                lock (_mapLock) _byNumber.TryGetValue(h.Dest, out target);
                if (target != null && !target.IsLink && target.W != null)
                {
                    WriteRaw(target.W, h.Body);
                    Interlocked.Increment(ref OnionCarried);
                    Emit("ONION delivered to #" + h.Dest);
                    return true;
                }
                // The directory said this number was here and it is not: it went
                // offline mid-flight. Losing the message is worse than the small
                // leak of handing it to whatever relay claims it now, but the
                // leak is worth saying out loud.
                Emit("ONION endpoint #" + h.Dest + " is not registered here; falling back to a routed forward, which the next hop can read");
                Route(conn, h.Dest, h.Body, OnionMaxHops - 1);
                Interlocked.Increment(ref OnionRefused);
                return true;
            }
            if (h.Kind != "HOP" || h.Index + 1 >= OnionMaxHops)
            {
                Emit("ONION stopped at hop " + h.Index + " (kind " + h.Kind + ")");
                Interlocked.Increment(ref OnionRefused);
                return true;
            }
            Conn next = LinkTowardRelay(h.Dest, conn);
            if (next == null || next.W == null)
            {
                Emit("ONION cannot continue: no route from here to relay " + h.Dest);
                Interlocked.Increment(ref OnionRefused);
                return true;
            }
            string carry = h.Body;
            if (next.PeerRelayId != h.Dest)
            {
                // Not the owner yet, so this hop's neighbour needs an envelope of
                // its own. Re-wrapping is the whole reason a circuit can cross a
                // chain the origin relay has never mapped.
                string pub = PubOf(next.PeerRelayId);
                if (string.IsNullOrEmpty(pub))
                {
                    Emit("ONION cannot continue: no key for relay " + next.PeerRelayId);
                    Interlocked.Increment(ref OnionRefused);
                    return true;
                }
                carry = Onion.Wrap(pub, h.Dest, h.Body, h.Index + 1);
                if (carry == null)
                {
                    Emit("ONION could not be re-sealed for the next hop");
                    Interlocked.Increment(ref OnionRefused);
                    return true;
                }
            }
            if (RelayBandwidthKbps > 0 && carry != null && carry.Length > RelayBandwidthKbps * 128)
            {
                Emit("ONION deferred: over the bandwidth cap this relay set for carrying");
                return true;
            }
            WriteRaw(next.W, "ONION|" + carry);
            Interlocked.Increment(ref OnionCarried);
            Emit("ONION carried hop " + h.Index + " -> " + h.Dest);
            return true;
        }

        // Forward a line to the relay that owns the target. envelope is explicit
        // because a LINK has no number of its own: re-using the link's would put
        // an empty field on the wire and the far side could not attribute the
        // line to anyone.
        bool Forward(Conn from, string toNumber, int hops, string line)
        {
            return Forward(from, toNumber, from != null ? from.Number : "", hops, line);
        }

        bool Forward(Conn from, string toNumber, string envelope, int hops, string line)
        {
            RemoteRec r;
            Conn targetConn = null;
            lock (_mapLock)
            {
                if (!_remote.TryGetValue(toNumber, out r)) return false;
            }
            lock (_linkLock)
            {
                Link l;
                if (_links.TryGetValue(r.Endpoint, out l) && l.Up && l.C != null) targetConn = l.C;
            }
            if (targetConn == null) return false;

            // Courtesy cap, not enforcement: it stops a friendly mesh from
            // saturating somebody's uplink by accident. A determined peer is a
            // different problem, and the answer to that is policy-nobody.
            if (RelayBandwidthKbps > 0)
            {
                int now = Environment.TickCount;
                if (now - _fwdWindowTick > 1000) { _fwdWindowTick = now; Interlocked.Exchange(ref _fwdWindowBytes, 0); }
                long budget = RelayBandwidthKbps * 1024L;
                if (Interlocked.Read(ref _fwdWindowBytes) + line.Length > budget) return false;
            }
            Interlocked.Add(ref _fwdWindowBytes, line.Length);
            WriteRaw(targetConn.W, "XF|" + (hops + 1) + "|" + (envelope ?? "") + "|" + line);
            if (line.StartsWith("RM|", StringComparison.Ordinal))
            {
                Interlocked.Increment(ref MediaForwarded);
                Interlocked.Add(ref MediaForwardedBytes, line.Length);
            }
            return true;
        }

        private static void WriteRaw(StreamWriter w, string line)
        {
            try
            {
                // w may belong to a socket that is closing - per-connection lock
                lock (w) w.WriteLine(line);
            }
            catch { }
        }

        private static bool RegexIsNumber(string s)
        {
            if (string.IsNullOrEmpty(s) || s.Length < 4 || s.Length > 15) return false;
            foreach (char c in s) if (c < '0' || c > '9') return false;
            return true;
        }
    }

    // =====================================================================
    // RelayClient: persistent connection from this app to a call server.
    // Maintains the number directory and carries signaling/media relay
    // traffic when a direct peer path is unavailable.
    // =====================================================================
    public sealed class RelayClient : IDisposable
    {
        public string Address = "";            // host:port
        public string Number = "";
        public string Token = "";
        public string Machine = Environment.MachineName;

        public class PeerInfo
        {
            public string Number;
            public string Ip;
            public string Machine;
            public override string ToString() { return Number + "  (" + Machine + " @" + Ip + ")"; }
        }

        private volatile bool _run;
        private volatile bool _connected;
        public bool UseTls { get; private set; }
        private SslStream _ssl;
        // Set when the relay has accepted our REG, not when the socket opened. The gap
        // between those two is small and always has been, and everything that asks "am I
        // reachable yet" was answering the wrong question: dialling, group calls, file
        // transfer and voice notes all proceeded against a session the relay had not
        // registered, with an empty directory and a peer list that cannot exist yet.
        private volatile bool _registered;
        private TcpClient _tcp;
        private StreamWriter _w;
        private readonly object _writeLock = new object();
        private readonly object _dirLock = new object();
        private Dictionary<string, PeerInfo> _dir = new Dictionary<string, PeerInfo>();
        private Thread _thread;

        public event Action<string> Log;
        public event Action DirectoryChanged;
        public event Action<string, string> MessageArrived;   // fromNumber, line (MSG|...)
        public event Action<string, string> MediaArrived;     // fromNumber, base64 payload
        public event Action<string> MessageQueued;            // target offline, message stored server-side
        public event Action<string> MessageUndeliverable;     // target offline, nothing stored
        // This number is already leased to someone else and our token did not match.
        // Distinct from a busy number on purpose: "someone else is using it right now"
        // and "someone else owns it" need different answers from the user.
        public event Action<string> RegistrationRefused;      // number
        public event Action<string, int> ClaimAttemptsSeen;   // number, refusals since we last connected
        // A room join that never landed. The relay holds a join while the route
        // appears, so this now means "I waited and nobody came", which is exactly
        // what the screen has to say - not the "joined room" line it prints today.
        public event Action<string> RoomUnavailable;          // roomId
        string _refusalSaid = "";                             // explain a standing refusal once, not every beat

        public bool Connected { get { return _connected; } }
        // Registered is the one to ask before relying on the directory. Connected only
        // means a socket: the relay has our number on it, and has agreed to nothing.
        public bool Registered { get { return _registered; } }
        public bool Running { get { return _thread != null; } }

        public List<PeerInfo> Directory
        {
            get { lock (_dirLock) return new List<PeerInfo>(_dir.Values); }
        }

        public PeerInfo Lookup(string number)
        {
            lock (_dirLock)
            {
                PeerInfo p;
                if (_dir.TryGetValue(number, out p)) return p;
                return null;
            }
        }

        // ── "is that number online?" asked of the relay, not of the cache ──────
        // The directory is a snapshot that arrives some moments after connecting, so on a
        // freshly opened client it is empty while the friend is very much online. Nothing
        // should be able to tell a person "they are offline" on that basis - the relay
        // knows, so ask it and wait a bounded moment for the answer.
        private readonly Dictionary<string, bool> _whoAnswers = new Dictionary<string, bool>();
        private readonly Dictionary<string, bool> _whoRemote = new Dictionary<string, bool>();
        private readonly object _whoLock = new object();
        // "yes", "no" or "silent" for the last question asked. They need different words
        // on screen: a relay that says no has settled the matter, a relay that says
        // nothing has not, and telling a person their friend is offline because of a
        // timeout would be the same lie in a new outfit.
        public string WhoVerdict = "never asked";

        // True only when the relay said yes. Silence, a closed socket and a malformed
        // reply all mean "do not know", which the caller treats as no rather than as an
        // excuse to dial into nothing.
        public bool AskOnline(string number, int waitMs)
        {
            if (string.IsNullOrEmpty(number) || !_connected) return false;
            // Before registration the relay answers WHO with ERR|registerfirst, so asking
            // is not merely useless, it wastes 1.5 s of somebody waiting to dial. The
            // caller is told "not registered yet" rather than being handed a false no.
            if (!_registered) { WhoVerdict = "not registered"; return false; }
            lock (_whoLock) { _whoAnswers.Remove(number); _whoRemote.Remove(number); }
            Write("WHO|" + number);
            WhoVerdict = "asking";
            int end = Environment.TickCount + waitMs;
            while (Environment.TickCount < end)
            {
                lock (_whoLock) if (_whoAnswers.ContainsKey(number))
                {
                    bool yes = _whoAnswers[number];
                    WhoVerdict = yes ? "yes" : "no";
                    return yes;
                }
                Thread.Sleep(40);
            }
            WhoVerdict = "silent";
            return false;
        }

        // Whether the relay said the number is on ANOTHER relay, which means the caller
        // cannot reach it directly and the media has to be carried.
        public bool IsRemoteNumber(string number)
        {
            lock (_whoLock)
            {
                bool r;
                return _whoRemote.TryGetValue(number, out r) && r;
            }
        }

        private void Emit(string s)
        {
            Hang.Trace("RelayCli emit: " + s);
            Action<string> h = Log;
            if (h != null) h(s);
        }

        public void Start(string address, string number, string token)
        {
            Address = address;
            if (Address != null && Address.StartsWith("tls://", StringComparison.OrdinalIgnoreCase))
            {
                UseTls = true;
                Address = Address.Substring("tls://".Length);
            }
            else if (Address != null && Address.StartsWith("ssl://", StringComparison.OrdinalIgnoreCase))
            {
                UseTls = true;
                Address = Address.Substring("ssl://".Length);
            }
            else
            {
                UseTls = false;
            }
            Number = number;
            Token = token;
            if (_thread != null) return;
            _run = true;
            _thread = new Thread(RunLoop);
            _thread.IsBackground = true;
            _thread.Start();
        }

        public void Stop()
        {
            _run = false;
            try { if (_ssl != null) _ssl.Dispose(); } catch { }
            try { if (_tcp != null) _tcp.Close(); } catch { }
            _ssl = null;
            _connected = false;
            _registered = false;
            Thread t = _thread;
            _thread = null;
            if (t != null) try { t.Join(800); } catch { }
        }

        public void Dispose() { Stop(); }

        private void RunLoop()
        {
            while (_run)
            {
                try
                {
                    if (string.IsNullOrEmpty(Address)) { Thread.Sleep(2000); continue; }
                    string host;
                    int port;
                    bool endpointTls;
                    if (!CallServer.TryParseRelayEndpoint(Address, out host, out port, out endpointTls))
                        throw new FormatException("invalid relay endpoint");
                    if (endpointTls) UseTls = true;
                    TcpClient tc = new TcpClient();
                    IAsyncResult ar = tc.BeginConnect(host, port, null, null);
                    if (!ar.AsyncWaitHandle.WaitOne(5000, false)) { tc.Close(); throw new Exception("connect timeout"); }
                    tc.EndConnect(ar);
                    if (!_run) { tc.Close(); return; }   // Stop() raced the connect - never register
                    tc.ReceiveTimeout = 0; // read loop blocks; server closes on failure
                    try { tc.Client.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.KeepAlive, true); } catch { }
                    Stream net = tc.GetStream();
                    StreamReader r;
                    StreamWriter w;
                    if (UseTls)
                    {
                        SslStream ssl = new SslStream(net, false);
                        ssl.AuthenticateAsClient(host, null, (SslProtocols)3072, false);
                        _ssl = ssl;
                        r = new StreamReader(ssl, Encoding.UTF8);
                        w = new StreamWriter(ssl, Encoding.UTF8);
                    }
                    else
                    {
                        w = new StreamWriter(net, Encoding.UTF8);
                        r = new StreamReader(net, Encoding.UTF8);
                    }
                    w.AutoFlush = true;
                    _tcp = tc;
                    _w = w;
                    _connected = true;

                    // ── who are we about to tell our number to? ──────────────
                    // Asked and answered BEFORE the registration, on this one ordered
                    // socket: a relay that is not the relay its address claims to be
                    // is caught before it has our number, our peer list or any of the
                    // mail we would later queue there. Too old to answer stays allowed
                    // and unverified - nobody can upgrade every server at once - but a
                    // key that does not match the one we pinned for this address is
                    // not a thing to shrug at, so that connection is closed for good.
                    string verdict = AskRelayIdentity(tc, r);
                    if (ProbeOnly)
                    {
                        // No REG and no key publication on this socket, whatever the
                        // verdict said: an address we came to look at is not being told
                        // who we are. The finally below closes it; the caller reads the
                        // fields AskRelayIdentity left behind.
                        if (verdict != "mismatch" && verdict != "bad-signature")
                            Emit("Relay: " + Address + " probed only - its identity was checked and nothing was registered.");
                        _run = false;
                        return;
                    }
                    if (verdict == "mismatch" || verdict == "bad-signature")
                    {
                        Emit("SECURITY: " + Address + " answered with a relay key that is NOT the one pinned for"
                             + (verdict == "mismatch" ? " it." : " which it did not sign correctly.")
                             + " Nothing was registered and this client will not reconnect to it. Check the"
                             + " address, and ask whoever runs the relay for its fingerprint."
                             + " To start over deliberately, delete relay_pins.txt from the profile.");
                        try { tc.Close(); } catch { }
                        _connected = false;
                        Stop();
                        return;
                    }
                    Write(RegLine());
                    // Cleared per attempt, deliberately NOT cleared by the keepalive
                    // re-REG below: that one refreshes a registration that is already
                    // good, and flickering this off would drop every "ready" gate in the
                    // app once a minute for no reason.
                    _registered = false;
                    // Publish our identity key with the registration, so a peer can
                    // seal a message to us while we are off-line. Without this the
                    // only way to get a key is to be connected to exchange one.
                    PublishKeyLine();
                    Emit("Relay: connected to " + Address + ", registering #" + Number);
                    Hang.Trace("RelayCli connected+REG sent");

                    // keepalive thread for this connection; every third beat is a
                    // re-REG so a silently-lost directory entry self-heals.
                    TcpClient conn = tc;
                    int kaTick = 0;
                    Thread ka = new Thread((ThreadStart)delegate
                    {
                        while (_run && _connected && _tcp == conn)
                        {
                            Thread.Sleep(20000);
                            if (!_run || _tcp != conn) break;
                            if (Interlocked.Increment(ref kaTick) % 3 == 0)
                            {
                                Hang.Trace("RelayCli KA tick=" + kaTick + " -> re-REG");
                                Write(RegLine());
                                PublishKeyLine();
                            }
                            else
                            {
                                Hang.Trace("RelayCli KA tick=" + kaTick);
                                Write("KA|");
                            }
                        }
                    });
                    ka.IsBackground = true;
                    ka.Start();

                    string line;
                    while (_run && (line = r.ReadLine()) != null)
                        Dispatch(line);

                    Hang.Trace("RelayCli read ended (server closed)");
                    if (!_run) return;
                    throw new Exception("server closed connection");
                }
                catch (Exception ex)
                {
                    if (!_run) return;
                    // A probe gets one attempt and no retry loop: standing on a dead
                    // address is how a bootstrap stalls look from the user's side, so
                    // the attempt is reported as settled with no answer in it.
                    if (ProbeOnly) { RelayAskSettled = true; _run = false; return; }
                    Emit("Relay: connection problem (" + ex.Message + ") - retrying...");
                }
                finally
                {
                    _connected = false;
                    _registered = false;
                    try { if (_ssl != null) _ssl.Dispose(); } catch { }
                    _ssl = null;
                    try { if (_tcp != null) _tcp.Close(); } catch { }
                    _tcp = null;
                    _w = null;
                }
                for (int i = 0; i < 10 && _run; i++) Thread.Sleep(500);
            }
        }

        public event Action<string> RelaysReferral;   // comma list of host:port

        public void RequestRelayList()
        {
            if (!_connected) return;
            Write("RLIST|");
        }

        // ── Published identity keys ──────────────────────────────────────
        // The line is built by the owner (VoipService), because only it holds the
        // private key to sign the claim. Set it once at startup; it goes out with
        // every registration, so a key published before a peer existed is still
        // there when they look.
        public string OwnKeyLine = "";
        // <identityPub>|<sig over "OWNS|<number>"> - appended to the registration so
        // the relay can prove to itself, and to anyone reading its lease file, that
        // the number belongs to a key rather than to whoever knows a secret. Built by
        // VoipService for the same reason OwnKeyLine is: only the owner holds the
        // private half.
        public string OwnProof = "";
        // ── what we know about the relay itself ─────────────────────────
        // Address -> the relay key first seen there. Held in its own file because
        // these pins are about servers, not people, and deleting them to redo a
        // relay is not the same decision as deleting a peer's pin.
        public PeerIdentityBook RelayPins;
        public string RelayTrust = "unattested";   // unattested | verified-new | verified-known | mismatch | bad-signature
        // "unattested" is also the starting value, so a caller that wants to know
        // whether the question was even answered needs this - not the verdict string.
        public bool RelayIdentityChecked;
        // The identity question is SETTLED: an answer arrived, the relay said it has
        // no identity to offer, or it stayed silent past the timeout. Not the same as
        // Connected - the socket comes up FIRST and the check is still in flight
        // behind it, so a caller that waits on Connected reads "no answer yet" as
        // "no answer coming" and decides early. That misread is what made a perfectly
        // good seed line look broken in the first end-to-end run.
        public bool RelayAskSettled;
        // Said it has no relay identity, because it is deliberately configured to link
        // to nobody. Different from not answering, and it needs different words: one
        // is the operator's choice, the other is a relay built before this check.
        public bool RelayRefusedIdentity;
        // How long to wait for the answer before calling the relay silent. Four
        // seconds is roomy across a LAN and short enough that a dead address cannot
        // hang a client which still has a connection to get on with.
        public int IdentityTimeoutMs = 4000;
        // Look, and do not introduce ourselves: ask WHOAMI, then hang up without
        // registering. Bootstrap probes use this, because "check the relay before you
        // hand it your number" is undone the moment the same socket sends the number
        // anyway once the answer turns out to be inconclusive.
        public bool ProbeOnly;
        public string RelayIdSeen = "";
        public string RelayFingerprint = "";
        public event Action<string> RelayTrustChanged;      // verdict text
        public event Action<string, string> RelayIdentityArrived;   // relayId, fingerprint

        // Ask, read the answer, decide. Returns the verdict string and leaves the
        // fields set for whoever is showing this to a user.
        //
        // The timeout is the point of no return: a relay from before this check
        // answers nothing and must not be able to hang the client, so four seconds of
        // silence becomes "unattested" and the connection proceeds as it always did.
        string AskRelayIdentity(TcpClient tc, StreamReader r)
        {
            RelayTrust = "unattested";
            RelayIdSeen = "";
            RelayFingerprint = "";
            RelayRefusedIdentity = false;
            RelayAskSettled = false;              // this attempt is now in flight
            PeerIdentityBook pins = RelayPins;
            string pinned = null;
            try { if (pins != null) pinned = pins.Lookup(Address); } catch { }
            string line = null;
            bool refused = false;
            try
            {
                try { tc.Client.ReceiveTimeout = IdentityTimeoutMs; } catch { }
                Write("WHOAMI|");
                for (int guard = 0; guard < 8; guard++)
                {
                    line = r.ReadLine();
                    if (line == null) break;
                    if (line.StartsWith("RPUB|", StringComparison.Ordinal)) break;
                    if (line.StartsWith("ERR|norelaykey", StringComparison.Ordinal)) { line = null; refused = true; break; }
                    // Anything else at this point is not an answer to us; the relay has
                    // nothing it may send unasked, so stopping here beats reading on
                    // hoping for better luck.
                    if (!line.StartsWith("OK|", StringComparison.Ordinal)) { line = null; break; }
                }
            }
            catch { line = null; }      // silent or old relay: unattested, carry on
            finally { try { tc.Client.ReceiveTimeout = 0; } catch { } }

            if (string.IsNullOrEmpty(line))
            {
                RelayRefusedIdentity = refused;
                Emit(refused
                    ? "Relay: " + Address + " says it has no relay identity to offer, so there is nothing to"
                      + " check it against. It is reachable, and traffic to it stays sealed."
                    : "Relay: " + Address + " did not identify itself (a relay from before that check)."
                      + " Traffic is still sealed from it, but its identity is unverified.");
                RaiseTrust();
                return RelayTrust;
            }
            string rid, adv, pub, sig;
            RelayIdentityChecked = true;      // we asked, and something answered
            if (!RelayIdentity.TryParse(line, out rid, out adv, out pub, out sig))
            {
                RelayTrust = "bad-signature";
                RaiseTrust();
                return RelayTrust;
            }
            RelayIdentity.Verdict v = RelayIdentity.Judge(RelayIdentity.Verify(pub, rid, sig), pub, pinned);
            RelayIdSeen = rid;
            RelayFingerprint = RelayIdentity.Fingerprint(pub);
            RelayTrust = v == RelayIdentity.Verdict.New ? "verified-new"
                       : v == RelayIdentity.Verdict.Same ? "verified-known"
                       : v == RelayIdentity.Verdict.Mismatch ? "mismatch" : "bad-signature";
            if (v == RelayIdentity.Verdict.New && pins != null)
            {
                // Pin it, then say what was pinned. The fingerprint is printed because
                // this is the one moment a user can compare it against whatever the
                // relay's owner read out to them over a channel this one did not carry.
                try { pins.Check(Address, pub); } catch { }
                Emit("Relay: " + Address + " is " + rid + ", fingerprint " + RelayFingerprint +
                     " - pinned. Read those digits against the relay's own log (it prints the same line) before"
                     + " you rely on it with anything private.");
            }
            else if (v == RelayIdentity.Verdict.Same)
                Emit("Relay: " + Address + " presented the key pinned for it (" + RelayFingerprint + ").");
            RaiseTrust();
            return RelayTrust;
        }

        void RaiseTrust()
        {
            // Every exit from AskRelayIdentity comes through here, and only once the
            // verdict and the fields beside it are final - which makes this the one
            // place that can honestly tell a waiter "the answer is whatever you see".
            RelayAskSettled = true;
            Action<string> ht = RelayTrustChanged;
            if (ht != null) ht(RelayTrust);
            Action<string, string> hi = RelayIdentityArrived;
            if (hi != null) hi(RelayIdSeen, RelayFingerprint);
        }
        public event Action<string, string> PeerKeyArrived;    // number, pubB64 (empty = none known)

        // The registration line, proof included when we have one. The relay reads
        // four fields and lets the fourth keep its pipes, so the proof rides inside
        // the machine field - and a relay that has never heard of OWNS simply stores
        // the longer machine string, which costs nothing.
        string RegLine()
        {
            string p = OwnProof;
            if (string.IsNullOrEmpty(p)) return "REG|" + Number + "|" + Token + "|" + Machine;
            return "REG|" + Number + "|" + Token + "|" + Machine + "|" + p;
        }

        void PublishKeyLine()
        {
            string ln = OwnKeyLine;
            if (string.IsNullOrEmpty(ln)) return;
            Write(ln);
        }

        // Ask for the key a peer published. Answered by PKPUB (verified below) or
        // PKNONE; a relay that simply does not answer leaves the caller holding the
        // message, which is the correct outcome - silence must not look like a key.
        public void RequestPeerKey(string number)
        {
            if (string.IsNullOrEmpty(number)) return;
            if (!_connected) return;
            Write("PKQ|" + number);
        }

        // Send a line immediately rather than waiting for the next registration.
        // Used when the identity key becomes available after the connection was made
        // (a number claimed later, or a key file created on first chat).
        public void PublishNow(string line)
        {
            if (string.IsNullOrEmpty(line) || !_connected) return;
            Write(line);
        }

        private void Dispatch(string line)
        {
            string[] p = line.Split(new char[] { '|' }, 4);
            if (p[0] == "RLIST")
            {
                // Other relays this one knows about. Treated as a hint to show
                // the user, never dialed automatically: a relay can name any
                // address, so trusting it silently would let one hostile host
                // point every client at a server he controls.
                Action<string> hrl = RelaysReferral;
                if (hrl != null) hrl(p.Length >= 2 ? p[1] : "");
                return;
            }
            if (p[0] == "PEERS" && p.Length >= 2)
            {
                Dictionary<string, PeerInfo> dir = new Dictionary<string, PeerInfo>();
                string[] recs = p[1].Split(';');
                foreach (string rec in recs)
                {
                    if (rec.Length == 0) continue;
                    string[] f = rec.Split(',');
                    if (f.Length >= 1 && f[0].Length > 0)
                        dir[f[0]] = new PeerInfo
                        {
                            Number = f[0],
                            Ip = f.Length >= 2 ? f[1] : "",
                            Machine = f.Length >= 3 ? f[2] : ""
                        };
                }
                lock (_dirLock) _dir = dir;
                // self-heal: if the server dropped us (e.g. a stale connection of ours
                // unregistered the number), claim it again on this connection.
                if (_run && Number.Length > 0 && !dir.ContainsKey(Number))
                {
                    Hang.Trace("RelayCli PEERS self-heal re-REG (dir=" + dir.Count + ")");
                    Write(RegLine());
                    PublishKeyLine();
                }
                Hang.Trace("RelayCli PEERS dir=" + dir.Count);
                Action h = DirectoryChanged;
                if (h != null) h();
                return;
            }
            if (p[0] == "PKPUB" && p.Length >= 4)
            {
                // The claim is verified with the key it presents, so a relay cannot
                // hand this client an arbitrary key and have offline mail sealed to it.
                string num = p[1].Trim();
                string pub = p[2].Trim();
                string[] rest = p[3].Split('|');
                string sig = rest[0].Trim();
                bool okClaim = false;
                try
                {
                    byte[] s = Convert.FromBase64String(sig ?? "");
                    okClaim = Identity.Verify(pub, Encoding.UTF8.GetBytes("PUBK|" + num), s);
                }
                catch { okClaim = false; }
                if (!okClaim)
                {
                    Emit("Relay: a key offered for #" + num + " does not prove that number - ignored");
                    return;
                }
                Action<string, string> hk = PeerKeyArrived;
                if (hk != null) hk(num, pub);
                return;
            }
            if (p[0] == "PKNONE" && p.Length >= 2)
            {
                Action<string, string> hn = PeerKeyArrived;
                if (hn != null) hn(p[1].Trim(), "");
                return;
            }
            if (p[0] == "MSG" && p.Length >= 4)
            {
                Action<string, string> h = MessageArrived;
                if (h != null) h(p[2], p[3]);
                return;
            }
            if (p[0] == "RM" && p.Length >= 4)
            {
                Action<string, string> h = MediaArrived;
                if (h != null) h(p[2], p[3]);
                return;
            }
            if (p[0] == "OK")
            {
                // The relay has the number and will answer for it. This is the moment
                // "ready" starts to mean anything; PEERS follows on the same socket.
                _registered = true;
                _refusalSaid = "";     // we are registered: a later refusal is news again
                Emit("Relay: registered as #" + (p.Length >= 2 ? p[1] : ""));
                return;
            }
            // The relay's answer to "is this number online". Only ever read by whoever
            // asked, and a missing answer means no answer, never a guess.
            if (p[0] == "WHO" && p.Length >= 3)
            {
                lock (_whoLock)
                {
                    _whoRemote[p[1]] = (p.Length >= 4 && p[3] == "remote");
                    _whoAnswers[p[1]] = (p[2] == "yes");
                }
                return;
            }
            if (p[0] == "ERR")
            {
                // "claimed" must not read like a transient error. No amount of retrying
                // fixes it, and saying nothing would leave the user believing they are
                // reachable while nothing addressed to them arrives here at all.
                if (p.Length >= 2 && p[1] == "claimed")
                {
                    string num = p.Length >= 3 ? p[2] : Number;
                    Emit("Relay: #" + num + " is leased to another install's token, so this one was refused."
                         + " Nobody can take your number without your number_token - if this device is the"
                         + " rightful owner after a config reset, the relay operator has to release it"
                         + " (--release-number=" + num + ") or delete the relay's number_leases.txt.");
                    if (_refusalSaid != num)
                    {
                        _refusalSaid = num;
                        Action<string> hr = RegistrationRefused;
                        if (hr != null) hr(num);
                    }
                    return;
                }
                if (p.Length >= 2 && p[1] == "badproof")
                {
                    // Our own key signed something the relay would not accept, or the
                    // number is claimed by a key that is not ours. This is not a
                    // network hiccup to retry quietly: it means this install does not
                    // own the number it is trying to use.
                    Emit("Relay: #" + (p.Length >= 3 ? p[2] : Number) +
                         " refused our ownership proof. This install's identity key does not sign the claim" +
                         " that number belongs to it - if the number is yours from another device, restore" +
                         " that identity.key, or ask the relay operator to release it (--release-number=" +
                         (p.Length >= 3 ? p[2] : Number) + ").");
                    if (_refusalSaid != "proof")
                    {
                        _refusalSaid = "proof";
                        Action<string> hb = RegistrationRefused;
                        if (hb != null) hb(p.Length >= 3 ? p[2] : Number);
                    }
                    return;
                }
                if (p.Length >= 2 && p[1] == "nokey")
                {
                    // The relay kept nothing. Say which rule stopped it, because the
                    // sender's app already tries to seal: this reaches the log when a
                    // line went out around that funnel, or from a build too old to seal.
                    Emit("Relay: nothing was stored for #" + (p.Length >= 3 ? p[2] : "?") +
                         " - it arrived unsealed, and a relay does not keep plaintext. Open a chat with" +
                         " them once (that fetches their published key) and the message can be sealed.");
                    return;
                }
                if (p.Length >= 2 && p[1] == "proofneeded")
                {
                    // Not an accusation. The number belongs to a key and this build
                    // cannot say so - which in practice means it IS the owner, on an
                    // install older than the proof. Saying "claimed" here would send
                    // somebody hunting a thief that does not exist.
                    Emit("Relay: #" + (p.Length >= 3 ? p[2] : Number) + " is owned by an identity key and"
                         + " this build does not send the ownership proof. Update this install - it is"
                         + " almost certainly the rightful owner. If it cannot be updated, the relay"
                         + " operator has to release the number (--release-number=" +
                         (p.Length >= 3 ? p[2] : Number) + ") and let it be claimed again.");
                    if (_refusalSaid != "oldbuild")
                    {
                        _refusalSaid = "oldbuild";
                        Action<string> ho = RegistrationRefused;
                        if (ho != null) ho(p.Length >= 3 ? p[2] : Number);
                    }
                    return;
                }
                if (p.Length >= 3 && p[1] == "noroom")
                {
                    // The relay held this join as long as it could. Say so on the
                    // screen: "Conference: joined room X" printed unconditionally used
                    // to be the only feedback, so a failed join looked like a success
                    // and the member sat alone believing the call had started.
                    Emit("Relay: room " + p[2] + " could not be reached even after waiting - "
                         + "the person who opened it is not routable from this relay.");
                    Action<string> hn = RoomUnavailable;
                    if (hn != null) hn(p[2]);
                    return;
                }
                Emit("Relay error: " + line);
                return;
            }
            if (p[0] == "NOTICE" && p.Length >= 4 && p[1] == "claimed-attempts")
            {
                // The relay counted these while we were away; the user should hear it
                // from the app, not from a log nobody opens.
                int tries = 0;
                int.TryParse(p[3], out tries);
                Emit("Relay: " + tries + " other install(s) tried to register #" + p[2]
                     + " while it was offline and were refused.");
                Action<string, int> ha = ClaimAttemptsSeen;
                if (ha != null) ha(p[2], tries);
                return;
            }
            if (p[0] == "UNDELIVERABLE")
            {
                Emit("Relay: " + (p.Length >= 2 ? p[1] : "?") + " is offline");
                Action<string> hq = MessageUndeliverable;
                if (hq != null) hq(p.Length >= 2 ? p[1] : "");
                return;
            }
            if (p[0] == "PEEROFFLINE")
            {
                // Same fact as UNDELIVERABLE, said differently on purpose: nothing
                // was lost, because nothing was a message. A key exchange aimed at
                // somebody who is away is expected noise, and reporting it as a
                // failed delivery would make people think they lost a chat.
                Emit("Relay: " + (p.Length >= 2 ? p[1] : "?") + " is offline - no key exchange attempted (nothing was lost)");
                return;
            }
            if (p[0] == "QUEUED")
            {
                Emit("Relay: " + (p.Length >= 2 ? p[1] : "?") + " is offline - message queued for delivery");
                Action<string> hq2 = MessageQueued;
                if (hq2 != null) hq2(p.Length >= 2 ? p[1] : "");
                return;
            }
        }

        // Send a signaling line to a peer (full MSG line, already shaped).
        public bool SendMessage(string toNumber, string fromNumber, string line)
        {
            return Write("MSG|" + toNumber + "|" + fromNumber + "|" + line);
        }

        // Send one raw UDP-shaped media datagram (type byte + payload) to a peer.
        public bool SendMedia(string toNumber, string fromNumber, byte[] datagram)
        {
            return Write("RM|" + toNumber + "|" + fromNumber + "|" + Convert.ToBase64String(datagram));
        }

        // Send an already-shaped protocol line (conference controls etc.).
        // The call server validates the registered connection, not the shape.
        public bool SendRaw(string line)
        {
            if (string.IsNullOrEmpty(line)) return false;
            return Write(line);
        }

        private bool Write(string line)
        {
            if (!_connected || _w == null) return false;
            try { lock (_writeLock) { lock (_w) _w.WriteLine(line); } return true; }
            catch { return false; }
        }
    }
}
