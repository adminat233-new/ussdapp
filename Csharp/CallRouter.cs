using System;

namespace UssdApp
{
    // =====================================================================
    // Where a call actually goes.
    //
    // Four paths exist, and picking the wrong one is the difference between a
    // free call and a failed one:
    //
    //   AppMesh    - the peer runs this app. Encrypted, no airtime, works with
    //                no SIM and no carrier relationship at all.
    //   Cellular   - the modem dials the real number through the user's own SIM.
    //                Costs their plan, reaches anyone on any phone.
    //   Gateway    - a bridge the *user* supplied (SIP trunk, GSM gateway, a
    //                provider). Never assumed, never on by default.
    //   None       - nothing can carry it. Say why, and say what would fix it.
    //
    // The app's vision decides the precedence: prefer the path that keeps the
    // user's own devices in the middle, and fall back to paid infrastructure
    // only when the peer genuinely cannot be reached that way. A 700 number is
    // never dialled - it does not exist on the phone network, so sending it to
    // the modem would burn airtime on a guaranteed failure.
    // =====================================================================

    public enum EgressPath { AppMesh, Cellular, Gateway, None }

    // What the caller wants, from the Dialer's transport switch.
    public enum TransportPref { Auto, PreferCellular, PreferApp }

    public sealed class EgressRequest
    {
        public string Number = "";
        public TransportPref Pref = TransportPref.Auto;

        // Modem / SIM reality. Fed from the cached SIM snapshot, never a fresh
        // AT query: CPIN/CREG take seconds and a dialling attempt must answer
        // immediately.
        public bool ModemOpen;
        public bool SimPresent;
        public bool SimReady;          // +CPIN: READY
        public bool NetworkRegistered; // +CREG: 1 or 5
        public int Rssi = -999;        // 0-31, -999 unknown

        // Mesh reality.
        public bool RelayReady;        // connected to a relay (federated or not)
        public bool LanPeerKnown;      // discovered on the LAN
        public bool PeerOnMesh;        // directory resolves this number to an app id
        public bool AppNumber;         // 700-XXXXXXX form

        // User-supplied bridging, off unless configured.
        public bool GatewayConfigured;
        public string GatewayName = "";
    }

    public sealed class EgressDecision
    {
        public EgressPath Path = EgressPath.None;
        public string Why = "";
        // What the user could change to make this dial. Empty when a path exists.
        public string Fix = "";
        public string Label
        {
            get
            {
                return Path == EgressPath.AppMesh ? "App call (relay/mesh)"
                    : Path == EgressPath.Cellular ? "Cellular call (SIM)"
                    : Path == EgressPath.Gateway ? "Gateway call"
                    : "No route";
            }
        }
        public override string ToString() { return Path + ": " + Why; }
    }

    public static class CallRouter
    {
        // Signal floor below which a cellular attempt is not worth burning:
        // RSSI 0-31 maps to roughly -115 dBm to -51 dBm. Anything at or under
        // -111 dBm (value 10) will fail or drop straight after connection.
        const int MinUsableRssi = 10;

        public static EgressDecision Decide(EgressRequest r)
        {
            EgressDecision d = new EgressDecision();
            if (r == null) { d.Why = "No request."; return d; }

            bool cellularPossible = CellularUsable(r);
            bool meshPossible = r.RelayReady || r.LanPeerKnown;

            // ── 1. An app number is mesh-only, full stop ──────────────────────
            if (r.AppNumber)
            {
                if (!meshPossible)
                {
                    d.Path = EgressPath.None;
                    d.Why = "A 700 app number lives on the mesh, so the modem cannot dial it " +
                            "and there is no relay or LAN peer to carry it.";
                    d.Fix = "Connect the relay (Settings > Identity & Network) or get both devices " +
                            "on the same network. Cellular service is irrelevant for app numbers.";
                    return d;
                }
                d.Path = EgressPath.AppMesh;
                d.Why = "App Caller-ID routes over the relay or LAN - no SIM, no airtime, any network.";
                return d;
            }

            // ── 2. A real number the peer also answers on the mesh ────────────
            // Free, and encrypted end to end. Chosen whenever the directory says
            // this contact is reachable as an app peer, unless the user explicitly
            // asked for the cellular line (some people want their carrier's
            // recording, or the other side is on a normal phone right now).
            if (r.PeerOnMesh && meshPossible && r.Pref != TransportPref.PreferCellular)
            {
                d.Path = EgressPath.AppMesh;
                d.Why = "That number is reachable on the app mesh, so it is sent there instead of " +
                        "costing you airtime.";
                return d;
            }

            // ── 3. Cellular, when the SIM can actually place it ───────────────
            if (r.Pref == TransportPref.PreferApp && meshPossible && !r.PeerOnMesh)
            {
                d.Path = EgressPath.None;
                d.Why = "App transport is forced, but this number is not known on the mesh.";
                d.Fix = "Switch the transport to Cellular, or have them open the app so their number " +
                        "appears in the directory.";
                return d;
            }
            if (cellularPossible)
            {
                d.Path = EgressPath.Cellular;
                d.Why = "Dialling through the modem on your SIM.";
                return d;
            }

            // ── 4. A bridge the user supplied ─────────────────────────────────
            if (r.GatewayConfigured)
            {
                d.Path = EgressPath.Gateway;
                d.Why = "No usable SIM, so the call goes out through " +
                        (string.IsNullOrEmpty(r.GatewayName) ? "the configured gateway" : r.GatewayName) + ".";
                return d;
            }

            // ── 5. Nothing. Say exactly what is missing ───────────────────────
            d.Path = EgressPath.None;
            d.Why = DescribeCellularBlock(r);
            d.Fix = "Insert a working SIM, or add a bridging provider you already pay for " +
                    "(Settings > Communication), or ask the other side to open the app so you " +
                    "can call them free over the mesh.";
            return d;
        }

        static bool CellularUsable(EgressRequest r)
        {
            if (!r.ModemOpen || !r.SimPresent || !r.SimReady) return false;
            if (r.NetworkRegistered) return r.Rssi < 0 || r.Rssi >= MinUsableRssi;
            // Registered flag unknown/stale: still try, unless the signal is a
            // dead flat -111 dBm or worse and we actually have a reading.
            return r.Rssi == -999 || r.Rssi >= MinUsableRssi;
        }

        static string DescribeCellularBlock(EgressRequest r)
        {
            if (!r.ModemOpen)
                return "No modem is connected, and the peer is not reachable on the app mesh.";
            if (!r.SimPresent)
                return "The modem is up but its SIM slot is empty - nothing can carry a " +
                       "normal phone number without a SIM, and this number is not on the mesh.";
            if (!r.SimReady)
                return "The SIM is present but locked or faulty (AT+CPIN is not READY), so it " +
                       "cannot place a call.";
            if (r.Rssi >= 0 && r.Rssi < MinUsableRssi)
                return "The SIM is ready but there is no usable signal (RSSI " + r.Rssi +
                       "), so a cellular attempt would fail.";
            return "No cellular path is available and the peer is not reachable over the mesh.";
        }

        // A SIM is usable for a call when it is inserted, unlocked and the radio
        // is registered. Kept public so the Dialer can grey out the right button
        // with the same rule it dials with, instead of a second copy drifting.
        public static bool CellularUsable(bool modemOpen, bool simPresent, bool simReady,
                                          bool registered, int rssi)
        {
            return CellularUsable(new EgressRequest
            {
                ModemOpen = modemOpen,
                SimPresent = simPresent,
                SimReady = simReady,
                NetworkRegistered = registered,
                Rssi = rssi
            });
        }
    }

    // =====================================================================
    // The seam for reaching the phone network when the user's own SIM cannot.
    //
    // Deliberately an interface and nothing more. Free calls across the mesh do
    // not need it; what it buys is the option for someone who already pays a
    // VoIP provider to terminate calls through that instead of a carrier. The
    // app must not assume a third party exists, so there is no built-in
    // implementation, no default endpoint, and no network probe.
    // =====================================================================
    public interface IEgressGateway
    {
        string Name { get; }                 // "SIP trunk", "GSM gateway"...
        bool Ready { get; }
        string LastError { get; }
        // Place a call. Returns false when the gateway refused or was unreachable.
        bool Place(string toNumber, bool video);
    }
}
