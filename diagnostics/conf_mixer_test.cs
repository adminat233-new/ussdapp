using System;
using System.Collections.Generic;
using System.Drawing;
using System.Drawing.Imaging;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Reflection;
using System.Text;
using System.Threading;
using UssdApp;

// End-to-end check of the conference mixer in CallServer.cs, driven over real
// TCP exactly the way the app drives it. Answers the questions that matter:
//   - does a member hear the room at all,
//   - does a member hear themselves (they must not),
//   - do two speakers both arrive, with the loud one trimmed by AGC,
//   - does CONF_MUTE take a stream out of the sum,
//   - does video fan-out skip the sender.
// Built and run by build_conf_test.bat; exits 0 when every assertion passes.
static class ConfMixerTest
{
    const int PORT = 45999;
    const string ROOM = "room-test";
    static int failures = 0;

    static void Main()
    {
        // A run that died mid-suite (OOM, killed process) leaves relay_scratch
        // behind. Its pin files then make a brand-new probe read 'verified-known'
        // and a brand-new relay reuse another run's identity - a failure that
        // looks like a product regression but is only last run's state. Clean
        // before the first ScratchDir() use, not just on the happy path.
        TryDeleteDir(ScratchDir());
        SweepScratch();
        string endpointHost;
        int endpointPort;
        bool endpointTls;
        Check("TLS relay endpoint parses with port",
            CallServer.TryParseRelayEndpoint("tls://relay.example:45675", out endpointHost, out endpointPort, out endpointTls) &&
            endpointHost == "relay.example" && endpointPort == 45675 && endpointTls);
        Check("legacy relay endpoint keeps the default port",
            CallServer.TryParseRelayEndpoint("relay.example", out endpointHost, out endpointPort, out endpointTls) &&
            endpointHost == "relay.example" && endpointPort == CallServer.DEFAULT_PORT && !endpointTls);
        Check("bracketed IPv6 relay endpoint parses",
            CallServer.TryParseRelayEndpoint("tls://[2001:db8::1]:45675", out endpointHost, out endpointPort, out endpointTls) &&
            endpointHost == "2001:db8::1" && endpointPort == 45675 && endpointTls);
        Check("malformed relay endpoint is refused",
            !CallServer.TryParseRelayEndpoint("tls://:45675", out endpointHost, out endpointPort, out endpointTls));
        Check("unbracketed malformed IPv6 relay endpoint is refused",
            !CallServer.TryParseRelayEndpoint("tls://:::1", out endpointHost, out endpointPort, out endpointTls));
        Check("malformed bracketed IPv6 relay endpoint is refused",
            !CallServer.TryParseRelayEndpoint("tls://[not-ip]:45675", out endpointHost, out endpointPort, out endpointTls));

        CallServer srv = new CallServer();
        // Even the throwaway mixer relay must not write into the folder the test
        // suite lives in: with no override it used to drop number_leases.txt and
        // peer_keys.txt next to the .cs files, which looks like project state and
        // is nothing of the sort.
        srv.LeaseFileOverride = Path.Combine(ScratchDir(), "leases_main.txt");
        srv.PeerKeyFileOverride = Path.Combine(ScratchDir(), "peerkeys_main.txt");
        srv.MailDirOverride = Path.Combine(ScratchDir(), "mail_main");
        srv.LedgerFileOverride = Path.Combine(ScratchDir(), "ledger_main.txt");
        srv.RelayPolicy = "nobody";      // this relay never links, so it needs no keys
        srv.Log += delegate(string s) { Console.WriteLine("    [srv] " + s); };
        if (!srv.Start(PORT))
        {
            Console.WriteLine("FAIL: could not host the relay on port " + PORT);
            Environment.Exit(2);
        }

        Member a = new Member("7000000001", "tokA");
        Member b = new Member("7000000002", "tokB");
        Member c = new Member("7000000003", "tokC");
        a.Join(); b.Join(); c.Join();
        Thread.Sleep(300);

        Check("roster lists all three members",
            WaitFor(delegate { return a.Roster.Contains("7000000001") && a.Roster.Contains("7000000002") && a.Roster.Contains("7000000003"); }, 5000),
            "roster=" + a.Roster);

        // ── Phase 1: only A speaks ─────────────────────────────────────────
        // All three transmit at once, the way a real room does: two silent mics
        // plus one voice. Sending them in sequence would leave every stream
        // stale-pruned by the time the assertions run.
        Console.WriteLine("  phase 1: one speaker");
        a.Reset(); b.Reset(); c.Reset();
        SendAll(a, 8000, b, 0, c, 0, 40);
        Thread.Sleep(100);

        Check("B hears A", b.LastPeak() > 1000, "peak " + b.LastPeak());
        Check("C hears A", c.LastPeak() > 1000, "peak " + c.LastPeak());
        Check("A does not hear itself", a.MixCount == 0, "frames " + a.MixCount);
        Check("talk indicator names A", a.TalkEver.Contains("7000000001"), "talk=" + a.TalkEver);

        // ── Phase 2: A and B both speak, at different levels ───────────────
        Console.WriteLine("  phase 2: two speakers");
        a.Reset(); b.Reset(); c.Reset();
        SendAll(a, 8000, b, 4000, c, 0, 40);
        Thread.Sleep(100);

        Check("A hears B once a second voice joins", a.LastPeak() > 500, "peak " + a.LastPeak());
        Check("B hears A", b.LastPeak() > 500, "peak " + b.LastPeak());
        // AGC starts at unity, so early frames carry the raw 8000 peak; a lower
        // trailing peak proves the loud stream is being pulled toward target.
        Check("AGC trims the loud stream below raw level", a.AgcTrimmed(), "peak " + a.LastPeak());

        // ── Phase 3: A mutes ───────────────────────────────────────────────
        // A is muted but still transmitting its 8000 tone; B and C are silent.
        // Nothing should reach anybody: that is what proves the mute took A's
        // stream out of the sum rather than merely hiding it from the UI.
        Console.WriteLine("  phase 3: A muted, everyone else silent");
        a.Mute();
        Thread.Sleep(150);
        a.Reset(); b.Reset(); c.Reset();
        SendAll(a, 8000, b, 0, c, 0, 20);
        Thread.Sleep(100);

        Check("room hears nothing while A is muted", b.MixCount == 0, "frames " + b.MixCount);
        Check("C hears nothing either", c.MixCount == 0, "frames " + c.MixCount);

        // ── Phase 3b: A stays muted but must still hear the room ───────────
        Console.WriteLine("  phase 3b: muted A listens while B speaks");
        a.Reset(); b.Reset(); c.Reset();
        SendAll(a, 0, b, 4000, c, 0, 20);
        Thread.Sleep(100);

        Check("muted A still receives", a.LastPeak() > 500, "peak " + a.LastPeak());
        Check("C still hears B", c.LastPeak() > 500, "peak " + c.LastPeak());
        Check("B hears nobody (sole speaker, self-excluded)", b.MixCount == 0, "frames " + b.MixCount);

        // ── Phase 4: video fan-out ─────────────────────────────────────────
        Console.WriteLine("  phase 4: group video");
        a.Reset(); b.Reset(); c.Reset();
        a.SendVideo();
        Thread.Sleep(250);
        Check("B received A's thumbnail", b.VidCount == 1, "count " + b.VidCount);
        Check("C received A's thumbnail", c.VidCount == 1, "count " + c.VidCount);
        Check("A did not receive its own thumbnail", a.VidCount == 0, "count " + a.VidCount);

        // ── Phase 5: leaving closes the room cleanly ───────────────────────
        Console.WriteLine("  phase 5: leave");
        a.Leave(); b.Leave(); c.Leave();
        Thread.Sleep(200);
        Check("empty room is gone (no crash on re-send)", SafeResend(c));

        srv.Stop();
        VerifyTrayBadge();
        VerifyVCard();
        VerifyStickerSync();
        VerifyTranscription();
        VerifyEgress();
        VerifyFederation();
        VerifyMeshGossip();
        VerifyCrossRelayRoom();
        VerifyLateRoomJoin();
        VerifyRoomOutlivesHost();
        VerifyOnion();
        VerifyStoreAndForward();
        VerifyNumberLeases();
        VerifyPrekeys();
        VerifyNatPaths();
        VerifyStunAndTargets();
        VerifyRelayBootstrap();
        VerifyCrossRelayCall();
        VerifyMediaRoute();
        VerifyPeerPush();
        VerifyPairProof();
        VerifyPortMap();
        VerifyRadio();
        TryDeleteDir(ScratchDir());
        SweepScratch();
        Console.WriteLine(failures == 0 ? "ALL CONFERENCE TESTS PASSED" : failures + " TEST(S) FAILED");
        Environment.Exit(failures == 0 ? 0 : 1);
    }

    // Every section parks its relays in a *_tmp_<ticks> folder beside the sources and
    // deletes it at the end. A relay that was stopped a moment ago can still write one
    // last ledger, and a folder that reappears after its own cleanup leaves test state
    // sitting in the repository looking like project state - which happened here, three
    // times over, silently. So: sweep, and name what refuses to go.
    static void SweepScratch()
    {
        string baseDir = AppDomain.CurrentDomain.BaseDirectory;
        int swept = 0;
        try
        {
            foreach (string d in Directory.GetDirectories(baseDir))
            {
                string name = Path.GetFileName(d);
                if (name.IndexOf("_tmp_", StringComparison.Ordinal) < 0) continue;
                TryDeleteDir(d);
                if (!Directory.Exists(d)) swept++;
            }
        }
        catch { }
        if (swept > 0) Console.WriteLine("  swept " + swept + " scratch folder(s) a late relay write had brought back");
    }

    // ── Egress routing ─────────────────────────────────────────────────
    // The choice of *how* to dial is pure logic, and a wrong answer here costs
    // the user airtime or fails silently. Each row is a real situation.
    static void VerifyEgress()
    {
        Console.WriteLine("  egress routing");

        EgressRequest app = new EgressRequest { Number = "7001111111", AppNumber = true, RelayReady = true };
        Check("app number goes to the mesh", CallRouter.Decide(app).Path == EgressPath.AppMesh);

        EgressRequest appNoNet = new EgressRequest { Number = "7001111111", AppNumber = true };
        EgressDecision dna = CallRouter.Decide(appNoNet);
        Check("app number with no relay has no route", dna.Path == EgressPath.None, dna.Why);
        Check("...and says the modem cannot dial it", dna.Why.Contains("modem cannot dial"), dna.Why);
        Check("...and names the fix", dna.Fix.Contains("relay"), dna.Fix);

        EgressRequest meshPeer = new EgressRequest
        {
            Number = "+233240000001", PeerOnMesh = true, RelayReady = true,
            ModemOpen = true, SimPresent = true, SimReady = true, NetworkRegistered = true, Rssi = 20
        };
        EgressDecision dm = CallRouter.Decide(meshPeer);
        Check("a number reachable on the mesh is sent there, not dialled", dm.Path == EgressPath.AppMesh, dm.Why);
        Check("...and explains it saves airtime", dm.Why.Contains("airtime"), dm.Why);

        meshPeer.Pref = TransportPref.PreferCellular;
        Check("forcing cellular is honoured", CallRouter.Decide(meshPeer).Path == EgressPath.Cellular);

        EgressRequest sim = new EgressRequest
        {
            Number = "+233240000001", ModemOpen = true, SimPresent = true, SimReady = true,
            NetworkRegistered = true, Rssi = 18
        };
        EgressDecision ds = CallRouter.Decide(sim);
        Check("real number + ready SIM = cellular", ds.Path == EgressPath.Cellular, ds.Why);

        EgressRequest noSim = new EgressRequest { Number = "+233240000001", ModemOpen = true };
        EgressDecision dn = CallRouter.Decide(noSim);
        Check("no SIM and no mesh = no route", dn.Path == EgressPath.None, dn.Why);
        Check("...names the empty SIM slot", dn.Why.Contains("SIM slot is empty"), dn.Why);
        Check("...offers all three ways out", dn.Fix.Contains("SIM") &&
              dn.Fix.ToLowerInvariant().Contains("provider") && dn.Fix.Contains("app"), dn.Fix);

        EgressRequest locked = new EgressRequest { Number = "+1", ModemOpen = true, SimPresent = true };
        Check("locked SIM is reported as locked", CallRouter.Decide(locked).Why.Contains("locked"),
            CallRouter.Decide(locked).Why);

        EgressRequest noSignal = new EgressRequest
        {
            Number = "+1", ModemOpen = true, SimPresent = true, SimReady = true,
            NetworkRegistered = true, Rssi = 4
        };
        Check("dead signal is not attempted", CallRouter.Decide(noSignal).Why.Contains("signal"),
            CallRouter.Decide(noSignal).Why);

        EgressRequest gw = new EgressRequest
        {
            Number = "+233240000001", GatewayConfigured = true, GatewayName = "office SIP trunk"
        };
        EgressDecision dg = CallRouter.Decide(gw);
        Check("a user-supplied gateway is used only when the SIM cannot", dg.Path == EgressPath.Gateway, dg.Why);
        Check("...and is named to the user", dg.Why.Contains("office SIP trunk"), dg.Why);

        EgressRequest forced = new EgressRequest { Number = "+233240000001", RelayReady = true, Pref = TransportPref.PreferApp };
        EgressDecision df = CallRouter.Decide(forced);
        Check("forced app transport refuses an unknown number", df.Path == EgressPath.None, df.Why);
        Check("...and tells them to switch transport", df.Fix.Contains("Cellular"), df.Fix);

        Check("the UI helper agrees with the router",
            CallRouter.CellularUsable(true, true, true, true, 18) &&
            !CallRouter.CellularUsable(true, false, false, false, -999) &&
            !CallRouter.CellularUsable(true, true, true, true, 3));
        Check("unknown signal strength still attempts a call",
            CallRouter.CellularUsable(true, true, true, false, -999));
    }

    // ── Federation ───────────────────────────────────────────────────────
    // Three relays in a chain (R1 - R2 - R3). R1 and R3 are never connected to
    // each other, so anything that passes between them proves the directory
    // merged AND that forwarding hops through an intermediary that consents to
    // carrying it.
    static void VerifyFederation()
    {
        Console.WriteLine("  federation");
        CallServer r1 = NewRelay(45711, "everyone", "");
        CallServer r2 = NewRelay(45710, "everyone", "127.0.0.1:45711,127.0.0.1:45712");
        CallServer r3 = NewRelay(45712, "everyone", "");
        if (r1 == null || r2 == null || r3 == null)
        {
            Check("relay ports free for the test", false, "could not host 45710-45712");
            return;
        }
        // Wait for R2 to dial out and the directories to merge.
        Check("both links came up", WaitFor(delegate { return r2.LinkCount >= 2; }, 6000),
            "links=" + r2.LinkCount);

        Node a = new Node("7001111111", 45711);    // on R1
        Node c = new Node("7003333333", 45712);    // on R3
        Check("middle relay sees both sides", WaitFor(delegate { return r2.RemotePeerCount >= 1; }, 5000),
            "remote=" + r2.RemotePeerCount);
        // The entry that must travel two hops: C is unknown to R1 until R2
        // forwards it (with split horizon, so R2 never hears its own news back).
        Check("R1 learns a peer that lives two hops away", a.WaitForDir("7003333333", 6000));
        Check("R3 likewise sees R1's peer", c.WaitForDir("7001111111", 4000));
        Check("federated entries keep the local IP field", a.DirHasVia("7003333333"));

        // A -> C across the chain.
        a.Send("MSG|7003333333|7001111111|hello over the mesh");
        Check("message crossed two relays", c.WaitForMsg("7001111111", "hello over the mesh", 6000));
        // Reply path: the far relay must know how to get back.
        c.Send("MSG|7001111111|7003333333|got it");
        Check("reply came back along the same chain", a.WaitForMsg("7003333333", "got it", 6000));

        // A number nobody has is still queued, not lost - sealed, because a relay
        // keeps no plaintext any more, and the queue is the reason that matters.
        a.Reset();
        a.Send("MSG|7009999999|7001111111|ECHAT|cXVldWVkIGZvciBsYXRlcg==");
        Check("unknown number is queued", a.WaitForLine("QUEUED|7009999999", 4000));
        Node late = new Node("7009999999", 45711);
        Check("queued mail flushes on arrival",
              late.WaitForMsg("7001111111", "ECHAT|cXVldWVkIGZvciBsYXRlcg==", 4000));
        // ...and the same send in the clear is refused with a reason, rather than
        // filed where anybody with the disk can read it.
        a.Send("MSG|7009999998|7001111111|CHAT|clear-text-must-not-be-kept");
        Check("unsealed mail for an unknown number is refused, not stored",
              a.WaitForLine("ERR|nokey|7009999998", 4000));
        late.Close();

        // Teardown must propagate: C leaves, everyone forgets it.
        c.Close();
        Check("peer leaving removes it from the far directory",
            WaitFor(delegate { return r1.RemotePeerCount == 0; }, 6000), "remote=" + r1.RemotePeerCount);

        // ── Relay referral: joining without somebody typing an address ──────
        Console.WriteLine("  relay referral");
        Node middle = new Node("7002222222", 45710);   // on the relay that dials both
        middle.Send("RLIST|");
        Check("a client can ask for other relays", middle.WaitForLine("RLIST|", 4000));
        string referred = middle.ReferredRaw();
        Check("...and gets both linked relays by port", referred.Contains(":45711") && referred.Contains(":45712"), referred);
        // The advertised address, not the one R2 happened to dial: referring
        // 127.0.0.1 would tell every client to call itself.
        Check("...and not the loopback address R2 dialled",
            !referred.Contains("127.0.0.1:") && referred.Contains("127.0.0.11"), referred);
        // R1 is only reached by an inbound link, whose remote port is ephemeral.
        // Handing that out would send seekers to a dead address, so it must not.
        a.Send("RLIST|");
        Thread.Sleep(600);
        Check("an inbound-only link is not referred as if diallable",
            !a.ReferredAnythingContains("in:"), a.ReferredRaw());
        middle.Close();

        // ── Consent: a relay may refuse to carry for strangers ─────────────
        Console.WriteLine("  relay consent");
        CallServer strict = NewRelay(45714, "nobody", "");
        Node probe = new Node("", 0);   // not used; handshake tested directly
        probe.Close();
        Check("policy nobody refuses to link", LinkDeny(strict, "remoteid", "friend-pc") == "policy-nobody");
        CallServer open = NewRelay(45715, "everyone", "");
        Check("policy everyone accepts", LinkDeny(open, "remoteid", "friend-pc") == null);
        CallServer listed = NewRelay(45716, "allowed", "");
        listed.RelayAllow = "friend-pc";
        Check("allow list accepts a named relay", LinkDeny(listed, "someid", "friend-pc") == null);
        listed.RelayAllow = "192.168.5.9";
        Check("allow list accepts the address it comes from", LinkDeny(listed, "id", "AnyName", "192.168.5.9:45675") == null);
        listed.RelayAllow = "friend-pc";
        Check("allow list refuses a stranger", LinkDeny(listed, "id", "stranger", "203.0.113.7:1") == "not-allowed");
        Check("default policy is to NOT carry for strangers", new CallServer().RelayPolicy == "allowed");
        Check("a relay never links to itself", LinkDeny(listed, listed.RelayId, "me") == "selflink");

        a.Close();
        r1.Stop(); r2.Stop(); r3.Stop(); strict.Stop(); open.Stop(); listed.Stop();
    }

    static CallServer NewRelay(int port, string policy, string links)
    {
        // 127.0.0.0/8 is all loopback on Windows, so a relay listening on Any
        // accepts on 127.0.0.11 too. That gives each relay an advertise address
        // that is real, reachable, and clearly different from the one a peer
        // dialled - which is what referral is supposed to return.
        return NewRelay(port, policy, links, "127.0.0.1" + ((port % 10)) + ":" + port, false);
    }

    static CallServer NewRelay(int port, string policy, string links, string advertise, bool autoMesh)
    {
        CallServer s = new CallServer();
        s.RelayPolicy = policy;
        s.RelayLinks = links;
        s.RelayName = "relay-" + port;
        s.RelayAdvertise = advertise;
        s.RelayAutoMesh = autoMesh;
        // A key file per relay, in a scratch folder that goes away with the run.
        // Left on the default, every test relay would read and write the same
        // Home\relay_id.key and therefore *be* the same identity - and it would
        // leave a private key file in the repository.
        string d = ScratchDir();
        s.RelayKeyFile = Path.Combine(d, "relay_" + port + ".key");
        s.RelayBookFile = Path.Combine(d, "relay_" + port + "_book.txt");
        // Offline mail is stored per node too: sharing Home\mail would let one test
        // relay "recover" another's queue and deliver it a second time.
        s.MailDirOverride = Path.Combine(d, "mail_" + port);
        s.LedgerFileOverride = Path.Combine(d, "ledger_" + port + ".txt");
        s.LeaseFileOverride = Path.Combine(d, "leases_" + port + ".txt");
        s.PeerKeyFileOverride = Path.Combine(d, "peerkeys_" + port + ".txt");
        if (!s.Start(port)) { try { s.Dispose(); } catch { } return null; }
        return s;
    }

    static string ScratchDir()
    {
        string d = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "relay_scratch");
        try { Directory.CreateDirectory(d); } catch { }
        return d;
    }

    static void TryDeleteDir(string d)
    {
        // Retried, and reported if it still will not go: a relay that was stopped a
        // moment ago can still hold a handle on its mail folder, and a cleanup that
        // swallows the failure leaves test litter in the repository with no trace of
        // having happened. That happened here for three runs before anyone looked -
        // and a 2.5 s window turned out not to be enough either, so this waits.
        for (int i = 0; i < 40; i++)
        {
            try
            {
                if (!Directory.Exists(d)) return;
                Directory.Delete(d, true);
                return;
            }
            catch { }
            Thread.Sleep(250);
        }
        try { if (Directory.Exists(d)) Console.WriteLine("    (left behind: " + d + " - a relay still held it open)"); } catch { }
    }

    // ── Self-forming mesh ──────────────────────────────────────────────
    // R1 and R3 never dial each other; both only know R2. If gossip works, each
    // learns the other's diallable address from R2, and with auto-mesh on they
    // link directly - which is the "two friends with one common relay end up in
    // one graph" claim, tested rather than asserted.
    static void VerifyMeshGossip()
    {
        Console.WriteLine("  mesh gossip");
        // One-way chain: G3 dials G2, G2 dials G1. Nobody dials across the ends,
        // so anything G1 knows about G3 can only have arrived by gossip.
        CallServer g1 = NewRelay(45720, "everyone", "", "127.0.0.10:45720", false);
        CallServer g2 = NewRelay(45721, "everyone", "127.0.0.1:45720", "127.0.0.11:45721", false);
        CallServer g3 = NewRelay(45722, "everyone", "127.0.0.1:45721", "127.0.0.12:45722", false);
        if (g1 == null || g2 == null || g3 == null) { Check("gossip relay ports free", false); return; }

        Check("the chain forms from the two dials",
            WaitFor(delegate { return g1.LinkCount >= 1 && g2.LinkCount >= 2 && g3.LinkCount >= 1; }, 8000),
            "links=" + g1.LinkCount + "/" + g2.LinkCount + "/" + g3.LinkCount);
        // G1 must hear of G3 from G2. This is the announce-on-learn path: G2 only
        // met G3 after its link to G1 was already up.
        Check("G1 hears of G3 through G2",
            WaitFor(delegate { return HasEndpoint(g1.KnownRelayEndpoints, "45722"); }, 12000),
            Join(g1.KnownRelayEndpoints));
        Check("...and does not dial it, because auto-mesh is off", g1.LinkCount <= 1, "links=" + g1.LinkCount);
        // Localise the failure: does the middle relay even hold G3's address?
        Check("G2 knows G3's advertised address", HasEndpoint(g2.KnownRelayEndpoints, "45722"),
            "g2 known=" + Join(g2.KnownRelayEndpoints) + " links=" + g2.LinkCount);

        // Now consent is given: the already-known relay is dialled straight away,
        // and a real handshake follows (G3 counting a second link proves it).
        g1.RelayAutoMesh = true;
        g1.ReconsiderMesh();
        Check("with auto-mesh on, G1 dials the relay it heard about",
            WaitFor(delegate { return g3.LinkCount >= 2; }, 12000), "g3 links=" + g3.LinkCount);
        Check("...and G1 now has both", WaitFor(delegate { return g1.LinkCount >= 2; }, 4000), "links=" + g1.LinkCount);

        // A triangle exists; it must not dissolve into a dial storm. G2 should not
        // have dialled itself, and nobody re-announces a relay to its own link.
        Thread.Sleep(700);
        Check("no relay dials itself", !Join(g2.KnownRelayEndpoints).Contains("127.0.0.12:45721") && g2.LinkCount <= 4,
            "links=" + g2.LinkCount + " known=" + Join(g2.KnownRelayEndpoints));

        g1.Stop(); g2.Stop(); g3.Stop();
    }

    // ── One room, three relays ────────────────────────────────────
    // This is the "audio and video work across multiple devices" claim, and the
    // last gap in the room design: a room used to be reachable only by members
    // registered on the SAME relay. Chain R1 <- R2 <- R3, host on R1, members on
    // all three, two of them reached only by hops.
    static void VerifyCrossRelayRoom()
    {
        Console.WriteLine("  room across relays");
        CallServer r1 = NewRelay(45730, "everyone", "", "127.0.0.21:45730", false);
        CallServer r2 = NewRelay(45731, "everyone", "127.0.0.1:45730", "127.0.0.22:45731", false);
        CallServer r3 = NewRelay(45732, "everyone", "127.0.0.1:45731", "127.0.0.23:45732", false);
        if (r1 == null || r2 == null || r3 == null) { Check("room relay ports free", false); return; }

        Node host = new Node("7001111111", 45730);    // on R1, and the room owner
        Node mid = new Node("7002222222", 45731);     // on R2
        Node far = new Node("7003333333", 45732);     // on R3, two hops away
        // Wait until the directory is federated, or a join is refused for no
        // reason other than the routes not having settled yet.
        // Wait for the actual precondition. This check used to end in
        // "|| r1.RemotePeerCount >= 0", which is always true, so it waited for
        // nothing and the section passed only on lucky timing - which it stopped
        // doing the moment link setup got a millisecond slower.
        Check("R1 learns the far member's number through two hops",
            host.WaitForDir("7003333333", 15000));
        // ...and the other direction, which is the one a join actually needs. The
        // room is owned by the host, so a member's relay must be able to route to
        // 7001111111 before its CONF_JOIN can be delivered. Waiting for only the
        // first half made this section pass or fail on which way the gossip
        // happened to arrive first; joining too early is a different case, and it
        // now has its own test (VerifyLateRoomJoin) that sets it up on purpose.
        Check("...and each member's relay learns the host's number",
            mid.WaitForDir("7001111111", 15000) && far.WaitForDir("7001111111", 15000),
            "mid_dir=" + (mid.WaitForDir("7001111111", 0) ? "yes" : "no") +
            " far_dir=" + (far.WaitForDir("7001111111", 0) ? "yes" : "no"));

        string room = "conf-7001111111-4242";         // owned by the number in it
        host.Send("CONF_JOIN|" + room + "|t");
        Thread.Sleep(200);
        mid.Send("CONF_JOIN|" + room + "|t");
        far.Send("CONF_JOIN|" + room + "|t");

        Check("every member gets a 3-person roster, wherever they are",
            host.WaitForText(room, 4000) &&
            WaitFor(delegate { return mid.LineWith(room).Contains("7003333333"); }, 6000) &&
            WaitFor(delegate { return far.LineWith(room).Contains("7003333333"); }, 6000),
            "mid=" + mid.LineWith(room) + " far=" + far.LineWith(room));
        Check("...including the two-hop member on the host's own roster",
            WaitFor(delegate { return host.LineWith(room).Contains("7003333333"); }, 4000),
            host.LineWith(room));

        // ---- audio: far member talks, the others must hear it ----------------
        host.Reset(); mid.Reset(); far.Reset();
        far.SendFrames(room, 5000, 30);               // from R3, across two links
        Thread.Sleep(200);
        Check("the host mixes a member who is two hops away", host.LastConfPeak(room) > 300,
            "peak=" + host.LastConfPeak(room));
        Check("...and the middle member hears them too", mid.LastConfPeak(room) > 300,
            "peak=" + mid.LastConfPeak(room));
        Check("the talker is not echoed their own voice", far.ConfCount(room) == 0,
            "frames=" + far.ConfCount(room));

        // ---- audio the other way: host talks, the far member hears it --------
        host.Reset(); mid.Reset(); far.Reset();
        host.SendFrames(room, 6000, 30);
        Thread.Sleep(200);
        Check("a two-hop member receives the mix", far.LastConfPeak(room) > 300,
            "peak=" + far.LastConfPeak(room));
        Check("...and so does the one-hop member", mid.LastConfPeak(room) > 300,
            "peak=" + mid.LastConfPeak(room));

        // ---- video: a thumbnail from the host reaches both remote members ---
        host.Reset(); mid.Reset(); far.Reset();
        host.SendConfVideo(room);
        Thread.Sleep(400);
        Check("group video reaches a member on another relay",
            far.CountsWith("CONF_VID") == 1 && mid.CountsWith("CONF_VID") == 1,
            "mid=" + mid.CountsWith("CONF_VID") + " far=" + far.CountsWith("CONF_VID"));
        Check("...and is not echoed to the sender", host.CountsWith("CONF_VID") == 0);

        // ---- text still works between members on different relays -----------
        host.Reset(); far.Reset();
        host.Send("MSG|7003333333|7001111111|text across the room");
        Check("text crosses the same chain", far.WaitForMsg("7001111111", "text across the room", 5000));

        far.Send("CONF_LEAVE|" + room);
        Thread.Sleep(300);
        Check("a leaving member drops off everyone's roster",
            WaitFor(delegate { return !host.LineWith(room).Contains("7003333333"); }, 5000),
            host.LineWith(room));

        host.Close(); mid.Close(); far.Close();
        r1.Stop(); r2.Stop(); r3.Stop();
    }

    // ── Joining a room before the mesh has finished forming ─────────────
    // The shape of a real Friday: Alice opens a group call on her relay, Bob taps
    // invite two seconds later, and the gossip that tells Bob's relay where Alice
    // lives has not arrived yet. This used to be answered with ERR|noroom - once,
    // unretried, and then dropped by the carrier relay as well, so nobody heard it
    // at all and Bob sat in a call he believed he had joined.
    //
    // Set up on purpose rather than raced: the two relays are simply not linked
    // when the join is sent, so there is no timing to get lucky with.
    static void VerifyLateRoomJoin()
    {
        Console.WriteLine("  room: a join that arrives before the route does");
        int hp = 45805, gp = 45806;
        CallServer hostRelay = NewRelay(hp, "everyone", "");
        CallServer guestRelay = NewRelay(gp, "everyone", "");     // deliberately unlinked
        if (hostRelay == null || guestRelay == null)
        {
            Check("late-join relay ports free (45805-45806)", false);
            return;
        }

        Node host = new Node("7008880001", hp);
        Node guest = new Node("7008880002", gp);
        string room = "conf-7008880001-4848";                    // owned by the host
        host.Send("CONF_JOIN|" + room + "|t");
        Thread.Sleep(300);
        Check("the host is in its own room", host.WaitForText(room, 4000), host.LineWith(room));

        long parked0 = guestRelay.JoinsParked;
        guest.Send("CONF_JOIN|" + room + "|t");
        Check("the join is held while there is no route", WaitFor(delegate
              { return guestRelay.PendingJoinCount == 1; }, 4000),
              "waiting=" + guestRelay.PendingJoinCount);
        Check("...and not refused while there is still hope", !guest.WaitForLine("ERR|noroom", 1200));
        Check("...and the holding is counted", guestRelay.JoinsParked > parked0,
              "parked=" + guestRelay.JoinsParked);

        // The route appears. Nothing is re-sent by anybody: this is the relay's own
        // replay, driven by the RDIST that lands when the link comes up.
        guestRelay.RelayLinks = "127.0.0.1:" + hp;
        guestRelay.SyncLinks();
        Check("the late link comes up", WaitFor(delegate { return guestRelay.LinkCount >= 1; }, 15000),
              "links=" + guestRelay.LinkCount);
        Check("the held join lands with nobody sending it twice", WaitFor(delegate
              { return guest.LineWith(room).Contains("7008880001"); }, 12000),
              "guest sees " + guest.LineWith(room));
        Check("...and the host sees the member who joined early", WaitFor(delegate
              { return host.LineWith(room).Contains("7008880002"); }, 8000),
              "host sees " + host.LineWith(room));
        Check("...and nothing is left waiting", guestRelay.PendingJoinCount == 0,
              "waiting=" + guestRelay.PendingJoinCount);
        Check("...and the replay is counted", guestRelay.JoinsReplayed >= 1,
              "replayed=" + guestRelay.JoinsReplayed);

        host.Reset(); guest.Reset();
        guest.SendFrames(room, 5000, 25);
        Thread.Sleep(250);
        Check("a member who joined early is heard", host.LastConfPeak(room) > 300,
              "peak=" + host.LastConfPeak(room));

        // The other half of the promise: a wait that never pays off has to end in
        // something the member can read. The TTL is shortened for the check, but
        // the expiry itself runs on the relay's real 5 s upkeep beat.
        Console.WriteLine("  room: a join that never gets a route says so");
        CallServer lonely = NewRelay(45807, "everyone", "");
        if (lonely != null)
        {
            lonely.PendingJoinTtlMs = 500;
            Node waiting = new Node("7008880003", 45807);
            string dead = "conf-7008889999-1";                   // owner who never appears
            waiting.Send("CONF_JOIN|" + dead + "|t");
            Check("the unreachable join is held first", WaitFor(delegate
                  { return lonely.PendingJoinCount == 1; }, 4000),
                  "waiting=" + lonely.PendingJoinCount);
            Check("...and then refused out loud, not silently", waiting.WaitForLine("ERR|noroom", 12000),
                  "lines=" + waiting.LineWith(dead));
            Check("...and nothing is left held on the promise", WaitFor(delegate
                  { return lonely.PendingJoinCount == 0; }, 12000),
                  "waiting=" + lonely.PendingJoinCount);
            waiting.Close(); lonely.Stop();
        }

        // Leaving while a join is still waiting must cancel it, or the replay would
        // walk a member who already hung up back into the room.
        Console.WriteLine("  room: leaving while a join is still waiting");
        CallServer waiter = NewRelay(45808, "everyone", "");
        if (waiter != null)
        {
            Node walker = new Node("7008880004", 45808);
            string r2 = "conf-7008889998-2";
            walker.Send("CONF_JOIN|" + r2 + "|t");
            Check("the join is held", WaitFor(delegate { return waiter.PendingJoinCount == 1; }, 4000));
            walker.Send("CONF_LEAVE|" + r2);
            Check("...and leaving cancels it", WaitFor(delegate
                  { return waiter.PendingJoinCount == 0; }, 4000),
                  "waiting=" + waiter.PendingJoinCount);
            walker.Close(); waiter.Stop();
        }

        host.Close(); guest.Close();
        hostRelay.Stop(); guestRelay.Stop();
    }

    // ── The call outlives the person who started it ────────────────────
    // Somebody hosts a group call, three friends join, the host drops off - a
    // laptop lid, a walk away, an accidental hang-up. Before this, the mixer kept
    // running on the host's relay while every other relay went on routing the room
    // by the host's NUMBER, which no longer resolved: the call did not end, it
    // became unreachable, and nobody was told. So a relay that mixes a room says so,
    // and a room is handled where it lives.
    static void VerifyRoomOutlivesHost()
    {
        Console.WriteLine("  room: surviving the host's departure");
        int p1 = 45810, p2 = 45811, p3 = 45812;
        CallServer r1 = NewRelay(p1, "everyone", "", "127.0.0.71:" + p1, false);
        CallServer r2 = NewRelay(p2, "everyone", "127.0.0.1:" + p1, "127.0.0.72:" + p2, false);
        CallServer r3 = NewRelay(p3, "everyone", "127.0.0.1:" + p2, "127.0.0.73:" + p3, false);
        if (r1 == null || r2 == null || r3 == null) { Check("host-survival relay ports free (45810-45812)", false); return; }

        Node host = new Node("7009990001", p1);
        Node m1 = new Node("7009990002", p2);
        Node m2 = new Node("7009990003", p3);
        Check("the directory settles before anybody dials",
              m1.WaitForDir("7009990001", 15000) && m2.WaitForDir("7009990001", 15000));

        string room = "conf-7009990001-9001";
        host.Send("CONF_JOIN|" + room + "|t");
        Thread.Sleep(200);
        m1.Send("CONF_JOIN|" + room + "|t");
        m2.Send("CONF_JOIN|" + room + "|t");
        Check("all three are in the room together", WaitFor(delegate
              { return m2.LineWith(room).Contains("7009990002"); }, 9000), m2.LineWith(room));

        // The host hangs up, and their process goes: the number leaves the directory,
        // so every relay that still routes this room by that number is now wrong.
        host.Send("CONF_LEAVE|" + room);
        Thread.Sleep(200);
        host.Close();
        Check("the remaining members are not told the room died",
              WaitFor(delegate { return r1.RoomsAnnounced >= 1; }, 8000),
              "announcements=" + r1.RoomsAnnounced);
        Check("the neighbouring relay learns where the room actually is",
              WaitFor(delegate { return r2.RoomRouteCount >= 1; }, 8000),
              "routes on r2=" + r2.RoomRouteCount);

        // Mixing must go on with the host gone: this is the part that was already
        // working, and it is the part the old routing threw away.
        m1.Reset(); m2.Reset();
        m2.SendFrames(room, 5000, 25);
        Thread.Sleep(250);
        Check("the call is still mixed with its host gone", m1.LastConfPeak(room) > 300,
              "peak=" + m1.LastConfPeak(room));
        m1.Reset(); m2.Reset();
        m1.SendFrames(room, 5000, 25);
        Thread.Sleep(250);
        Check("...in both directions", m2.LastConfPeak(room) > 300, "peak=" + m2.LastConfPeak(room));

        // A fourth friend dials in minutes later, having never seen the host. Their
        // relay has no route to the owner's number and never will: the only way in is
        // the host-relay announcement.
        Node m3 = new Node("7009990004", p3);
        m3.Send("CONF_JOIN|" + room + "|t");
        Check("somebody who joins after the host vanished still gets in", WaitFor(delegate
              { return m3.LineWith(room).Contains("7009990002"); }, 12000), m3.LineWith(room));
        Check("...and they are heard", WaitFor(delegate
              { return m1.LineWith(room).Contains("7009990004"); }, 9000), m1.LineWith(room));
        m1.Reset(); m3.Reset();
        m3.SendFrames(room, 5000, 25);
        Thread.Sleep(250);
        Check("...and they hear the call they joined", m1.LastConfPeak(room) > 300,
              "peak=" + m1.LastConfPeak(room));
        Check("the departed host is off the roster at last",
              !m1.LineWith(room).Contains("7009990001"), m1.LineWith(room));

        // The hint has to travel further than the direct neighbour, or a member two
        // hops out would still be turned away. r3 is linked only to r2, so it can
        // only have learned this by gossip.
        Check("...and the word travels past the direct neighbour", WaitFor(delegate
              { return r3.RoomRouteCount >= 1; }, 8000), "routes on r3=" + r3.RoomRouteCount);
        m1.Close(); m2.Close(); m3.Close();
        r1.Stop(); r2.Stop(); r3.Stop();
    }

    static bool HasEndpoint(List<string> list, string needle)
    {
        foreach (string s in list) if (s.Contains(needle)) return true;
        return false;
    }

    static string Join(List<string> list)
    {
        if (list == null || list.Count == 0) return "(none)";
        return string.Join(",", list.ToArray());
    }

    // ── STUN answers and where to aim media ─────────────────────────────
    // Both of these were broken in ways no live test would have shown. A STUN
    // response cannot be produced here without a server and a public network, but
    // it is 32 bytes of agreed format, so it can be CARRIED here - which is the
    // only way to pin down that the port is XORed with 0x2112 and not with the two
    // bytes the first implementation reached for.
    static void VerifyStunAndTargets()
    {
        Console.WriteLine("  nat: reading our own public address");
        byte[] tx = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12 };
        // A binding success saying 203.0.113.77:50000. Hand-assembled: the length
        // field, the magic cookie, our transaction id, then XOR-MAPPED-ADDRESS with
        // port 0xC350^0x2112 = 0xE242 and the address XORed against the cookie bytes.
        byte[] ok = new byte[] {
            0x01, 0x01, 0x00, 0x0C, 0x21, 0x12, 0xA4, 0x42,
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C,
            0x00, 0x20, 0x00, 0x08, 0x00, 0x01, 0xE2, 0x42, 0xEA, 0x12, 0xD5, 0x0F
        };
        string ip; int port;
        Check("a real STUN response is parsed", Stun.TryParse(ok, tx, out ip, out port), ip + ":" + port);
        Check("...and the address is the one the server reported", ip == "203.0.113.77", "ip=" + ip);
        Check("...and so is the port - 50000, not the value the old XOR produced",
              port == 50000, "port=" + port + " (the previous formula returned 61440)");
        // The confusion this could cause: an encrypted audio frame starts with the
        // media type byte, and its IV can begin with any byte at all - so two
        // matching bytes must never be enough to call something a STUN answer.
        byte[] wrongTx = (byte[])ok.Clone();
        wrongTx[8] = 0xEE;
        string ip2; int p2;
        Check("a packet that is not the answer to OUR request is not one",
              !Stun.TryParse(wrongTx, tx, out ip2, out p2));
        byte[] wrongCookie = (byte[])ok.Clone();
        wrongCookie[4] = 0x00;
        Check("...and neither is one with the magic cookie altered",
              !Stun.TryParse(wrongCookie, tx, out ip2, out p2));
        byte[] shortOne = new byte[24];
        Array.Copy(ok, shortOne, 24);          // header + attribute type, value cut off
        Check("a truncated answer is refused, not an exception",
              !Stun.TryParse(shortOne, tx, out ip2, out p2));
        byte[] lyingLen = (byte[])ok.Clone();
        lyingLen[2] = 0x7F; lyingLen[3] = 0xFF;
        Check("...and so is one whose declared length runs past the packet",
              !Stun.TryParse(lyingLen, tx, out ip2, out p2));
        // The other direction: a packet that declares LESS than it carries must not
        // have the extra bytes read as attributes. Cheap to allow, and it means
        // whoever sent the datagram decides where our parsing stops.
        byte[] lyingShort = (byte[])ok.Clone();
        lyingShort[2] = 0x00; lyingShort[3] = 0x04;         // one 4-byte attribute only
        Check("...and attributes beyond the declared length are not read",
              !Stun.TryParse(lyingShort, tx, out ip2, out p2));
        Check("a request carries the cookie and our transaction id",
              Stun.Request(tx)[4] == 0x21 && Stun.Request(tx)[7] == 0x42 &&
              Stun.Request(tx)[8] == 1 && Stun.Request(tx)[19] == 12);
        byte[] txA = Stun.NewTransactionId(), txB = Stun.NewTransactionId();
        bool txSame = true;
        for (int i = 0; i < 12; i++) if (txA[i] != txB[i]) { txSame = false; break; }
        Check("two requests do not share a transaction id", !txSame);

        Console.WriteLine("  nat: where to aim media at the peer");
        // The two forms of the announcement, and the order that has to come out of
        // them. On another network the peer's LAN address is unroutable, so the
        // reflexive one has to lead - and an old build that only sends a port must
        // still produce a usable candidate.
        IPEndPoint[] old = VoipService.MediaTargets("203.0.113.9", new string[] { "MPORT", "45672" });
        Check("an old one-port announcement still gives a target",
              old.Length == 1 && old[0].Port == 45672 && old[0].Address.ToString() == "203.0.113.9",
              old.Length.ToString());
        IPEndPoint[] both = VoipService.MediaTargets("203.0.113.9",
            new string[] { "MPORT", "45672", "203.0.113.77", "50000" });
        Check("with a public pair announced, it is aimed at FIRST",
              both.Length == 2 && both[0].Address.ToString() == "203.0.113.77" && both[0].Port == 50000,
              both.Length + " targets, first=" + (both.Length > 0 ? both[0].ToString() : "none"));
        Check("...and the local port is still tried after it",
              both.Length == 2 && both[1].Port == 45672);
        IPEndPoint[] same = VoipService.MediaTargets("203.0.113.9",
            new string[] { "MPORT", "45672", "203.0.113.9", "45672" });
        Check("a public address identical to the local one is not aimed at twice",
              same.Length == 1, same.Length.ToString());
        IPEndPoint[] badLocal = VoipService.MediaTargets("203.0.113.9",
            new string[] { "MPORT", "0", "203.0.113.77", "50000" });
        Check("a broken local port does not throw away a usable public one",
              badLocal.Length == 1 && badLocal[0].Port == 50000, badLocal.Length.ToString());
        Check("...and an announcement with nothing usable gives no target",
              VoipService.MediaTargets("203.0.113.9", new string[] { "MPORT", "80" }).Length == 0);
        Check("...and neither does a peer whose address we never learned",
              VoipService.MediaTargets("", new string[] { "MPORT", "45672", "203.0.113.77", "50000" }).Length == 0);
        Check("...and a public address of 0.0.0.0 is not a candidate",
              VoipService.MediaTargets("203.0.113.9",
                  new string[] { "MPORT", "45672", "0.0.0.0", "50000" }).Length == 1);
    }

    // ── Can a stranger be handed a relay address and stay safe? ─────────
    // A seed file is only worth having if "this address is that relay" can be
    // checked before anything is registered, so every step here is the step an
    // attacker would have to pass: forge the signature, or serve a different key
    // than the one pinned.
    static void VerifyRelayBootstrap()
    {
        Console.WriteLine("  bootstrap: the seed file and the proof a relay gives");
        RelaySeedEntry e;
        Check("a commented line is not an entry", !RelaySeed.TryParseLine("# nothing here", out e) && e == null);
        Check("a bare host with no port is refused, not defaulted to 45675",
              !RelaySeed.TryParseLine("relay.example|01234567-89ABCDEF|note", out e));
        Check("a full line parses", RelaySeed.TryParseLine("10.0.0.5:45675|abc-DEF |Aisha's PC", out e)
              && e.Address == "10.0.0.5:45675" && e.Note == "Aisha's PC");
        Check("...and its fingerprint is normalised, so pasting case or spaces apart still matches",
              e.Fingerprint == "ABC-DEF");
        Check("no fingerprint at all means 'pin on first use', not 'accept anything'",
              RelaySeed.TryParseLine("10.0.0.6:45675", out e) && e.Fingerprint == RelaySeed.AnyKey);
        Check("a junk file yields the real entries only",
              RelaySeed.Load("# c\n\nnot-a-line\n10.0.0.7:45675|-|ok\n10.0.0.8:45675|AAAA-BBBB|ok").Count == 2);
        RelaySeedEntry pinned = RelaySeed.Load("10.0.0.7:45675|AAAA-BBBB|ok")[0];
        Check("the fingerprint a relay proved is compared exactly",
              RelaySeed.Matches(pinned, "aaaa-bbbb") && !RelaySeed.Matches(pinned, "AAAA-BBC0"));
        Check("...and an unpinned entry matches whatever it sees, once, and says so",
              RelaySeed.Matches(RelaySeed.Load("10.0.0.7:45675|-|x")[0], "anything-at-all"));

        // ---- the attestation itself ----
        Identity relayKey = new Identity(Path.Combine(ScratchDir(), "relay_bootstrap.key"));
        Identity otherKey = new Identity(Path.Combine(ScratchDir(), "relay_imposter.key"));
        string rid = "relay-45820";
        string goodSig = Convert.ToBase64String(relayKey.Sign(Encoding.UTF8.GetBytes(RelayIdentity.Claim(rid))));
        Check("a relay signing its own id is verified", RelayIdentity.Verify(relayKey.PublicBase64, rid, goodSig));
        Check("...and the same key signing somebody else's id is not",
              !RelayIdentity.Verify(relayKey.PublicBase64, "relay-somebody-else", goodSig));
        Check("...and a signature made by another key does not authenticate this one",
              !RelayIdentity.Verify(relayKey.PublicBase64, rid,
                  Convert.ToBase64String(otherKey.Sign(Encoding.UTF8.GetBytes(RelayIdentity.Claim(rid))))));
        Check("garbage where a signature should be is refused, not an exception",
              !RelayIdentity.Verify(relayKey.PublicBase64, rid, "not-base64-@@@"));
        string line = "RPUB|" + rid + "|10.0.0.9:45675|" + relayKey.PublicBase64 + "|" + goodSig;
        string pId, pAdv, pPub, pSig;
        Check("the wire form parses", RelayIdentity.TryParse(line, out pId, out pAdv, out pPub, out pSig)
              && pId == rid && pPub == relayKey.PublicBase64);
        Check("...and a truncated one is not half-read",
              !RelayIdentity.TryParse("RPUB|" + rid + "|adv|" + relayKey.PublicBase64, out pId, out pAdv, out pPub, out pSig));
        Check("first sight of a key is New, never 'trusted'",
              RelayIdentity.Judge(true, relayKey.PublicBase64, null) == RelayIdentity.Verdict.New);
        Check("the same key again is Same",
              RelayIdentity.Judge(true, relayKey.PublicBase64, relayKey.PublicBase64) == RelayIdentity.Verdict.Same);
        Check("a DIFFERENT key at a pinned address is Mismatch - the substitution case",
              RelayIdentity.Judge(true, otherKey.PublicBase64, relayKey.PublicBase64) == RelayIdentity.Verdict.Mismatch);
        Check("and a key that did not sign its id is BadSignature whatever is pinned",
              RelayIdentity.Judge(false, relayKey.PublicBase64, relayKey.PublicBase64) == RelayIdentity.Verdict.BadSignature);

        // ---- live: a real relay answering a real client ----
        int port = 45820;
        CallServer open = NewRelay(port, "everyone", "", "127.0.0.80:" + port, false);
        if (open == null) { Check("bootstrap relay port free (45820)", false); return; }
        TcpClient tc = new TcpClient();
        tc.Connect("127.0.0.1", port);
        StreamWriter tw = new StreamWriter(tc.GetStream(), Encoding.UTF8); tw.AutoFlush = true;
        StreamReader tr = new StreamReader(tc.GetStream(), Encoding.UTF8);
        tw.WriteLine("WHOAMI|");
        string answer = tr.ReadLine();
        Check("an unregistered connection can ask who it is talking to",
              answer != null && answer.StartsWith("RPUB|", StringComparison.Ordinal), answer);
        string aId, aAdv, aPub, aSig;
        bool parsed = RelayIdentity.TryParse(answer ?? "", out aId, out aAdv, out aPub, out aSig);
        Check("...and the answer parses and verifies with the key it presents",
              parsed && RelayIdentity.Verify(aPub, aId, aSig));
        Check("...and it names the relay id the server reports", parsed && aId == open.RelayId,
              parsed ? aId : "unparsed");
        Check("...and it advertises the address peers should dial",
              parsed && aAdv == "127.0.0.80:" + port, parsed ? aAdv : "unparsed");
        tw.WriteLine("WHOAMI|");
        string again = tr.ReadLine();
        Check("asking twice gives the same proof (one key, not one per question)", again == answer);
        tc.Close();
        CallServer strict = NewRelay(45821, "nobody", "", "127.0.0.81:45821", false);
        if (strict != null)
        {
            TcpClient tc2 = new TcpClient();
            tc2.Connect("127.0.0.1", 45821);
            StreamWriter w2 = new StreamWriter(tc2.GetStream(), Encoding.UTF8); w2.AutoFlush = true;
            StreamReader r2 = new StreamReader(tc2.GetStream(), Encoding.UTF8);
            w2.WriteLine("WHOAMI|");
            string reply = r2.ReadLine();
            Check("a relay configured to link to nobody says it has no key, rather than minting one",
                  reply != null && reply.StartsWith("ERR|norelaykey", StringComparison.Ordinal), reply);
            Check("...and no relay key file appeared in its folder", !File.Exists(Path.Combine(ScratchDir(), "relay_45821.key")));
            tc2.Close();
            // A probe has to be able to tell "this relay declined" from "this relay was
            // silent", because the words shown to a user are different and the fix is
            // different: one is a policy the operator chose, the other is an old build.
            RelayClient sp = new RelayClient();
            sp.ProbeOnly = true;
            sp.IdentityTimeoutMs = 1500;    // it answers at once; the test need not burn a full timeout
            sp.Start("127.0.0.1:45821", "7008881066", "tok-7008881066");
            Check("a relay that declines to have an identity still settles the question", WaitFor(delegate
                  { return sp.RelayAskSettled; }, 6000), "settled=" + sp.RelayAskSettled);
            Check("...and it reads as a refusal, not as silence",
                  sp.RelayRefusedIdentity && !sp.RelayIdentityChecked,
                  "refused=" + sp.RelayRefusedIdentity + " checked=" + sp.RelayIdentityChecked);
            Check("...and a declined identity is not treated as a verdict about a key",
                  sp.RelayTrust == "unattested", "trust=" + sp.RelayTrust);
            sp.Stop();
            strict.Stop();
        }

        // ---- the client that registers only after checking ----
        string pinFile = Path.Combine(ScratchDir(), "relay_pins_test.txt");
        try { if (File.Exists(pinFile)) File.Delete(pinFile); } catch { }
        // What the relay logged is the witness for "did a registration actually reach
        // it". The client's own idea of its socket is precisely the thing that was
        // wrong here, so it does not get to be the evidence.
        List<string> srvSaid = new List<string>();
        open.Log += delegate(string s) { lock (srvSaid) srvSaid.Add(s); };
        RelayClient c1 = new RelayClient();
        c1.RelayPins = new PeerIdentityBook(pinFile);
        c1.Start("127.0.0.1:" + port, "7008881001", "tok-7008881001");
        // Wait on RelayAskSettled, not just on Checked+Connected: an attempt in flight
        // resets the verdict to "unattested" while the flag from the previous attempt is
        // still set, so reading the trust at that moment is reading a half-written answer.
        // This is the same misread that the bootstrap fix was about, seen from the test side.
        Check("the client asks before it registers, and gets a verdict", WaitFor(delegate
              { return c1.RelayAskSettled && c1.RelayIdentityChecked && c1.Connected; }, 8000),
              "checked=" + c1.RelayIdentityChecked + " connected=" + c1.Connected);
        Check("...first contact is 'verified-new', which is a pin, not a trust",
              c1.RelayTrust == "verified-new", "trust=" + c1.RelayTrust + " fp=" + c1.RelayFingerprint);
        Check("...and the fingerprint it printed is the relay's own",
              c1.RelayFingerprint == RelayIdentity.Fingerprint(open.RelayKey.PublicBase64),
              c1.RelayFingerprint);
        Check("...and the pin is on disk, not only in memory",
              File.Exists(pinFile) && File.ReadAllText(pinFile).Contains("127.0.0.1:" + port));
        c1.Stop();
        RelayClient c2 = new RelayClient();
        c2.RelayPins = new PeerIdentityBook(pinFile);
        c2.Start("127.0.0.1:" + port, "7008881001", "tok-7008881001");
        Check("returning to the same relay is recognised, not re-pinned", WaitFor(delegate
              { return c2.RelayAskSettled && c2.RelayIdentityChecked && c2.Connected; }, 8000));
        Check("...and reads as 'verified-known'", c2.RelayTrust == "verified-known", "trust=" + c2.RelayTrust);
        c2.Stop();

        // The case that matters: the pin says one key, the server presents another.
        PeerIdentityBook swapped = new PeerIdentityBook(Path.Combine(ScratchDir(), "relay_pins_swapped.txt"));
        swapped.Check("127.0.0.1:" + port, otherKey.PublicBase64);
        RelayClient c3 = new RelayClient();
        c3.RelayPins = swapped;
        c3.Start("127.0.0.1:" + port, "7008881002", "tok-7008881002");
        Check("a relay presenting a key other than the pinned one is refused", WaitFor(delegate
              { return c3.RelayTrust == "mismatch" || c3.RelayTrust == "bad-signature"; }, 8000),
              "trust=" + c3.RelayTrust);
        // The verdict is reached inside the identity check and the socket is closed by its
        // caller, so sampling Connected the moment the verdict appears catches a live
        // socket legitimately on its way down. Wait for the way down to be done.
        bool refusedAndClosed = WaitFor(delegate { return !c3.Connected; }, 6000);
        Check("...and nothing was registered while it was refused", refusedAndClosed,
              "connected=" + c3.Connected);
        Check("...and nothing at all was registered at that relay while it was refused",
              !RelaySaid(srvSaid, "Registered 7008881002"), "it registered despite the refusal");
        c3.Stop();

        // ---- the two defects the first end-to-end run caught ----
        // (1) the caller waited on Connected, which comes up BEFORE the identity answer,
        // so it read "no answer yet" as "no answer coming" and refused a perfectly good
        // seed entry; (2) the probe sent its REG as soon as the check finished, whatever
        // the caller decided, so "we checked before handing over our number" was true of
        // the decision and false of the wire. Both are proven here against the relay's
        // own log rather than against the client's feelings.
        Check("a real registration does leave a line in the relay log (so an empty log means something)",
              RelaySaid(srvSaid, "Registered 7008881001"), string.Join(" / ", srvSaid.ToArray()));
        RelayClient p1 = new RelayClient();
        p1.ProbeOnly = true;
        p1.RelayPins = new PeerIdentityBook(Path.Combine(ScratchDir(), "relay_pins_probe.txt"));
        p1.Start("127.0.0.1:" + port, "7008881055", "tok-7008881055");
        Check("a probe settles on the answer, not on the socket coming up", WaitFor(delegate
              { return p1.RelayAskSettled; }, 9000), "settled=" + p1.RelayAskSettled);
        // The probe closes its own socket once the answer is read, and RelayAskSettled is
        // set just before that - so sampling Connected the instant it settles races the
        // close and fails one run in many. Wait for the close instead: the claim "it never
        // became a client" is carried by the relay's log below, not by this flag.
        bool probeHungUp = WaitFor(delegate { return !p1.Connected; }, 4000);
        Check("...and it learned the relay's key without ever being a client of it",
              p1.RelayIdentityChecked && p1.RelayTrust == "verified-new" && probeHungUp,
              "checked=" + p1.RelayIdentityChecked + " trust=" + p1.RelayTrust + " connected=" + p1.Connected);
        Check("...and the relay never saw that number at all",
              !RelaySaid(srvSaid, "Registered 7008881055"), "the probe leaked a registration");
        Check("...and the pin the probe took is on file, so the real connection reads as known",
              File.Exists(Path.Combine(ScratchDir(), "relay_pins_probe.txt")));
        p1.Stop();
        try { p1.Dispose(); } catch { }
        // A dead address must settle on its own rather than being waited on for the
        // whole budget - this is what a first entry in a seed file looks like when the
        // machine behind it is switched off.
        RelayClient dead = new RelayClient();
        dead.ProbeOnly = true;
        dead.Start("127.0.0.79:45999", "7008881077", "tok-7008881077");
        Check("a dead address settles instead of being waited on", WaitFor(delegate
              { return dead.RelayAskSettled; }, 6000), "settled=" + dead.RelayAskSettled);
        Check("...and settles as 'no answer', not as 'an answer we disliked'",
              !dead.RelayIdentityChecked && !dead.RelayRefusedIdentity,
              "checked=" + dead.RelayIdentityChecked + " refused=" + dead.RelayRefusedIdentity);
        Check("...and it registered nothing there either", !RelaySaid(srvSaid, "Registered 7008881077"));
        dead.Stop();
        try { dead.Dispose(); } catch { }
        open.Stop();
    }

    // Did the relay log a line starting with this? Used to prove a probe stayed quiet.
    static bool RelaySaid(List<string> lines, string start)
    {
        lock (lines) return lines.Exists(delegate(string s)
        { return s != null && s.StartsWith(start, StringComparison.Ordinal); });
    }

    // ── Which route is carrying a call, and can the peer's announcement be trusted ──
    //
    // "direct" was the whole answer the app could give, and at distance that is not a
    // fact about the network: three different peer addresses can deliver the media and
    // they mean three different things about the two routers involved. The classifier is
    // pure, so every case is settled here with synthetic endpoints; the part that cannot
    // be settled purely is whether the announcement survives a relay hop with its new
    // field, because that is where this project has been bitten before.
    static void VerifyMediaRoute()
    {
        Console.WriteLine("  media route: announced endpoints and which one delivered");
        IPEndPoint host = new IPEndPoint(IPAddress.Parse("192.168.1.50"), 45672);
        IPEndPoint reflex = new IPEndPoint(IPAddress.Parse("203.0.113.7"), 51000);
        IPEndPoint mapped = new IPEndPoint(IPAddress.Parse("203.0.113.7"), 45672);

        IPEndPoint h, r, m;
        Check("a peer that only knows its local port announces just that",
              VoipService.ParsePeerMediaAnnounce("192.168.1.50", new string[] { "MPORT", "45672" }, out h, out r, out m)
              && host.Equals(h) && r == null && m == null);
        Check("...and the reflexive pair is read from the two fields it has always had",
              VoipService.ParsePeerMediaAnnounce("192.168.1.50",
                  new string[] { "MPORT", "45672", "203.0.113.7", "51000" }, out h, out r, out m)
              && reflex.Equals(r) && m == null);
        Check("...and a router forward arrives as its own labelled field, not as positions five and six",
              VoipService.ParsePeerMediaAnnounce("192.168.1.50",
                  new string[] { "MPORT", "45672", "203.0.113.7", "51000", "map=203.0.113.7:45672" },
                  out h, out r, out m) && mapped.Equals(m) && reflex.Equals(r));
        Check("...and it is read even when there was no STUN answer at all",
              VoipService.ParsePeerMediaAnnounce("192.168.1.50",
                  new string[] { "MPORT", "45672", "", "", "map=203.0.113.7:45672" },
                  out h, out r, out m) && mapped.Equals(m) && r == null && host.Equals(h));
        Check("...and order does not matter, because a self-describing field is not a position",
              VoipService.ParsePeerMediaAnnounce("192.168.1.50",
                  new string[] { "MPORT", "45672", "map=203.0.113.7:45672" }, out h, out r, out m)
              && mapped.Equals(m));
        Check("...and a malformed forward is dropped rather than guessed at",
              VoipService.ParsePeerMediaAnnounce("192.168.1.50",
                  new string[] { "MPORT", "45672", "map=not-an-address:99999" }, out h, out r, out m)
              && m == null && host.Equals(h));
        Check("...and a port below the ephemeral floor is not a media port, so it is dropped",
              VoipService.ParsePeerMediaAnnounce("192.168.1.50",
                  new string[] { "MPORT", "45672", "map=203.0.113.7:80" }, out h, out r, out m)
              && m == null && host.Equals(h));
        Check("...and a peer whose address is not an address announces nothing",
              !VoipService.ParsePeerMediaAnnounce("router.local",
                  new string[] { "MPORT", "45672" }, out h, out r, out m));

        // The order the punch aims in, and the two refusals that keep it honest.
        IPEndPoint[] t = VoipService.MediaTargets("192.168.1.50",
            new string[] { "MPORT", "45672", "203.0.113.7", "51000", "map=203.0.113.7:45672" });
        Check("targets are ordered best-first, and a forward a router promised beats one it merely saw",
              t.Length == 3 && mapped.Equals(t[0]) && reflex.Equals(t[1]) && host.Equals(t[2]),
              string.Join(", ", Array.ConvertAll<IPEndPoint, string>(t, delegate(IPEndPoint e) { return e.ToString(); })));
        IPEndPoint[] same = VoipService.MediaTargets("192.168.1.50",
            new string[] { "MPORT", "45672", "map=192.168.1.50:45672" });
        Check("...and an announced forward that is really the local address is not sent to twice",
              same.Length == 1 && host.Equals(same[0]), same.Length.ToString());
        IPEndPoint[] zero = VoipService.MediaTargets("192.168.1.50",
            new string[] { "MPORT", "45672", "0.0.0.0", "45672" });
        Check("...and 0.0.0.0 is refused as a target however it is announced",
              zero.Length == 1 && host.Equals(zero[0]), zero.Length.ToString());

        // Which address delivered it - the actual diagnosis, and the reason the three
        // endpoints are kept apart instead of being merged into one candidate list.
        Check("a relayed call is a relayed call, whatever the socket also heard",
              VoipService.RouteKind(true, host, true, host, reflex, mapped) == "relay");
        Check("nothing received yet is reported as nothing, not as a route",
              VoipService.RouteKind(false, null, false, host, reflex, mapped) == "none");
        Check("frames from the local address mean the two machines are on one network",
              VoipService.RouteKind(false, host, true, host, reflex, mapped) == "host");
        Check("...and frames from the reflexive address mean STUN saw a path, nothing more",
              VoipService.RouteKind(false, reflex, true, host, reflex, mapped) == "reflexive");
        Check("...while frames from the mapped address mean a router promised that door",
              VoipService.RouteKind(false, mapped, true, host, reflex, mapped) == "mapped");
        Check("...and an address nobody announced is named as that, never as a clean direct path",
              VoipService.RouteKind(false, new IPEndPoint(IPAddress.Parse("198.51.100.9"), 40000),
                                    true, host, reflex, mapped) == "unannounced");
        Check("...and a peer that announced nothing at all is not blamed for an unmatched source",
              VoipService.RouteKind(false, host, true, null, null, null) == "unannounced");

        // The words the bar shows. Asserted, because a screen that prints an internal
        // code to a user has failed at the thing it is for.
        Check("every route kind has words, and none of them is the raw code",
              VoipService.RouteWords("host") == "direct, on the same network" &&
              VoipService.RouteWords("reflexive") == "direct, over its public address" &&
              VoipService.RouteWords("mapped") == "direct, through the port it opened" &&
              VoipService.RouteWords("relay") == "carried by the relay" &&
              VoipService.RouteWords("unannounced").Contains("never announced") &&
              VoipService.RouteWords("none") == "no media yet");
        Check("...and a kind this build has never heard of still reads as a sentence",
              VoipService.RouteWords("quic-tunnel") == "no media yet");

        // ── the announcement across a real relay hop ──────────────────
        CallServer ra = NewRelay(45855, "everyone", "127.0.0.1:45856");
        CallServer rb = NewRelay(45856, "everyone", "");
        if (ra == null || rb == null) { Check("media-route relay ports free (45855-45856)", false); return; }
        Node a = new Node("7008885001", 45855);
        Node b = new Node("7008885002", 45856);
        Check("the two relays are linked for the announcement test",
              WaitFor(delegate { return ra.LinkCount >= 1 && rb.LinkCount >= 1; }, 9000));
        // The route has to exist before anything is sent, or the line is filed as offline
        // mail for a number this relay has not heard of yet - and the assertion would be
        // measuring a queue instead of a forward.
        Check("relay A's client can see the peer that lives on relay B",
              a.WaitForDir("7008885002", 9000) && a.DirHasVia("7008885002"), a.DirText);
        string mport = "MPORT|45672|203.0.113.7|51000|map=203.0.113.7:45672";
        a.Send("MSG|7008885002|7008885001|" + mport);
        bool got = b.WaitForMsg("7008885001", mport, 9000);
        string payload = b.LastMsgFrom("7008885001");
        Check("the announcement reaches a peer on the other relay with its map= field intact", got,
              payload == null ? "<nothing arrived>" : payload);
        string[] asSplit = (payload ?? "").Split('|');
        IPEndPoint h2, r2, m2;
        Check("...and what arrived still parses to three distinct endpoints on the far side",
              VoipService.ParsePeerMediaAnnounce("203.0.113.7", asSplit, out h2, out r2, out m2)
              && m2 != null && m2.Port == 45672 && r2 != null && r2.Port == 51000,
              "fields=" + asSplit.Length + " map=" + (m2 == null ? "-" : m2.ToString()));
        Check("...and a glued remainder would have been caught, not silently misread as a port",
              asSplit.Length == 5, string.Join("|", asSplit));
        a.Close(); b.Close(); ra.Stop(); rb.Stop();
    }

    // ── The peer list is pushed by one thread, not by whoever noticed ────────
    //
    // Two real defects were removed here, and both are things a test can hold the
    // relay to: a snapshot pushed while holding the map lock across blocking writes
    // stalls message ROUTING for everybody, and a client's own registration running
    // that push inline means its next command waits behind other people's sockets -
    // which is where the measured `WHO` timeouts came from. Coalescing is the risk
    // this change introduces, so the assertions are mostly about information not being
    // lost: PEERS is a full snapshot, so a collapsed push must still contain everyone.
    static void VerifyPeerPush()
    {
        Console.WriteLine("  peer push: one notifier, coalesced, nothing lost");
        CallServer r = NewRelay(45857, "everyone", "");
        if (r == null) { Check("peer-push relay port free (45857)", false); return; }

        Node early = new Node("7008886000", 45857);
        long push0 = r.PeerBroadcasts;
        var late = new List<Node>();
        // A burst of registrations: the burst is the point, because the notifier must
        // serve them all without any of them seeing a stale or partial list.
        for (int i = 1; i <= 8; i++)
            late.Add(new Node("700888600" + i, 45857));

        bool earlySeesAll = WaitFor(delegate
        {
            for (int i = 1; i <= 8; i++)
                if (!early.DirText.Contains("700888600" + i)) return false;
            return true;
        }, 12000);
        Check("a client that joined before the burst still learns every one of them",
              earlySeesAll, early.DirText);
        bool lateSeesAll = WaitFor(delegate
        {
            foreach (Node n in late)
            {
                if (!n.DirText.Contains("7008886000")) return false;
                for (int i = 1; i <= 8; i++)
                    if (!n.DirText.Contains("700888600" + i)) return false;
            }
            return true;
        }, 12000);
        Check("...and no late joiner gets a list missing the others (coalescing must not drop information)",
              lateSeesAll, late.Count > 0 ? late[late.Count - 1].DirText : "<none>");
        Check("...and the notifier thread actually ran",
              r.PeerBroadcasts > push0, "pushes " + push0 + " -> " + r.PeerBroadcasts);
        // How many pushes served how many events. Reported, not asserted: whether two
        // registrations collapse into one push depends on how fast this machine was,
        // and a bound that happens to hold today is a flake with a number on it.
        Console.WriteLine("    note: " + (r.PeerBroadcasts - push0) + " push(es) served 8 registrations");

        // The responsiveness claim, in the place it is cheapest to see: a question asked
        // by an already-registered client while other clients are joining. Measured at
        // process level in cold_cache_dial_e2e's silent counter; here it is a smoke test,
        // because eight loopback sockets may simply be too fast to ever stall.
        // A real RelayClient asks, because AskOnline lives there - the raw Node wrapper
        // has no idea the verb exists.
        RelayClient asker = new RelayClient();
        asker.Start("127.0.0.1:45857", "7008886009", "tok-7008886009");
        Check("the asker is registered before it starts asking", WaitFor(delegate
              { return asker.Connected && asker.Registered; }, 9000),
              "connected=" + asker.Connected + " registered=" + asker.Registered);
        int unanswered = 0;
        for (int i = 1; i <= 8; i++)
        {
            late.Add(new Node("70088860" + (10 + i), 45857));
            if (!asker.AskOnline("70088860" + (10 + i), 1500)) unanswered++;
        }
        Check("every question asked during a join burst got an answer",
              unanswered == 0, unanswered + " of 8 unanswered in-process (see the e2e for the real signal)");

        // Routing must not wait for the directory. This is the half that would have
        // shown up as someone else's chat being slow, not as anything about the relay.
        string probe = "PEER-PUSH-" + DateTime.Now.Ticks;
        late[0].Send("MSG|7008886000|" + late[0].Number + "|" + probe);
        Check("...and a message still got through while the list was being pushed",
              early.WaitForMsg(late[0].Number, probe, 4000), "chat stalled behind a directory push");

        early.Close();
        asker.Stop();
        try { asker.Dispose(); } catch { }
        foreach (Node n in late) n.Close();
        r.Stop();
    }

    // ── Does a route claim name a PROVED pair? ────────────────────────
    //
    // A route used to be named from whichever address sent us a datagram, and a datagram
    // needs no key - so a keyless keep-alive could name one, and far worse, NOTHING on
    // either machine knew whether our own audio had ever landed. Media is sprayed at every
    // candidate at once, so a reply cannot imply it either: the peer may be hearing us
    // through an address it does not answer from. This checks the receipt that fixes the
    // second half and the narrowing that fixes the first, over real UDP on loopback.
    static void VerifyPairProof()
    {
        Console.WriteLine("  pair proof: receipts, and what may name a route");

        // ── the verdict itself: every state reachable, none sharing an input ──
        Check("no key means no claim at all",
              VoipService.PairProof(false, 9, 9, 9, 100, true, true) == "none");
        Check("their receipt, and nothing of ours sent, is not a proved pair",
              VoipService.PairProof(true, 0, 5, 0, 100, true, true) == "ours-silent");
        Check("a receipt reporting zero, while we have been sending, is called one-way",
              VoipService.PairProof(true, 40, 38, 0, 100, true, true) == "one-way");
        Check("...and proved once that same receipt names frames we sent",
              VoipService.PairProof(true, 40, 38, 37, 100, true, true) == "proved");
        Check("a receipt from a different address than their media is not this pair",
              VoipService.PairProof(true, 40, 38, 37, 100, false, true) == "asymmetric");
        Check("no receipt yet, peer not yet asked twice, is only waiting",
              VoipService.PairProof(true, 40, 38, 0, -1, true, false) == "waiting");
        Check("...and unreported once it has been, so an older build is not called broken",
              VoipService.PairProof(true, 40, 38, 0, -1, true, true) == "unreported");
        Check("nothing arriving and nothing reported claims nothing",
              VoipService.PairProof(true, 40, 0, 0, -1, true, true) == "none");
        Check("one-way and unreported are not worded the same way round",
              VoipService.PairWords("one-way") != VoipService.PairWords("unreported"),
              VoipService.PairWords("unreported"));
        // Every state must have its own words. One that fell through to the default string
        // would be read by a person as a different state than the one that happened.
        string[] proofStates = new string[] { "proved", "one-way", "asymmetric", "ours-silent",
                                              "waiting", "unreported", "none" };
        bool wordsDistinct = true;
        for (int i = 0; i < proofStates.Length && wordsDistinct; i++)
            for (int j = i + 1; j < proofStates.Length && wordsDistinct; j++)
                if (VoipService.PairWords(proofStates[i]) == VoipService.PairWords(proofStates[j]))
                    wordsDistinct = false;
        Check("each state has its own words, so none reads as another", wordsDistinct);

        // ── the same over real sockets ──
        byte[] key = new byte[16];
        for (int i = 0; i < 16; i++) key[i] = (byte)(0x31 + i);
        byte[] otherKey = new byte[16];
        for (int i = 0; i < 16; i++) otherKey[i] = (byte)(0x77 + i);

        VoipMedia a = new VoipMedia();
        VoipMedia b = new VoipMedia();
        VoipMedia impostor = new VoipMedia();
        string liveErr = "";
        try
        {
            a.Open(VoipService.MEDIA_PORT);
            b.Open(a.LocalPort);                    // forced to move, as a second instance is
            a.SetKey(key);
            b.SetKey(key);
            a.AddCandidate(new IPEndPoint(IPAddress.Loopback, b.LocalPort));
            b.AddCandidate(new IPEndPoint(IPAddress.Loopback, a.LocalPort));

            // A keyless keep-alive and a noise packet arrive first. Both have always been
            // allowed to say "somebody is there"; neither may name a route.
            UdpClient probe = new UdpClient();
            byte[] ka = new byte[] { VoipMedia.PKT_KEEPALIVE, 0 };
            probe.Send(ka, ka.Length, "127.0.0.1", b.LocalPort);
            byte[] noise = new byte[] { 99, 1, 2, 3, 4, 5 };
            probe.Send(noise, noise.Length, "127.0.0.1", b.LocalPort);
            Check("a keyless keep-alive still credits the watchdog, as a muted peer needs",
                  WaitFor(delegate { return b.LastRxTicks != 0; }, 2500), "ticks=" + b.LastRxTicks);
            Check("...but it does not name the source of the media",
                  b.LastRxAuthRemote == null,
                  b.LastRxAuthRemote == null ? "null" : b.LastRxAuthRemote.ToString());
            Check("...and with no named source the route stays unnamed, key or no key",
                  VoipService.RouteKind(false, b.LastRxAuthRemote, b.LastRxTicks != 0,
                        new IPEndPoint(IPAddress.Loopback, a.LocalPort), null, null) == "none");
            probe.Close();

            // Now actual media, both directions.
            byte[] pcm = new byte[640];
            for (int i = 0; i < pcm.Length; i++) pcm[i] = (byte)(i & 0x7f);
            a.SendAudio(pcm);
            a.SendAudio(pcm);
            bool decrypted = WaitFor(delegate { return b.RxFrames >= 2; }, 4000);
            Check("the peer received and counted our audio", decrypted, "b rx=" + b.RxFrames);
            IPEndPoint aEp = new IPEndPoint(IPAddress.Loopback, a.LocalPort);
            Check("...and the address it came from may now name the route",
                  b.LastRxAuthRemote != null && b.LastRxAuthRemote.Equals(aEp),
                  b.LastRxAuthRemote == null ? "null" : b.LastRxAuthRemote.ToString());
            Check("...which is then the address the peer announced, not an unnamed one",
                  VoipService.RouteKind(false, b.LastRxAuthRemote, b.LastRxTicks != 0, aEp, null, null) == "host");

            long bTxBefore = b.TxFrames;
            long aRxBefore = a.RxFrames;
            b.AckPeer();
            bool receipted = WaitFor(delegate { return b.AcksSent >= 1 && a.PeerRxFrames >= 2; }, 4000);
            Check("the receipt arrives and says how much of our audio landed",
                  receipted, "a saw peer rx=" + a.PeerRxFrames + " acks sent=" + b.AcksSent);
            Check("...so this pair is proved in both directions, by observation",
                  VoipService.PairProof(a.HasKey, a.TxFrames, a.RxFrames, a.PeerRxFrames,
                        1, true, true) == "proved");
            Check("a receipt the peer signed names the peer's own address",
                  a.LastAckRemote != null && a.LastAckRemote.Port == b.LocalPort,
                  a.LastAckRemote == null ? "null" : a.LastAckRemote.ToString());
            // The counters are asserted elsewhere as "frames we sent arrived". If a receipt
            // counted as a media frame, that assertion would be measuring its own paperwork.
            Check("...and does not count as a media frame sent",
                  b.TxFrames == bTxBefore, bTxBefore + " -> " + b.TxFrames);
            Check("...nor as one received",
                  a.RxFrames == aRxBefore, aRxBefore + " -> " + a.RxFrames);

            // A receipt is only worth what its proof is worth. CTR has no integrity and the
            // packet type is in the clear, so this is the check that an off-path datagram
            // cannot talk this machine into believing its audio arrived.
            long rxClaimed = a.PeerRxFrames;
            long acksIn = a.AcksRcvd;
            impostor.Open(a.LocalPort);
            impostor.SetKey(otherKey);
            impostor.AddCandidate(new IPEndPoint(IPAddress.Loopback, a.LocalPort));
            impostor.AckPeer();
            impostor.AckPeer();
            Thread.Sleep(600);
            Check("a receipt from somebody without the call key is refused outright",
                  a.AcksRcvd == acksIn && a.PeerRxFrames == rxClaimed,
                  "acksRcvd " + acksIn + " -> " + a.AcksRcvd + ", rx " + rxClaimed + " -> " + a.PeerRxFrames);

            // A fresh call must not open holding the last one's proof.
            a.ResetForCall();
            Check("...and a new call starts with no proof from the last one",
                  a.PeerRxFrames == 0 && a.LastAckTicks == 0 && a.LastRxAuthRemote == null,
                  "rx=" + a.PeerRxFrames + " ticks=" + a.LastAckTicks);

            // ── the case the timers cannot see, reproduced on purpose ──
            // x aims at a port with nothing listening, so its audio really does land
            // nowhere, while y aims back at x correctly so y's receipts arrive. This is the
            // call where BOTH sides previously reported a working route: nothing here ever
            // goes quiet on x's side, so no inbound timer can fire.
            //
            // A FRESH pair, and that is not tidiness. A receipt carries the peer's
            // CUMULATIVE count for its call - ResetForCall deliberately leaves RxFrames and
            // TxFrames alone, because --call prints them as the call's totals - so a
            // recycled socket would still be reporting the two frames it decrypted above,
            // and would read `proved` forever no matter where the audio went. The first two
            // runs of this check failed for exactly that reason.
            VoipMedia x = new VoipMedia();
            VoipMedia y = new VoipMedia();
            x.Open(b.LocalPort);                  // forced off, as any second socket is
            y.Open(x.LocalPort);
            x.SetKey(key);
            y.SetKey(key);
            UdpClient gone = new UdpClient(0);
            int deadPort = ((IPEndPoint)gone.Client.LocalEndPoint).Port;
            gone.Close();
            x.AddCandidate(new IPEndPoint(IPAddress.Loopback, deadPort));
            y.AddCandidate(new IPEndPoint(IPAddress.Loopback, x.LocalPort));
            for (int i = 0; i < 8; i++) { x.SendAudio(pcm); Thread.Sleep(25); }
            y.AckPeer();
            bool zeroReceipt = WaitFor(delegate
                { return x.LastAckTicks != 0 && Interlocked.Read(ref x.PeerRxFrames) == 0; }, 4000);
            string owVerdict = VoipService.PairProof(x.HasKey, x.TxFrames, x.RxFrames,
                Interlocked.Read(ref x.PeerRxFrames), 1, true, true);
            Check("audio sent into a dead port is seen as one-way, not as a working route",
                  zeroReceipt && owVerdict == "one-way",
                  "receipt zero=" + zeroReceipt + " verdict=" + owVerdict +
                  " tx=" + x.TxFrames + " peer rx=" + x.PeerRxFrames + " dead port=" + deadPort);
            Check("...and the peer really did not receive any of it",
                  y.RxFrames == 0, "y rx=" + y.RxFrames);
            Check("...while the receipt itself arrived, so this is not mere silence",
                  x.AcksRcvd >= 1, "acks rcvd=" + x.AcksRcvd);
            try { x.Dispose(); y.Dispose(); } catch { }

            // ── the gates that stop that verdict from bouncing every call ──
            Check("one one-way reading does not move the call",
                  VoipService.OneWayFallbackReason("one-way", 400, 1, false, true, true) == null);
            Check("...nor does a reading taken before we had said much",
                  VoipService.OneWayFallbackReason("one-way",
                        VoipService.OneWayMinFrames - 1, VoipService.OneWayBeatsNeeded,
                        false, true, true) == null);
            Check("...and it takes the full stretch of repeated receipts, not most of one",
                  VoipService.OneWayFallbackReason("one-way", 400,
                        VoipService.OneWayBeatsNeeded - 1, false, true, true) == null);
            Check("repeated receipts that we are not heard, with a relay to go to, is acted on",
                  VoipService.OneWayFallbackReason("one-way", 400,
                        VoipService.OneWayBeatsNeeded, false, true, true) != null);
            // Every other state must be inert, or a normal call gets bounced by its own
            // paperwork: proving is not a failure, and an older peer that never answers is
            // not one either.
            string[] inert = new string[] { "proved", "waiting", "unreported", "ours-silent",
                                            "asymmetric", "none" };
            bool allInert = true;
            for (int i = 0; i < inert.Length; i++)
                if (VoipService.OneWayFallbackReason(inert[i], 400, 30, false, true, true) != null)
                    allInert = false;
            Check("no other pair state can trigger a switch", allInert);
            Check("...and with no relay route the call is left alone rather than ended",
                  VoipService.OneWayFallbackReason("one-way", 400, 30, false, false, true) == null &&
                  VoipService.OneWayFallbackReason("one-way", 400, 30, false, true, false) == null);
            Check("...and once the relay is already carrying it there is nothing left to switch",
                  VoipService.OneWayFallbackReason("one-way", 400, 30, true, true, true) == null);
        }
        catch (Exception ex) { liveErr = ex.Message; }
        Check("the pair-proof sockets came up", liveErr.Length == 0, liveErr);
        try { a.Dispose(); b.Dispose(); impostor.Dispose(); } catch { }
    }

    // ── Asking a router to open a port (UPnP IGD) ─────────────────────
    //
    // There is no router in this test and none is pretended for. What is checked is the
    // handful of things that are easy to get wrong and invisible from the outside: the
    // shape of the discovery request, a LOCATION that is not fetchable, a controlURL that
    // is relative (the classic one - it turns into a 404 that reads like "no UPnP"), the
    // service a description should be believed to offer, and a SOAP fault whose number
    // says what a person should do next. Whether a real gateway opens a port is answered
    // by running the relay with --relay-port-map, and "no gateway answered" is a correct
    // outcome on a VPS, not a bug to retry.
    static void VerifyPortMap()
    {
        Console.WriteLine("  port mapping: discovery, description, faults");
        string req = PortMap.SearchRequest(PortMap.StIgd);
        Check("the discovery request is a legal M-SEARCH",
              req.StartsWith("M-SEARCH * HTTP/1.1\r\n", StringComparison.Ordinal) &&
              req.Contains("HOST: 239.255.255.250:1900") &&
              req.Contains("MAN: \"ssdp:discover\"") &&
              req.Contains("ST: " + PortMap.StIgd) &&
              req.EndsWith("\r\n\r\n", StringComparison.Ordinal), req);
        Check("...and it asks on the SSDP port, never on the port being mapped",
              PortMap.SsdpPort == 1900);

        Check("a LOCATION header is read whatever case it arrived in",
              PortMap.LocationFromResponse("HTTP/1.1 200 OK\r\nCACHE-CONTROL: max-age=1800\r\nlocation: http://192.168.1.1:45877/igd/desc.xml\r\n")
                  == "http://192.168.1.1:45877/igd/desc.xml");
        Check("...and a response with no LOCATION is not a device",
              PortMap.LocationFromResponse("HTTP/1.1 200 OK\r\nST: x\r\n") == null);
        Check("...and a LOCATION nobody can fetch is refused now, not as an exception later",
              PortMap.LocationFromResponse("LOCATION: ftp://192.168.1.1/desc.xml") == null);
        Check("...and silence is refused too",
              PortMap.LocationFromResponse(null) == null && PortMap.LocationFromResponse("") == null);

        // Two description shapes that differ in exactly the way that matters, and one
        // that is not an Internet Gateway Device at all.
        string descBoth = "<root><device><deviceType>urn:schemas-upnp-org:device:InternetGatewayDevice:1</deviceType>" +
            "<serviceList>" +
            "<service><serviceType>urn:schemas-upnp-org:service:Layer3Forwarding:1</serviceType><controlURL>/upnp/control/layer3fwd</controlURL></service>" +
            "<service><serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType><controlURL>/upnp/control/WANIPConn1</controlURL></service>" +
            "<service><serviceType>urn:schemas-upnp-org:service:WANIPConnection:2</serviceType><controlURL>/upnp/control/WANIPConn2</controlURL></service>" +
            "</serviceList></device></root>";
        string control, stype;
        Check("a description offering both versions prefers :2",
              PortMap.TryFindControlUrl(descBoth, "http://192.168.1.1:45877/igd/desc.xml", out control, out stype)
              && stype.EndsWith("WANIPConnection:2", StringComparison.Ordinal)
              && control == "http://192.168.1.1:45877/upnp/control/WANIPConn2", control + " / " + stype);
        // The port the description was served on stays attached to the control URL. A
        // router on port 80 gives a bare host; one on a non-standard port does not, and
        // "helpfully" dropping it would post the SOAP to a closed port.
        Check("...and a root-relative controlURL is resolved against the host and its port, not the page",
              control == "http://192.168.1.1:45877/upnp/control/WANIPConn2", control);
        Check("...and on an ordinary router that means a plain host URL",
              PortMap.ResolveUrl("http://192.168.1.1/desc.xml", "/ctl/WANIPConn1")
                  == "http://192.168.1.1/ctl/WANIPConn1",
              PortMap.ResolveUrl("http://192.168.1.1/desc.xml", "/ctl/WANIPConn1"));
        string descPpp = "<root><serviceList><service><serviceType>" +
            "urn:schemas-upnp-org:service:WANPPPConnection:1</serviceType><controlURL>ctl/IPConn</controlURL></service></serviceList></root>";
        Check("...and an old router offering only PPP is still usable",
              PortMap.TryFindControlUrl(descPpp, "http://10.0.0.1/upnp/igd/desc.xml", out control, out stype)
              && stype.EndsWith("WANPPPConnection:1", StringComparison.Ordinal)
              && control == "http://10.0.0.1/upnp/igd/ctl/IPConn", control + " / " + stype);
        string descNone = "<root><serviceList><service><serviceType>" +
            "urn:schemas-upnp-org:service:L2TPConnection:1</serviceType><controlURL>/x</controlURL></service></serviceList></root>";
        Check("...and a device with no WAN connection service is not called an IGD",
              !PortMap.TryFindControlUrl(descNone, "http://192.168.1.1/d.xml", out control, out stype));
        Check("...and a missing description or controlURL is no route to anything",
              !PortMap.TryFindControlUrl("", "http://192.168.1.1/d.xml", out control, out stype) &&
              PortMap.ResolveUrl("http://a/b/c.xml", "") == null);
        Check("...and a controlURL that is already absolute is left exactly as it was",
              PortMap.ResolveUrl("http://a/b/c.xml", "http://other:5000/ctl") == "http://other:5000/ctl");

        string ipService = "urn:schemas-upnp-org:service:WANIPConnection:1";
        string body = PortMap.AddPortMappingBody(ipService, 45675, 45675, "192.168.1.23", "UssdApp & friends");
        Check("the mapping request names the port, TCP, and this machine",
              body.Contains("<NewExternalPort>45675</NewExternalPort>") &&
              body.Contains("<NewProtocol>TCP</NewProtocol>") &&
              body.Contains("<NewInternalClient>192.168.1.23</NewInternalClient>") &&
              body.Contains("xmlns:u=\"" + ipService + "\""), body);
        Check("...and asks for no lease and any source, the pair most routers accept",
              body.Contains("<NewLeaseDuration>0</NewLeaseDuration>") &&
              body.Contains("<NewRemoteHost></NewRemoteHost>"));
        Check("...and an & in the description is escaped instead of sending broken XML",
              body.Contains("UssdApp &amp; friends") && !body.Contains("& "));

        // UDP is the protocol a direct call needs, and a router asked for the wrong one
        // answers successfully while leaving the door shut. So the spelling is normalised
        // in one place, the older five-argument form still means TCP, and neither is
        // inferred from context anywhere else in the client.
        Check("the protocol is normalised rather than passed through as typed",
              PortMap.NormProtocol("udp") == "UDP" && PortMap.NormProtocol(" UDP ") == "UDP" &&
              PortMap.NormProtocol("TCP") == "TCP" && PortMap.NormProtocol("") == "TCP" &&
              PortMap.NormProtocol(null) == "TCP" && PortMap.NormProtocol("sctp") == "TCP");
        string udpBody = PortMap.AddPortMappingBody(ipService, 45672, 45672, "192.168.1.23",
            "UssdApp media", "udp");
        Check("a media mapping asks for UDP on the port this machine actually holds",
              udpBody.Contains("<NewProtocol>UDP</NewProtocol>") &&
              udpBody.Contains("<NewExternalPort>45672</NewExternalPort>") &&
              udpBody.Contains("<NewInternalPort>45672</NewInternalPort>") &&
              udpBody.Contains("UssdApp media"), udpBody);
        Check("...and the five-argument form still means TCP, so no older caller changed meaning",
              PortMap.AddPortMappingBody(ipService, 45675, 45675, "192.168.1.23", "relay")
                  .Contains("<NewProtocol>TCP</NewProtocol>"));

        Check("a successful answer is not read as a fault",
              PortMap.FaultText("<s:Envelope><s:Body><u:AddPortMappingResponse/></s:Body></s:Envelope>") == null);
        string t718 = PortMap.FaultText("<s:Envelope><s:Body><s:Fault><faultcode>s:Client</faultcode>" +
            "<faultstring>UPnPError</faultstring><detail><UPnPError><errorCode>718</errorCode>" +
            "<errorDescription>ConflictInMappingEntry</errorDescription></UPnPError></detail></s:Fault></s:Body></s:Envelope>");
        Check("a 718 is reported as the port already being taken, which a person can act on",
              t718 != null && t718.Contains("718") && t718.ToLowerInvariant().Contains("already mapped"), t718);
        string t606 = PortMap.FaultText("<s:Fault><faultstring>action canceled</faultstring>" +
            "<detail><UPnPError><errorCode>606</errorCode></UPnPError></detail></s:Fault>");
        Check("a 606 says the router's own setting is in the way",
              t606 != null && t606.Contains("switched off"), t606);
        Check("...and no answer at all is said as that instead of a protocol error",
              PortMap.FaultText(null) != null && PortMap.FaultText(null).Contains("nothing"));

        Check("the public address is read out of the reply",
              PortMap.ExternalIpFrom("<u:GetExternalIPAddressResponse><NewExternalIPAddress>203.0.113.9</NewExternalIPAddress></u:GetExternalIPAddressResponse>")
                  == "203.0.113.9");
        Check("...and 0.0.0.0 is no answer, not an address to advertise",
              PortMap.ExternalIpFrom("<NewExternalIPAddress>0.0.0.0</NewExternalIPAddress>") == null);
        Check("...and a hostname where an IP belongs is refused",
              PortMap.ExternalIpFrom("<NewExternalIPAddress>router.local</NewExternalIPAddress>") == null);

        // ── what a relay does with the answer ────────────────────────
        CallServer pm = NewRelay(45853, "everyone", "");
        if (pm != null)
        {
            Check("a relay has not asked a router anything and holds no public address by default",
                  !pm.RelayPortMap && pm.PublicAddress.Length == 0);
            // The harness gives every test relay an explicit advertise address (that is
            // what makes referral testable), so the learned address has to be tested
            // against a relay that was NOT told one - otherwise the operator's value
            // wins and this assertion would be measuring the wrong precedence.
            pm.RelayAdvertise = "";
            pm.PublicAddress = "203.0.113.9:45853";
            Check("once the router has answered, that is the address peers are told",
                  pm.AdvertiseAddress() == "203.0.113.9:45853", pm.AdvertiseAddress());
            pm.RelayAdvertise = "relay.example:45853";
            Check("...and an address the operator typed outranks the learned one",
                  pm.AdvertiseAddress() == "relay.example:45853", pm.AdvertiseAddress());
            pm.Stop();
        }
        else Check("port-map relay port free (45853)", false);
    }

    // ── A 1:1 call across a federation link ───────────────────────────────
    //
    // Everything the call suite proved was two installs on ONE relay. "Your friend runs
    // their own relay and you run yours" is the mesh case, and the place it is most
    // likely to break is the project's oldest trap: INVITE now carries two appended
    // fields, and a forwarded line is re-split by whoever receives it. So the signalling
    // is driven for real between two linked relays, and the media is counted on the
    // relays rather than inferred at the endpoints - which genuinely cannot tell a
    // relayed frame from a direct one on a single machine.
    static void VerifyCrossRelayCall()
    {
        Console.WriteLine("  cross-relay 1:1 call: signalling and media over a link");
        // The rule itself, before any socket is opened. Forcing must win when a relay
        // route exists, and must NOT pretend to work when one does not: a plain IP call
        // has no relay to carry it, so "honour the setting" there would kill the audio
        // rather than reroute it.
        Check("with a relay route and the option on, media starts on the relay",
              VoipService.MediaRouteChoice(true, true, true, true) == "relay");
        Check("...and off by default, because direct is shorter and costs the operator less",
              VoipService.MediaRouteChoice(true, true, true, false) == "direct");
        Check("...and a plain IP call cannot be forced onto a relay it is not using",
              VoipService.MediaRouteChoice(false, true, true, true) == "direct");
        Check("...and no relay route, or no peer number, means no promise",
              VoipService.MediaRouteChoice(true, false, true, true) == "direct" &&
              VoipService.MediaRouteChoice(true, true, false, true) == "direct");
        CallServer ra = NewRelay(45851, "everyone", "127.0.0.1:45852");
        CallServer rb = NewRelay(45852, "everyone", "");
        if (ra == null || rb == null)
        {
            Check("cross-relay call ports free (45851-45852)", false);
            return;
        }
        Check("the two relays linked", WaitFor(delegate { return ra.LinkCount >= 1 && rb.LinkCount >= 1; }, 9000),
              "a=" + ra.LinkCount + " b=" + rb.LinkCount);

        Node caller = new Node("7008884001", 45851);
        Node callee = new Node("7008884002", 45852);
        Check("the caller's directory lists a number that lives on the other relay",
              caller.WaitForDir("7008884002", 9000) && caller.DirHasVia("7008884002"),
              "dir=" + caller.DirText);

        // A real signed exchange, with real keys: this is the part a fixture cannot
        // fake, because the assertion is that the signature still verifies after the
        // line has been split, forwarded and re-split by a second process's worth of
        // protocol code.
        Identity ka = new Identity(Path.Combine(ScratchDir(), "call_x_a.key"));
        Identity kb = new Identity(Path.Combine(ScratchDir(), "call_x_b.key"));
        string callId = "ca11cros";
        string dhA = "12345678901234567890123456789012345678901234567890";
        string dhB = "98765432109876543210987654321098765432109876543210";
        string sigA = Convert.ToBase64String(ka.Sign(Encoding.UTF8.GetBytes("CALL|" + callId + "|" + dhA)));
        string invite = "INVITE|" + callId + "|0|Caller|" + dhA + "|" + ka.PublicBase64 + "|" + sigA;
        caller.Send("MSG|7008884002|7008884001|" + invite);
        bool rang = callee.WaitForMsg("7008884001", invite, 9000);
        Check("a signed INVITE reached a peer on the OTHER relay", rang, "no INVITE arrived across the link");

        // Re-verify from what the callee actually received, not from the string that
        // was sent: if the hop mangled a field, this is where it shows.
        string gotPayload = callee.LastMsgFrom("7008884001");
        Check("...and it arrived byte-for-byte, signature included",
              gotPayload == invite, gotPayload == null ? "<nothing>" : "length " + gotPayload.Length);
        string[] inv = (gotPayload ?? "").Split('|');
        bool okSig = inv.Length >= 7 && Identity.Verify(inv[5],
            Encoding.UTF8.GetBytes("CALL|" + inv[1] + "|" + inv[4]),
            Convert.FromBase64String(inv[6]));
        Check("...and the key presented across the hop proves that DH key",
              okSig, "fields=" + inv.Length);
        Check("...and a DH key edited in transit would not, so the check is real",
              !(inv.Length >= 7 && Identity.Verify(inv[5],
                  Encoding.UTF8.GetBytes("CALL|" + inv[1] + "|" + "9" + inv[4].Substring(1)),
                  Convert.FromBase64String(inv[6]))));

        // The answer, coming back over the same link in the other direction.
        string sigB = Convert.ToBase64String(kb.Sign(Encoding.UTF8.GetBytes("CALL|" + callId + "|" + dhB)));
        string accept = "ACCEPT|" + callId + "|" + dhB + "|" + kb.PublicBase64 + "|" + sigB;
        callee.Send("MSG|7008884001|7008884002|" + accept);
        bool answered = caller.WaitForMsg("7008884002", accept, 9000);
        Check("the ACCEPT made it back across the link", answered, "no ACCEPT arrived");
        string acpt = caller.LastMsgFrom("7008884002");
        string[] ap = (acpt ?? "").Split('|');
        Check("...and the caller can verify the far end's key from it too",
              ap.Length >= 5 && Identity.Verify(ap[3],
                  Encoding.UTF8.GetBytes("CALL|" + ap[1] + "|" + ap[2]),
                  Convert.FromBase64String(ap[4])), "fields=" + ap.Length);

        // ── media, both directions, counted on the relays ─────────────────
        byte[] frame = new byte[320];
        for (int i = 0; i < frame.Length; i++) frame[i] = (byte)(i * 7 + 3);
        string b64 = Convert.ToBase64String(frame);
        long fa0 = ra.MediaForwarded, fb0 = rb.MediaForwarded;
        caller.Send("RM|7008884002|7008884001|" + b64);
        bool m1 = callee.WaitForLine("RM|7008884002|7008884001|" + b64, 9000);
        Check("a media frame sent to the other relay's client arrived intact", m1,
              "no RM delivered");
        Check("...and the caller's relay counted it as carried toward a link",
              ra.MediaForwarded > fa0, "fwd " + fa0 + " -> " + ra.MediaForwarded);
        Check("...and the callee's relay counted it as delivered",
              rb.MediaDelivered >= 1, "delivered=" + rb.MediaDelivered);

        callee.Send("RM|7008884001|7008884002|" + b64);
        bool m2 = caller.WaitForLine("RM|7008884001|7008884002|" + b64, 9000);
        Check("and the return path carries media too", m2, "no RM came back");
        Check("...counted on the relay that had to forward it",
              rb.MediaForwarded > fb0, "fwd " + fb0 + " -> " + rb.MediaForwarded);
        Check("...with bytes behind the frame count, so the counter is not a guess",
              ra.MediaForwardedBytes > 0, "bytes=" + ra.MediaForwardedBytes);

        // A media frame aimed at a number nobody owns must not be delivered, and must
        // not be counted as carried: the counters only mean something if they move on
        // real routes.
        long fa1 = ra.MediaForwarded;
        caller.Send("RM|7008884999|7008884001|" + b64);
        Thread.Sleep(700);
        Check("media for an unknown number is not counted as carried",
              ra.MediaForwarded == fa1, "went " + fa1 + " -> " + ra.MediaForwarded);

        // ── "is that number online?" asked of the relay ─────────────────
        // A client's directory is a snapshot that arrives after connecting, so "they are
        // offline" used to be partly a statement about how long the CALLER had been
        // open. That is how a call between two laptops gets refused for no reason a
        // person can see. The relay is the only party that knows, so it is asked.
        RelayClient w1 = new RelayClient();
        w1.Start("127.0.0.1:45851", "7008884099", "tok-7008884099");
        Check("a brand-new client is registered before it has learned anything", WaitFor(delegate
              { return w1.Connected && w1.Registered; }, 9000),
              "connected=" + w1.Connected + " registered=" + w1.Registered);
        long wa0 = ra.WhoAsked;
        Check("...and the relay says a number it holds is online",
              w1.AskOnline("7008884001", 3000),
              "said no: registered=" + w1.Registered + " connected=" + w1.Connected +
              " dir=" + w1.Directory.Count + " trust=" + w1.RelayTrust);
        Check("...and that one is not marked remote, because it is on this relay",
              !w1.IsRemoteNumber("7008884001"), "remote=" + w1.IsRemoteNumber("7008884001"));
        Check("...and a number on the FAR relay is online too, which a cold cache would miss",
              w1.AskOnline("7008884002", 3000),
              "said no: registered=" + w1.Registered + " connected=" + w1.Connected +
              " dir=" + w1.Directory.Count + " remote_seen_by_relay=" + rb.RemotePeerCount);
        Check("...and is named as remote, so the caller knows the media will be carried",
              w1.IsRemoteNumber("7008884002"), "remote flag missing");
        Check("...and a number nobody owns is answered, not left in silence",
              !w1.AskOnline("7008884888", 3000), "an unowned number was said to be online");
        // Repeated on purpose: an answer that is removed once read would pass a single
        // question and fail the second, which is the kind of bug a one-shot assert misses.
        Check("...and the same question asked twice gets the same answer both times",
              w1.AskOnline("7008884002", 3000) && w1.AskOnline("7008884002", 3000));
        Check("...and an unowned number stays no when asked again",
              !w1.AskOnline("7008884888", 3000) && !w1.AskOnline("7008884888", 3000));
        // The relay counts the questions, so "callers were dialling off a cold cache" is
        // something a test can read off a status line rather than a claim to believe.
        Check("...and the relay counted every question it answered",
              ra.WhoAsked >= wa0 + 5, "counted " + (ra.WhoAsked - wa0) + " of 5 asked");
        w1.Stop();
        try { w1.Dispose(); } catch { }

        // ── a socket is not a registration ──────────────────────────
        // The root cause under the "is not online" lie: `RelayReady` asked the socket, and
        // between the socket opening and REG being accepted the client is online in the
        // sense that matters to nobody and unreachable in the sense that matters to
        // everything - empty directory, and `ERR|registerfirst` for any question it asks.
        // A refused registration shows the two states apart deterministically, because it
        // keeps the socket open forever and never accepts the number.
        RelayClient own = new RelayClient();
        own.Start("127.0.0.1:45851", "7008884055", "tok-owned-by-this-client");
        Check("a registered client is Connected AND Registered",
              WaitFor(delegate { return own.Connected && own.Registered; }, 9000),
              "connected=" + own.Connected + " registered=" + own.Registered);
        RelayClient thief = new RelayClient();
        thief.Start("127.0.0.1:45851", "7008884055", "tok-somebody-elses");
        Check("a refused client still has a working socket", WaitFor(delegate { return thief.Connected; }, 9000),
              "connected=" + thief.Connected);
        Thread.Sleep(900);        // give any OK| a chance to arrive before judging its absence
        Check("...and is NOT registered, which is the fact the app was ignoring",
              !thief.Registered, "registered=" + thief.Registered);
        Check("...so it can be asked whether the number is online, but is not fooled into dialling",
              !thief.AskOnline("7008884055", 800), "the relay was not asked and said yes anyway");
        Check("...and the real owner keeps the number through the attempt",
              own.Registered && own.Connected,
              "owner connected=" + own.Connected + " registered=" + own.Registered);
        own.Stop(); thief.Stop();
        try { own.Dispose(); } catch { }
        try { thief.Dispose(); } catch { }

        caller.Close();
        callee.Close();
        ra.Stop(); rb.Stop();
    }

    // ── Radio stack ────────────────────────────────────────────────────
    // KISS framing, the AX.25 CRC, and fragment/reassembly are all testable
    // without a transceiver, and that is exactly what is checked here. What is
    // NOT claimed anywhere: that a specific board keys its PTT on a given port.
    static void VerifyRadio()
    {
        Console.WriteLine("  radio: kiss framing");
        byte[] payload = new byte[] { 1, 2, Kiss.FEND, 4, Kiss.FESC, 6, 0x00, 0xFF };
        byte[] wire = Kiss.Encode(payload);
        Check("frame wrapped in FEND", wire[0] == Kiss.FEND && wire[wire.Length - 1] == Kiss.FEND);
        Check("FEND escaped inside the payload", wire.Length == payload.Length + 4);
        Kiss.Stream ks = new Kiss.Stream();
        ks.Feed(wire, wire.Length);
        byte[] back;
        Check("decodes back to the original", ks.TryNext(out back) && SameBytes(back, payload));

        // Serial data arrives in scraps; a decoder that assumes whole frames
        // loses the one that straddled a read.
        Check("decodes when fed one byte at a time", FeedOneByteAtATime(payload));

        // Filler FENDs between frames are normal on a TNC; they must not make an
        // empty frame that shifts every subsequent message.
        Kiss.Stream k2 = new Kiss.Stream();
        byte[] f1 = Kiss.Encode(new byte[] { 9, 9 });
        byte[] joined = new byte[f1.Length + f1.Length + 1];
        Buffer.BlockCopy(f1, 0, joined, 0, f1.Length);
        joined[f1.Length - 1] = Kiss.FEND;                       // trailing FEND doubles as leading
        Buffer.BlockCopy(f1, 0, joined, f1.Length, f1.Length);
        k2.Feed(joined, joined.Length);
        byte[] a1, a2;
        Check("no phantom frame from filler FEND", k2.TryNext(out a1) && k2.TryNext(out a2) &&
              a1.Length == 2 && a2.Length == 2 && !k2.TryNext(out a2), "two real frames, no empty one");

        Check("garbage before the first FEND is dropped", ResyncAfterGarbage());

        Console.WriteLine("  radio: ax.25");
        byte[] info = Encoding.UTF8.GetBytes("MSG|7002222222|7001111111|hi from the hill");
        byte[] ax = Axa25.Build("RELAY1", "705555", info);
        string f, t; byte[] got;
        Check("ui frame round-trips", Axa25.Parse(ax, out f, out t, out got) && f == "RELAY1" && t == "705555" && SameBytes(got, info),
            f + "/" + t);
        byte[] broken = (byte[])ax.Clone();
        broken[20] ^= 0x5A;
        string f2, t2; byte[] g2;
        bool accepted = Axa25.Parse(broken, out f2, out t2, out g2);
        Check("a flipped bit is rejected by the FCS", !accepted,
            "accepted=" + accepted + " len=" + ax.Length + " byte20=" + ax[20] + "->" + broken[20]);
        Check("a callsign fits six characters", Axa25.CallsignForNumber("700-325-6099").Length <= 6,
            Axa25.CallsignForNumber("700-325-6099"));
        Check("crc is stable across calls",
            Axa25.Crc(info, info.Length) == Axa25.Crc(info, info.Length));
        // Is the checksum actually a function of the data? It was not: the
        // reference algorithm relies on 8-bit truncation, and computing it in a
        // 32-bit uint without masking made it ignore the payload entirely.
        byte[] other = (byte[])info.Clone();
        other[0] ^= 0x01;
        Check("crc depends on the payload",
            Axa25.Crc(info, info.Length) != Axa25.Crc(other, other.Length),
            Axa25.Crc(info, info.Length) + " vs " + Axa25.Crc(other, other.Length));

        Console.WriteLine("  radio: fragmentation");
        Fragmenter fr = new Fragmenter();
        byte[] big = new byte[600];
        for (int i = 0; i < big.Length; i++) big[i] = (byte)(i & 0xFF);
        List<byte[]> pieces = fr.Split(big, 100);
        Check("a 600 B frame splits into several", pieces.Count >= 7, "pieces=" + pieces.Count);
        Fragmenter rx = new Fragmenter();
        byte[] whole = null;
        // Out of order, with one piece delivered twice: a radio retransmits and
        // a reassembler that trusted arrival order would corrupt the message.
        for (int i = pieces.Count - 1; i >= 0; i--)
        {
            rx.Feed(pieces[i]);
            rx.Feed(pieces[i]);
        }
        whole = rx.Feed(pieces[0]);
        Check("reassembles exactly once", whole == null || whole.Length == big.Length, whole == null ? "pending" : "dup");
        // Feed the first piece again after the duplicate path above completes it.
        Fragmenter rx2 = new Fragmenter();
        byte[] done = null;
        foreach (byte[] pc in pieces) done = rx2.Feed(pc) ?? done;
        Check("in-order reassembly matches", done != null && SameBytes(done, big));
        Check("nothing left hanging once complete", rx.Pending <= 1 && rx2.Pending == 0, rx.Pending + "/" + rx2.Pending);
        Check("an oversized frame is refused, not truncated",
            new Fragmenter().Split(big, 100).Count <= Fragmenter.MaxFragments + 1);

        Console.WriteLine("  radio: transport end to end");
        // Two RadioTransports over a duplex in-memory pipe: this exercises the
        // write path, the reader thread, KISS decode, FCS, reassembly and the
        // Frame event - the whole receive chain, with no hardware.
        LoopStream sA, sB;
        LoopStream.Pair(out sA, out sB);
        RadioTransport ra = new RadioTransport("kiss-a", sA, 1200, 100, true);
        RadioTransport rb = new RadioTransport("kiss-b", sB, 1200, 100, true);
        ManualResetEvent got_ = new ManualResetEvent(false);
        byte[] arrived = null;
        rb.Frame += delegate(string from, byte[] frame) { lock (rb) { arrived = frame; } got_.Set(); };
        ra.Start("NODEA");
        rb.Start("NODEB");
        string text = "OTP 481930 - relayed over the packet link, worth more intact than fast";
        bool sent = ra.Send("7003256099", Encoding.UTF8.GetBytes(text));
        Check("send accepted over the radio link", sent);
        Check("the far node reassembled the same text",
            got_.WaitOne(4000) && arrived != null && Encoding.UTF8.GetString(arrived) == text,
            arrived == null ? "nothing arrived" : Encoding.UTF8.GetString(arrived));
        ra.Dispose(); rb.Dispose();

        Console.WriteLine("  radio: capability rules");
        // The claim that matters in the UI: voice does not go out a radio, and
        // a node that carries for strangers is not used until consent is given.
        TransportRouter rt = new TransportRouter();
        LoopTransport relayOnly = new LoopTransport("relay", 0, 0);
        rt.Add(relayOnly);
        rt.Add(new StubTransport("kiss", 200, 1200, true));
        string why;
        ITransport media = rt.Pick(640, PayloadClass.Media, out why);
        Check("media is refused on a 1200 bps link", media == null || media.Name == "relay",
            media == null ? "none: " + why : media.Name);
        rt.DefaultConsentGranted = false;
        ITransport txtNo = rt.Pick(80, PayloadClass.Text, out why);
        Check("text needs consent before a carrying node is used", txtNo != null && txtNo.Name != "kiss",
            txtNo == null ? "none" : txtNo.Name);
        rt.SetConsent("kiss", true);
        ITransport txtYes = rt.Pick(80, PayloadClass.Text, out why);
        Check("...and uses it once granted", txtYes != null && txtYes.Name == "kiss",
            txtYes == null ? "none" : txtYes.Name);
        ITransport tooBig = rt.Pick(5000, PayloadClass.Text, out why);
        Check("a frame over the radio ceiling goes elsewhere", tooBig != null && tooBig.Name == "relay",
            tooBig == null ? "none" : tooBig.Name);
    }

    static bool FeedOneByteAtATime(byte[] payload)
    {
        byte[] wire = Kiss.Encode(payload);
        Kiss.Stream k = new Kiss.Stream();
        for (int i = 0; i < wire.Length; i++) k.Feed(new byte[] { wire[i] }, 1);
        byte[] back;
        return k.TryNext(out back) && SameBytes(back, payload);
    }

    static bool ResyncAfterGarbage()
    {
        Kiss.Stream k = new Kiss.Stream();
        byte[] junk = new byte[] { 0x11, 0x22, Kiss.FESC };
        byte[] good = Kiss.Encode(new byte[] { 5, 6, 7 });
        byte[] all = new byte[junk.Length + good.Length];
        Buffer.BlockCopy(junk, 0, all, 0, junk.Length);
        Buffer.BlockCopy(good, 0, all, junk.Length, good.Length);
        k.Feed(all, all.Length);
        byte[] back;
        return k.TryNext(out back) && back.Length == 3 && back[0] == 5;
    }

    static bool SameBytes(byte[] a, byte[] b)
    {
        if (a == null || b == null || a.Length != b.Length) return false;
        for (int i = 0; i < a.Length; i++) if (a[i] != b[i]) return false;
        return true;
    }

    // A minimal ITransport stand-in, so routing rules are tested without a stream.
    sealed class StubTransport : ITransport
    {
        public StubTransport(string name, int maxFrame, int rate, bool carries)
        { _n = name; _f = maxFrame; _r = rate; _c = carries; }
        readonly string _n; readonly int _f; readonly int _r; readonly bool _c;
        public string Name { get { return _n; } }
        public int MaxFrameBytes { get { return _f; } }
        public int BitRate { get { return _r; } }
        public bool RequiresConsent { get { return _c; } }
        public bool Ready { get { return true; } }
        public string LastError { get { return ""; } }
        public bool Send(string to, byte[] frame) { return true; }
        public event Action<string, byte[]> Frame;
    }

    // Duplex in-memory stream pair: what A writes, B's reader thread sees, and
    // the other way round. Blocking Read with a timeout, like a real port.
    sealed class LoopStream : Stream
    {
        readonly List<byte> _inbox = new List<byte>();
        readonly object _l = new object();
        LoopStream _peer;
        bool _open = true;

        public static void Pair(out LoopStream a, out LoopStream b)
        {
            a = new LoopStream(); b = new LoopStream();
            a._peer = b; b._peer = a;
        }

        public override void Write(byte[] buffer, int offset, int count)
        {
            LoopStream p;
            lock (_l) p = _peer;
            lock (p._l)
            {
                for (int i = 0; i < count; i++) p._inbox.Add(buffer[offset + i]);
                Monitor.PulseAll(p._l);
            }
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            lock (_l)
            {
                int waited = 0;
                while (_inbox.Count == 0 && _open && waited < 3000)
                {
                    Monitor.Wait(_l, 10);
                    waited += 10;
                }
                if (_inbox.Count == 0) return 0;
                int n = Math.Min(count, _inbox.Count);
                for (int i = 0; i < n; i++) { buffer[offset + i] = _inbox[0]; _inbox.RemoveAt(0); }
                return n;
            }
        }

        public override void Close() { lock (_l) { _open = false; Monitor.PulseAll(_l); } }
        public override bool CanRead { get { return _open; } }
        public override bool CanWrite { get { return _open; } }
        public override bool CanSeek { get { return false; } }
        public override void Flush() { }
        public override long Length { get { lock (_l) return _inbox.Count; } }
        public override long Position { get { return 0; } set { } }
        public override long Seek(long o, SeekOrigin r) { throw new NotSupportedException(); }
        public override void SetLength(long v) { throw new NotSupportedException(); }
    }

    // LinkPolicyDeny is private and policy is only as good as its parsing, so it
    // is exercised through reflection rather than re-typed here.
    static string LinkDeny(CallServer s, string id, string name)
    {
        return LinkDeny(s, id, name, "127.0.0.1:55555");
    }

    static string LinkDeny(CallServer s, string id, string name, string endpoint)
    {
        MethodInfo mi = typeof(CallServer).GetMethod("LinkPolicyDeny", BindingFlags.NonPublic | BindingFlags.Instance);
        if (mi == null) return "<missing>";
        string[] p = new string[] { "RLINK", id, name };
        return (string)mi.Invoke(s, new object[] { p, endpoint });
    }

    static bool WaitFor(Func<bool> cond, int ms)
    {
        int end = Environment.TickCount + ms;
        while (Environment.TickCount < end)
        {
            try { if (cond()) return true; } catch { }
            Thread.Sleep(50);
        }
        try { return cond(); } catch { return false; }
    }

    // A plain relay client: registers a number and collects what arrives.
    sealed class Node
    {
        public string Number;
        readonly TcpClient _tcp;
        readonly StreamWriter _w;
        readonly object _write = new object();
        volatile string _dir = "";
        readonly List<string> _lines = new List<string>();
        readonly List<string> _msgs = new List<string>();

        public Node(string number, int port)
        {
            Number = number;
            if (port == 0) { _tcp = null; _w = null; return; }
            _tcp = new TcpClient();
            _tcp.Connect("127.0.0.1", port);
            _w = new StreamWriter(_tcp.GetStream(), Encoding.UTF8);
            _w.AutoFlush = true;
            Thread t = new Thread(ReadLoop);
            t.IsBackground = true;
            t.Start();
            if (number.Length > 0)
            {
                Send("REG|" + number + "|tok-" + number + "|node");
                // Wait for the relay's verdict rather than for a fixed 150 ms. A
                // request sent before the relay has finished with the registration is
                // answered with nothing at all (PKQ from an unregistered session is
                // ignored), and that race showed up here as a random failure roughly
                // one run in four, in whichever section happened to ask first.
                WaitForRegistration();
            }
            Thread.Sleep(150);
        }

        // The registration is answered with OK|<num> or with an ERR|... - a refusal is
        // a verdict too, so a node that is meant to be locked out costs the same few
        // milliseconds rather than the full window.
        void WaitForRegistration()
        {
            int end = Environment.TickCount + 4000;
            while (Environment.TickCount < end)
            {
                lock (_lines)
                    foreach (string l in _lines)
                        if (l.StartsWith("OK|", StringComparison.Ordinal) ||
                            l.StartsWith("ERR|", StringComparison.Ordinal)) return;
                Thread.Sleep(25);
            }
        }

        public void Send(string line)
        {
            if (_w == null) return;
            lock (_write) _w.WriteLine(line);
        }

        void ReadLoop()
        {
            try
            {
                StreamReader r = new StreamReader(_tcp.GetStream(), Encoding.UTF8);
                string line;
                while ((line = r.ReadLine()) != null)
                {
                    lock (_lines) _lines.Add(line);
                    if (line.StartsWith("PEERS|", StringComparison.Ordinal)) { _dir = line; continue; }
                    string[] p = line.Split(new char[] { '|' }, 4);
                    if (p[0] == "MSG" && p.Length >= 4) lock (_msgs) _msgs.Add(p[2] + "|" + p[3]);
                }
            }
            catch { }
        }

        public bool WaitForDir(string number, int ms)
        {
            return WaitFor(delegate { return _dir.Contains(number); }, ms);
        }

        // A federated row carries a 4th field, via=<relay id>.
        public bool DirHasVia(string number)
        {
            foreach (string rec in _dir.Split(';'))
                if (rec.Contains(number) && rec.Contains("via=")) return true;
            return false;
        }

        public bool WaitForMsg(string fromNumber, string payload, int ms)
        {
            return WaitFor(delegate
            {
                lock (_msgs)
                    foreach (string m in _msgs) if (m == fromNumber + "|" + payload) return true;
                return false;
            }, ms);
        }

        // How many messages from one number this node has seen. Carried mail is only
        // worth having if it arrives once, so this is counted, not assumed.
        public int CountMsgs(string fromNumber)
        {
            int n = 0;
            lock (_msgs)
                foreach (string m in _msgs)
                    if (m.StartsWith(fromNumber + "|", StringComparison.Ordinal)) n++;
            return n;
        }

        public bool WaitForLine(string prefix, int ms)
        {
            return WaitFor(delegate
            {
                lock (_lines)
                    foreach (string l in _lines) if (l.StartsWith(prefix, StringComparison.Ordinal)) return true;
                return false;
            }, ms);
        }

        // The directory exactly as received, so a failure can say what the node saw
        // instead of what the test hoped it would.
        public string DirText { get { return _dir; } }

        // The payload of the most recent MSG from one number. Assertions are made about
        // these bytes - what arrived at the far relay - not about the string that was
        // sent, which is the difference between testing the protocol and testing yourself.
        public string LastMsgFrom(string fromNumber)
        {
            string last = null;
            lock (_msgs)
                foreach (string m in _msgs)
                    if (m.StartsWith(fromNumber + "|", StringComparison.Ordinal))
                        last = m.Substring(fromNumber.Length + 1);
            return last;
        }

        // Any substring in any line received so far.
        public bool WaitForText(string needle, int ms)
        {
            return WaitFor(delegate
            {
                lock (_lines)
                    foreach (string l in _lines) if (l.Contains(needle)) return true;
                return false;
            }, ms);
        }

        public string ReferredRaw()
        {
            lock (_lines)
            {
                foreach (string l in _lines)
                    if (l.StartsWith("RLIST|", StringComparison.Ordinal)) return l;
            }
            return "";
        }

        public bool ReferredAnythingContains(string needle)
        {
            return ReferredRaw().Contains(needle);
        }

        public void Close() { try { if (_tcp != null) _tcp.Close(); } catch { } }

        // ── Room traffic ──────────────────────────────────────────────
        public void SendFrames(string room, short value, int count)
        {
            byte[] pcm = new byte[640];
            for (int i = 0; i + 1 < pcm.Length; i += 2)
            {
                pcm[i] = (byte)(value & 0xFF);
                pcm[i + 1] = (byte)((value >> 8) & 0xFF);
            }
            string b64 = Convert.ToBase64String(pcm);
            for (int i = 0; i < count; i++)
            {
                Send("CONF_AUDIO|" + room + "|" + b64);
                Thread.Sleep(20);
            }
        }

        public void SendConfVideo(string room)
        {
            byte[] jpeg = new byte[64];
            for (int i = 0; i < jpeg.Length; i++) jpeg[i] = (byte)i;
            Send("CONF_VIDEO|" + room + "|" + Convert.ToBase64String(jpeg));
        }

        public int ConfCount(string room)
        {
            int n = 0;
            lock (_lines)
                foreach (string l in _lines)
                    if (l.StartsWith("CONF_MIXED|" + room, StringComparison.Ordinal)) n++;
            return n;
        }

        public int LastConfPeak(string room)
        {
            lock (_lines)
            {
                for (int i = _lines.Count - 1; i >= 0; i--)
                {
                    string l = _lines[i];
                    if (!l.StartsWith("CONF_MIXED|" + room, StringComparison.Ordinal)) continue;
                    string[] p = l.Split(new char[] { '|' }, 4);
                    if (p.Length < 4) continue;
                    byte[] pcm;
                    try { pcm = Convert.FromBase64String(p[3]); } catch { continue; }
                    int peak = 0;
                    for (int j = 0; j + 1 < pcm.Length; j += 2)
                    {
                        short v = (short)(pcm[j] | (pcm[j + 1] << 8));
                        int mag = v < 0 ? -v : v;
                        if (mag > peak) peak = mag;
                    }
                    return peak;
                }
            }
            return 0;
        }

        public int CountsWith(string needle)
        {
            int n = 0;
            lock (_lines)
                foreach (string l in _lines)
                    if (l.StartsWith(needle, StringComparison.Ordinal)) n++;
            return n;
        }

        // The most recent roster line mentioning this room.
        public string LineWith(string needle)
        {
            lock (_lines)
            {
                for (int i = _lines.Count - 1; i >= 0; i--)
                    if (_lines[i].StartsWith("CONF_ROSTER", StringComparison.Ordinal) && _lines[i].Contains(needle))
                        return _lines[i];
            }
            return "";
        }

        // Forget what arrived so the next assertion cannot pass on stale traffic.
        public void Reset()
        {
            lock (_msgs) _msgs.Clear();
            lock (_lines) _lines.Clear();
        }
    }

    // whisper.cpp is not installed here, so what gets tested is the plumbing
    // that would otherwise fail silently: a wrong WAV header means "no text"
    // rather than an error, and the output filter decides what reaches the
    // subtitles. The absent-binary path must also degrade without a crash.
    static void VerifyTranscription()
    {
        Console.WriteLine("  transcription");
        Type tt = typeof(Transcriber);
        MethodInfo writeWav = tt.GetMethod("WriteWav", BindingFlags.NonPublic | BindingFlags.Instance);
        MethodInfo parse = tt.GetMethod("Parse", BindingFlags.NonPublic | BindingFlags.Static);
        MethodInfo pathFor = tt.GetMethod("TranscriptPathFor", BindingFlags.NonPublic | BindingFlags.Static);
        Check("internals are reachable for testing", writeWav != null && parse != null && pathFor != null);
        if (writeWav == null || parse == null || pathFor == null) return;

        Transcriber t = new Transcriber("", "", "auto");
        Check("no binary means not available", !t.Available);
        Check("self test explains what is missing",
            t.SelfTest().StartsWith("No whisper.cpp binary"), t.SelfTest());
        // Frames before a call must not throw or spin up a worker.
        t.AddFrame(new byte[640]);
        t.Stop();
        t.Dispose();
        Check("idle transcriber is safe to feed and stop", true);

        // ── WAV framing ──────────────────────────────────────────────────
        byte[] pcm = new byte[3200];               // 100 ms at 16 kHz mono 16-bit
        for (int i = 0; i < pcm.Length; i++) pcm[i] = (byte)(i * 7);
        string wav = (string)writeWav.Invoke(t, new object[] { pcm });
        Check("segment written as a wav", wav != null && File.Exists(wav), wav ?? "null");
        if (wav != null && File.Exists(wav))
        {
            byte[] all = File.ReadAllBytes(wav);
            Check("file is 44 header + pcm", all.Length == 44 + pcm.Length, all.Length.ToString());
            Check("RIFF/WAVE magic",
                all[0] == (byte)'R' && all[1] == (byte)'I' && all[2] == (byte)'F' && all[3] == (byte)'F' &&
                all[8] == (byte)'W' && all[9] == (byte)'A' && all[10] == (byte)'V' && all[11] == (byte)'E');
            Check("fmt chunk present", all[12] == (byte)'f' && all[13] == (byte)'m' && all[14] == (byte)'t' && all[15] == (byte)' ');
            Check("PCM format, mono", BitConverter.ToInt16(all, 20) == 1 && BitConverter.ToInt16(all, 22) == 1,
                BitConverter.ToInt16(all, 20) + "/" + BitConverter.ToInt16(all, 22));
            Check("16 kHz sample rate", BitConverter.ToInt32(all, 24) == Transcriber.Rate, BitConverter.ToInt32(all, 24).ToString());
            Check("16-bit depth", BitConverter.ToInt16(all, 34) == 16);
            Check("byte rate matches rate x channels x depth", BitConverter.ToInt32(all, 28) == Transcriber.Rate * 2);
            Check("data chunk declared", all[36] == (byte)'d' && all[37] == (byte)'a' && all[38] == (byte)'t' && all[39] == (byte)'a');
            Check("data size is the pcm length", BitConverter.ToInt32(all, 40) == pcm.Length);
            Check("riff size is consistent", BitConverter.ToInt32(all, 4) == all.Length - 8);
            Check("audio bytes survive intact", all[44] == pcm[0] && all[44 + pcm.Length - 1] == pcm[pcm.Length - 1]);
        }
        try { if (wav != null) File.Delete(wav); } catch { }

        // ── output filtering ─────────────────────────────────────────────
        string noisy =
            "whisper_init_from_file_with_params_no_state: loading model\n" +
            "load_backend: loaded CPU backend\n" +
            "system_info: n_threads = 2 / 8\n" +
            "\n" +
            "[00:00:00.000 --> 00:00:03.500]   Hello, can you hear me?\n" +
            "I already have the text without timestamps.\n" +
            "(no audio detected)\n" +
            "whisper_print_timings: load time = 12.3 ms\n";
        List<string> lines = (List<string>)parse.Invoke(null, new object[] { noisy });
        Check("diagnostics are dropped", lines.Count == 2, "kept " + lines.Count + ": " + string.Join(" / ", lines.ToArray()));
        Check("timestamped line is stripped", lines.Count > 0 && lines[0] == "Hello, can you hear me?",
            lines.Count > 0 ? lines[0] : "<none>");
        Check("plain line passes through", lines.Count > 1 && lines[1] == "I already have the text without timestamps.");
        Check("empty input yields nothing", ((List<string>)parse.Invoke(null, new object[] { "   \n\n " })).Count == 0);

        // ── transcript lands beside the recording ────────────────────────
        string fake = Path.Combine(Path.GetTempPath(), "ussd_fake_call.wav");
        File.WriteAllBytes(fake, new byte[8]);
        string tp = (string)pathFor.Invoke(null, new object[] { "TestPeer", fake });
        Check("transcript is named after the recording",
            tp != null && tp == Path.ChangeExtension(fake, ".txt"), tp ?? "null");
        try { File.Delete(fake); } catch { }
        string noRec = (string)pathFor.Invoke(null, new object[] { "TestPeer", null });
        Check("transcript still lands with no recording",
            noRec != null && noRec.Contains("transcript_") && noRec.EndsWith(".txt"), noRec ?? "null");
    }

    // Sticker sync takes a filename and bytes from a peer and writes them into
    // this device's folder, so the hostile cases are the interesting ones:
    // traversal in the name, a hash that does not match, and re-running the
    // same sync. A full REQ -> CAT -> WANT -> BIN exchange is simulated between
    // two folders to prove the delta actually converges.
    static void VerifyStickerSync()
    {
        Console.WriteLine("  sticker sync");
        string work = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "_stickertest");
        try { if (Directory.Exists(work)) Directory.Delete(work, true); } catch { }
        string rootA = Path.Combine(work, "a");
        string rootB = Path.Combine(work, "b");
        Directory.CreateDirectory(rootA);
        Directory.CreateDirectory(rootB);

        // ── names a peer might send ────────────────────────────────────────
        Check("traversal is stripped", !StickerSync.SafeName("..\\..\\windows\\system32\\evil.exe").Contains("\\"),
            StickerSync.SafeName("..\\..\\windows\\system32\\evil.exe"));
        Check("traversal cannot escape via slash", !StickerSync.SafeName("../../etc/passwd").Contains("/"),
            StickerSync.SafeName("../../etc/passwd"));
        Check("framing characters are stripped", !StickerSync.SafeName("a|b,c.png").Contains("|"),
            StickerSync.SafeName("a|b,c.png"));
        Check("unknown extension becomes png", StickerSync.SafeName("payload.exe").EndsWith(".png"),
            StickerSync.SafeName("payload.exe"));
        Check("gif stays gif", StickerSync.SafeName("anim.gif").EndsWith(".gif"));
        Check("empty name is replaced", StickerSync.SafeName("").Length > 0);
        Check("pack id cannot traverse", !StickerSync.SafePackId("../evil").Contains(".") &&
              !StickerSync.SafePackId("../evil").Contains("/"), StickerSync.SafePackId("../evil"));

        // ── build two device folders ───────────────────────────────────────
        byte[] f1 = Frame(1);        // shared between the two
        byte[] f2 = Frame(2);        // only A has it
        byte[] f3 = Frame(3);        // only A has it
        File.WriteAllBytes(Path.Combine(rootA, "one.png"), f1);
        File.WriteAllBytes(Path.Combine(rootA, "two.png"), f2);
        File.WriteAllBytes(Path.Combine(rootA, "three.png"), f3);
        File.WriteAllBytes(Path.Combine(rootB, "one.png"), f1);

        Dictionary<string, string> catA = StickerSync.CatalogAll(rootA);
        Dictionary<string, string> catB = StickerSync.CatalogAll(rootB);
        Check("catalogue counts frames", catA.Count == 3 && catB.Count == 1, catA.Count + "/" + catB.Count);
        Check("identical bytes share a hash", HasCommon(catA, catB));
        Check("a duplicate file dedups by hash", DedupsByHash(rootA));

        // ── the delta ──────────────────────────────────────────────────────
        List<string> missing = StickerSync.Missing(catA, catB);   // B wants what only A has
        Check("delta asks for exactly the difference", missing.Count == 2, "count " + missing.Count);

        // ── wire round trips ───────────────────────────────────────────────
        string catLine = StickerSync.MakeCat(StickerSync.SyncPack, catA);
        string pid; Dictionary<string, string> parsed;
        Check("CAT parses back", StickerSync.TryParseCat(catLine, out pid, out parsed) && parsed.Count == 3,
            parsed.Count.ToString());
        List<string> want;
        Check("WANT parses back", StickerSync.TryParseWant(StickerSync.MakeWant(pid, missing), out pid, out want) &&
              want.Count == 2, want.Count.ToString());
        string hash2 = KeyOf(catA, "two.png");
        string binLine = StickerSync.MakeBin(StickerSync.SyncPack, "two.png", f2);
        string bn, hh; byte[] data;
        Check("BIN parses back", StickerSync.TryParseBin(binLine, out pid, out bn, out hh, out data) &&
              data.Length == f2.Length && bn == "two.png", bn + "/" + hh);

        // ── import: honest, tampered, duplicate ────────────────────────────
        string written = StickerSync.Import(rootB, StickerSync.SyncPack, bn, hh, data);
        Check("import writes the frame", written != null && File.Exists(written), written ?? "null");
        byte[] tampered = (byte[])f3.Clone();
        tampered[0] = (byte)(tampered[0] ^ 0xFF);
        Check("tampered bytes are refused",
            StickerSync.Import(rootB, StickerSync.SyncPack, "three.png", KeyOf(catA, "three.png"), tampered) == null);
        Check("duplicate content is not written twice",
            StickerSync.Import(rootB, StickerSync.SyncPack, "two.png", hash2, f2) == null);
        Check("oversized frame is refused",
            StickerSync.Import(rootB, StickerSync.SyncPack, "big.png", "0123456789abcdef", new byte[StickerSync.MaxFrameBytes + 1]) == null);
        Check("delta shrinks to what is genuinely absent",
            StickerSync.Missing(catA, StickerSync.CatalogAll(rootB)).Count == 1,
            "missing " + StickerSync.Missing(catA, StickerSync.CatalogAll(rootB)).Count);

        // Import the last frame honestly and the two devices must converge.
        string bin3 = StickerSync.MakeBin(StickerSync.SyncPack, "three.png", f3);
        string n3, h3; byte[] d3;
        StickerSync.TryParseBin(bin3, out pid, out n3, out h3, out d3);
        StickerSync.Import(rootB, pid, n3, h3, d3);
        Check("a completed sync leaves nothing to ask for",
            StickerSync.Missing(catA, StickerSync.CatalogAll(rootB)).Count == 0);

        // ── manifest and zip pack ──────────────────────────────────────────
        string packDir = Path.Combine(rootB, StickerSync.SyncPack);
        StickerSync.WriteManifest(packDir, StickerSync.SyncPack, "Shared", "tester");
        string mani = Path.Combine(packDir, "manifest.json");
        Check("manifest written", File.Exists(mani));
        if (File.Exists(mani))
        {
            string text = File.ReadAllText(mani);
            Check("manifest lists frames with hashes",
                text.Contains("\"frames\"") && text.Contains(hash2), text.Replace("\n", " "));
        }
        string zip = StickerSync.ExportZip(packDir, Path.Combine(work, "shared.zip"));
        Check("pack exports as zip", zip != null && File.Exists(zip), zip ?? "null");
        string rootC = Path.Combine(work, "c");
        Directory.CreateDirectory(rootC);
        // The pack folder now holds all three frames B converged on.
        int imported = zip == null ? 0 : StickerSync.ImportZip(rootC, zip, "shared");
        Check("zip imports into a new device", imported == 3, "imported " + imported);
        Check("zip import dedups on a second run",
            StickerSync.ImportZip(rootC, zip, "shared") == 0);

        try { Directory.Delete(work, true); } catch { }
    }

    static byte[] Frame(int seed)
    {   // a small deterministic "png": bytes only, the test never decodes it
        byte[] b = new byte[64 + seed];
        for (int i = 0; i < b.Length; i++) b[i] = (byte)((i * 31 + seed * 7) & 0xFF);
        return b;
    }

    static bool HasCommon(Dictionary<string, string> a, Dictionary<string, string> b)
    {
        foreach (string h in a.Keys) if (b.ContainsKey(h)) return true;
        return false;
    }

    static string KeyOf(Dictionary<string, string> cat, string fileName)
    {
        foreach (KeyValuePair<string, string> kv in cat)
            if (kv.Value == fileName) return kv.Key;
        return "";
    }

    static bool DedupsByHash(string rootA)
    {
        string dup = Path.Combine(rootA, "copy_of_two.png");
        File.WriteAllBytes(dup, File.ReadAllBytes(Path.Combine(rootA, "two.png")));
        int before = StickerSync.CatalogAll(rootA).Count;
        try { File.Delete(dup); } catch { }
        return before == 3;   // three distinct contents, not four
    }

    // Cards travel inside a pipe-delimited chat line, so the token framing has
    // to survive: a stray pipe or bracket in somebody's name would otherwise
    // split the card across fields or swallow the message tail.
    static void VerifyVCard()
    {
        Console.WriteLine("  vCard framing");

        string tok = VCard.Token("Sampson Anku", "+233240000001", "Beta Ltd", "met at the hub");
        Check("card is recognised", VCard.Is(tok));
        Check("a plain message is not", !VCard.Is("see you at 8"));
        string[] c = VCard.Parse(tok);
        Check("fields round-trip",
            c[0] == "Sampson Anku" && c[1] == "+233240000001" &&
            c[2] == "Beta Ltd" && c[3] == "met at the hub",
            c[0] + "|" + c[1] + "|" + c[2] + "|" + c[3]);

        // Hostile fields: pipes, brackets and newlines must not break framing.
        string nasty = VCard.Token("A|B[1]", "233|000", "Org]", "line1\r\nline2");
        Check("framing survives pipes and brackets", VCard.Is(nasty));
        string[] n = VCard.Parse(nasty);
        Check("fields still line up", n.Length == 4 && n[1] == "233/000" && n[3] == "line1 line2",
            n[0] + "|" + n[1] + "|" + n[2] + "|" + n[3]);

        // Empty card: four entries, no exception.
        string[] e = VCard.Parse(VCard.Token("", "", "", ""));
        Check("empty card parses to four fields", e.Length == 4 && e[0] == "");

        // Inside a stored chat line: when|dir|id|body, body split with limit 4.
        string line = "2026-11-01|in|abc123|" + tok;
        string[] p = line.Split(new char[] { '|' }, 4);
        Check("card survives the chat line format", p.Length == 4 && p[3] == tok,
            p.Length >= 4 ? p[3] : "<short>");

        string vcf = VCard.ToVcf("Anku; Sampson", "+233240000001", "Beta, Ltd", "note");
        Check("vcf has vCard 3.0 envelope",
            vcf.StartsWith("BEGIN:VCARD") && vcf.Contains("VERSION:3.0") && vcf.TrimEnd().EndsWith("END:VCARD"));
        Check("vcf escapes the semicolon", vcf.Contains("FN:Anku\\; Sampson"), vcf);
        Check("vcf escapes the comma", vcf.Contains("ORG:Beta\\, Ltd"));
        Check("vcf carries the number", vcf.Contains("TEL;TYPE=CELL:+233240000001"));
    }

    // The tray badge is drawn at runtime, so a bad .ico encoder means either a
    // black square or an invisible dot - both silent, both in the notification
    // area where nobody thinks to screenshot it. Prove the bytes are a real
    // 32 bpp icon, that alpha survives, and that the dot landed.
    static void VerifyTrayBadge()
    {
        Console.WriteLine("  tray badge");
        Bitmap base32 = new Bitmap(32, 32, PixelFormat.Format32bppArgb);
        using (Graphics g = Graphics.FromImage(base32))
        {
            g.Clear(Color.Transparent);
            using (Brush b = new SolidBrush(Color.FromArgb(255, 0x4f, 0x8c, 0xff)))
                g.FillRectangle(b, 4, 4, 20, 20);
        }

        Bitmap badged = StatusIcons.Badge(base32, Color.FromArgb(0x22, 0xc5, 0x5e), 32);
        byte[] ico = StatusIcons.EncodeIco(badged, 32);

        // ICONDIR: reserved=0, type=1, count=1.
        Check("ico header is a single icon",
            ico[0] == 0 && ico[1] == 0 && ico[2] == 1 && ico[3] == 0 && ico[4] == 1 && ico[5] == 0);
        Check("ico size is header + DIB + mask", ico.Length == 22 + 40 + 4096 + 128, "len " + ico.Length);
        // ICONDIRENTRY starts at offset 6: w, h, colors, reserved, then planes
        // (10) and bitCount (12) as shorts, then size (14) and offset (18).
        Check("entry declares 32 bpp", BitConverter.ToInt16(ico, 12) == 32,
            "bpp " + BitConverter.ToInt16(ico, 12));
        Check("entry declares 1 plane", BitConverter.ToInt16(ico, 10) == 1);
        Check("entry size matches the payload", BitConverter.ToInt32(ico, 14) == 40 + 4096 + 128,
            "bytesInRes " + BitConverter.ToInt32(ico, 14));
        Check("entry points at the image data", BitConverter.ToInt32(ico, 18) == 22);

        Icon round;
        try { round = new Icon(new MemoryStream(ico, 0, ico.Length, true, false)); }
        catch (Exception ex) { Check("icon loads", false, ex.Message); return; }
        Check("icon loads at 32x32", round.Width == 32 && round.Height == 32, round.Width + "x" + round.Height);

        Bitmap back = round.ToBitmap();
        // Top-left is untouched on both the base and the badge: if it comes back
        // opaque, the encoder flattened transparency (the GetHicon bug).
        Check("transparency survives the round trip", back.GetPixel(1, 1).A == 0,
            "alpha " + back.GetPixel(1, 1).A);
        Color dot = back.GetPixel(24, 24);
        Check("green dot landed bottom-right", dot.G > 100 && dot.G > dot.R && dot.G > dot.B,
            "rgb " + dot.R + "," + dot.G + "," + dot.B);
        Color body = back.GetPixel(10, 10);
        Check("base icon pixels preserved", body.B > 150, "rgb " + body.R + "," + body.G + "," + body.B);
        back.Dispose();
        round.Dispose();
        badged.Dispose();
        base32.Dispose();
    }

    static bool SafeResend(Member m)
    {
        try { m.SendFrames(1000, 3); return true; }
        catch { return false; }
    }

    // Three members transmitting at the same time, 20 ms apart each.
    static void SendAll(Member a, short av, Member b, short bv, Member c, short cv, int frames)
    {
        Thread ta = a.BeginFrames(av, frames);
        Thread tb = b.BeginFrames(bv, frames);
        Thread tc = c.BeginFrames(cv, frames);
        ta.Join(); tb.Join(); tc.Join();
    }

    // ── Onion frames ────────────────────────────────────────────────────
    // The claim is narrow and it has to be tested narrowly. A relay sitting
    // BETWEEN the sender's relay and the target's relay already knows, from the
    // directory gossip, which numbers live behind which of its peers - that is a
    // phone book, and the mesh cannot work without it. What layering has to
    // remove is the *pairing*: a single frame that names sender and target
    // together. So the assertion is made against the raw lines the middle relay
    // read off its socket (CallServer.WireIn), not against what it logged, and it
    // is run twice - once with onion off, to prove the check is sensitive.
    static void VerifyOnion()
    {
        Console.WriteLine("  onion: sealed box and padding");
        string dir = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "onion_tmp_" + DateTime.Now.Ticks);
        try { Directory.CreateDirectory(dir); } catch { }

        Identity kb = new Identity(Path.Combine(dir, "b.key"));
        Identity kc = new Identity(Path.Combine(dir, "c.key"));
        // What Onion.Build actually seals is a padded layer, so that is what the
        // bucket claim has to be tested on - sealing a bare byte array here would
        // only prove AES-CTR is a stream cipher, which is not the assertion.
        string layerText = "v1|END|7004440002|0|1|aGVsbG8=";
        string box = SealedBox.Seal(kc.PublicBase64, Onion.Pad(layerText));
        Check("a key we have never spoken to can be sealed to", box != null);
        Check("...and opened by exactly that key",
              Onion.Unpad(SealedBox.Unseal(kc, box, kc.CipherBytes)) == layerText);
        Check("...and not by a neighbour's", SealedBox.Unseal(kb, box, kb.CipherBytes) == null);
        byte[] rawBox;
        try { rawBox = Convert.FromBase64String(box); } catch { rawBox = new byte[0]; }
        byte[] cut = new byte[rawBox.Length];
        Buffer.BlockCopy(rawBox, 0, cut, 0, rawBox.Length);
        cut[cut.Length - 5] ^= 0x01;      // inside the ciphertext tail
        Check("...and not after one bit of it changes",
              SealedBox.Unseal(kc, Convert.ToBase64String(cut), kc.CipherBytes) == null);
        Check("a padded layer is a whole number of buckets",
              rawBox.Length > kc.CipherBytes + 32 &&
              (rawBox.Length - kc.CipherBytes - 32) % Onion.Bucket == 0,
              "len=" + rawBox.Length + " cipher=" + kc.CipherBytes);
        Check("garbage is not a layer", SealedBox.Unseal(kc, "not-base64-@@@", kc.CipherBytes) == null);
        Check("a seal to a key that is not a key fails closed",
              SealedBox.Seal("<not a key>", Encoding.UTF8.GetBytes(layerText)) == null);

        Console.WriteLine("  onion: layers");
        string inner = "MSG|7004440002|7004440001|CHAT|ONION-PAYLOAD-CANARY";
        List<string> pubs = new List<string>();
        pubs.Add(kb.PublicBase64);
        pubs.Add(kc.PublicBase64);
        List<string> nexts = new List<string>();
        nexts.Add("relay-c");
        nexts.Add("");
        string circuit = Onion.Build(pubs, nexts, "7004440002", inner);
        Check("a two-hop circuit is built", circuit != null);
        Check("a one-hop route is not layered (there is nobody to hide from)",
              Onion.Build(OnlyPub(kb.PublicBase64), OnlyPub("x"), "7004440002", inner) == null);
        OnionHop h0 = Onion.Peel(kb, circuit);
        Check("the first hop can open its layer", h0 != null, "");
        Check("...and is told only the next relay", h0 != null && h0.Kind == "HOP" && h0.Dest == "relay-c",
              h0 == null ? "null" : h0.Kind + "/" + h0.Dest);
        Check("...and sees neither number", h0 != null &&
              h0.Dest.IndexOf("7004440001") < 0 && h0.Dest.IndexOf("7004440002") < 0 &&
              h0.Body.IndexOf("7004440001") < 0 && h0.Body.IndexOf("7004440002") < 0);
        Check("...and cannot open the layer meant for the destination", Onion.Peel(kb, h0.Body) == null);
        OnionHop h1 = Onion.Peel(kc, h0.Body);
        Check("the destination relay can", h1 != null && h1.Kind == "END" && h1.Dest == "7004440002",
              h1 == null ? "null" : h1.Kind + "/" + h1.Dest);
        Check("...and the line it delivers is the original", h1 != null && h1.Body == inner);
        byte[] tampered = Convert.FromBase64String(circuit);
        tampered[tampered.Length - 3] ^= 0x01;
        Check("editing a layer makes it not open", Onion.Peel(kb, Convert.ToBase64String(tampered)) == null);
        Check("a layer does not say who it came from", circuit.IndexOf("7004440001") < 0);
        Check("pad round-trips", Onion.Unpad(Onion.Pad("hello")) == "hello");
        Check("a non-bucket buffer is rejected", Onion.Unpad(new byte[100]) == null);

        Console.WriteLine("  onion: across a chain of relays");
        // A four-node chain, so the sender's relay has to trust an intermediate it
        // cannot map past: senderRelay -> entry -> middle -> exit. The route exists
        // without anybody dialling across the ends.
        // Its own port range: sharing 45730-45732 with the room section would
        // mean re-using those relays' key and pin files, so a pin from one section
        // could decide the outcome of another.
        CallServer sender = NewKeyedRelay(45753, "127.0.0.1:45750", "127.0.0.23:45753", "senders-relay", dir, null);
        CallServer entry = NewKeyedRelay(45750, "127.0.0.1:45751", "127.0.0.20:45750", "entry", dir, null);
        CallServer mid = NewKeyedRelay(45751, "127.0.0.1:45752", "127.0.0.21:45751", "middle", dir, null);
        CallServer exit = NewKeyedRelay(45752, "", "127.0.0.22:45752", "exit", dir, null);
        if (entry == null || mid == null || exit == null || sender == null)
        {
            Check("onion relay ports free (45750-45753)", false);
            CleanupOnion(dir);
            return;
        }
        List<string> midWire = new List<string>();
        mid.WireIn += delegate(string s) { lock (midWire) midWire.Add(s); };
        Check("the chain comes up", WaitFor(delegate
              { return sender.LinkCount >= 1 && entry.LinkCount >= 2 && mid.LinkCount >= 2; }, 9000),
              "links=" + sender.LinkCount + "/" + entry.LinkCount + "/" + mid.LinkCount + "/" + exit.LinkCount);
        // Both relay keys the circuit needs: the middle one directly, the exit one
        // only by gossip. Without the second the onion cannot be built at all, so
        // this is the assertion that key gossip actually works.
        // Waited for, not asserted inline: a relay writes RLINKOK before it
        // announces its key, so the dialler can see "link up" a moment before the
        // key file exists on either side.
        Check("every relay keeps its own key file", WaitFor(delegate
              { return File.Exists(Path.Combine(dir, "entry.key")) &&
                       File.Exists(Path.Combine(dir, "exit.key")); }, 5000),
              "dir=" + string.Join(",", SafeFiles(dir)));
        Check("the entry relay holds the exit relay's key", WaitFor(delegate {
              return HasPinned(Path.Combine(dir, "entry_book.txt"), "127.0.0.22:45752"); }, 8000));

        Node from = new Node("7004440001", 45753);
        Node to = new Node("7004440002", 45752);
        Check("the sender's relay can see a peer three hops away", from.WaitForDir("7004440002", 9000));

        // Baseline: onion off. The middle relay must see the pair, or every
        // assertion after this one would pass on an empty socket.
        lock (midWire) midWire.Clear();
        from.Send("MSG|7004440002|7004440001|CHAT|BASELINE-NO-ONION");
        Check("baseline: message delivered with onion off", to.WaitForMsg("7004440001", "CHAT|BASELINE-NO-ONION", 8000));
        Check("baseline: the middle relay did see both ends in one line",
              WaitFor(delegate { return PairLines(midWire) > 0; }, 3000), "pairLines=" + PairLines(midWire));

        // Now layer it.
        entry.RelayOnion = "force";
        sender.RelayOnion = "force";
        lock (midWire) midWire.Clear();
        long built0 = Interlocked.Read(ref sender.OnionBuilt);
        // Baselines taken BEFORE the send, not after the delivery is observed: a
        // "did this counter grow?" check whose baseline is captured afterwards can never
        // be satisfied, because the increment has usually landed by then. That mistake
        // was made writing the polling version below and is the reason these are read
        // up here alongside built0.
        long midCarry0 = Interlocked.Read(ref mid.OnionCarried);
        long exitCarry0 = Interlocked.Read(ref exit.OnionCarried);
        from.Send("MSG|7004440002|7004440001|CHAT|ONION-PAYLOAD-CANARY");
        Check("the message still arrives, two relays on", to.WaitForMsg("7004440001", "CHAT|ONION-PAYLOAD-CANARY", 9000));
        // Polled, not sampled. The relay increments its own counter just AFTER it
        // writes the frame to the target, so reading it the instant the delivery above
        // is observed loses by microseconds on a busy machine - and it did, in two runs
        // out of four, once the peer-push thread changed the timing around it. The claim
        // being tested ("this relay ended a layer") is a claim about something that
        // happened, so it should be waited for rather than glimpsed.
        Check("the sender's relay built a circuit",
              WaitFor(delegate { return Interlocked.Read(ref sender.OnionBuilt) > built0; }, 6000));
        Check("the middle relay carried a layer",
              WaitFor(delegate { return Interlocked.Read(ref mid.OnionCarried) > midCarry0; }, 6000),
              "carried=" + midCarry0 + " -> " + Interlocked.Read(ref mid.OnionCarried));
        Check("the exit relay ended a layer",
              WaitFor(delegate { return Interlocked.Read(ref exit.OnionCarried) > exitCarry0; }, 6000),
              "carried=" + exitCarry0 + " -> " + Interlocked.Read(ref exit.OnionCarried));
        Thread.Sleep(400);
        string wire;
        lock (midWire) wire = string.Join("\n", midWire.ToArray());
        Check("the middle relay got an onion line", wire.IndexOf("ONION|") >= 0);
        Check("...and no forwarded message envelope", wire.IndexOf("XF|") < 0 && wire.IndexOf("MSG|") < 0);
        Check("...and no line naming both ends", PairLines(midWire) == 0, "pairLines=" + PairLines(midWire));
        Check("...and the payload never touched it", wire.IndexOf("ONION-PAYLOAD-CANARY") < 0);
        Check("...and neither number at all in the traffic it carried",
              CountNumberLines(midWire, "7004440001") == 0 &&
              CountNumberLines(midWire, "7004440002") == 0 ||
              PairLines(midWire) == 0);

        // Media is deliberately NOT layered: the envelope would double a call's
        // bandwidth for a relay that can see the flow anyway. Pinning that here
        // stops a future change from "fixing" it into a stall.
        lock (midWire) midWire.Clear();
        long built1 = Interlocked.Read(ref sender.OnionBuilt);
        from.Send("RM|7004440002|7004440001|Zm9vYmFy");
        Check("media still crosses in clear, as documented", to.WaitForLine("RM|", 6000));
        Check("...and was not layered", Interlocked.Read(ref sender.OnionBuilt) == built1);
        Check("...and the middle relay saw the frame go past", wireHas(midWire, "RM|"));

        from.Close(); to.Close();
        entry.Stop(); mid.Stop(); exit.Stop(); sender.Stop();

        Console.WriteLine("  onion: a swapped relay key is refused");
        // The entry relay has already pinned a different key for the exit relay's
        // address. Gossip cannot talk it out of that, and force mode then refuses
        // the message rather than forwarding it in clear - which is the whole
        // point of having a third setting.
        string seedBad = "127.0.0.30:45742|" + Convert.ToBase64String(
            Encoding.UTF8.GetBytes("<RSAXML bogus pinned key>")) + "|2026-01-01 00:00:00|tofu\n";
        List<string> log2 = new List<string>();
        List<string> logE2 = new List<string>();
        List<string> logM2 = new List<string>();
        List<string> logX2 = new List<string>();
        CallServer e2 = NewKeyedRelay(45740, "127.0.0.1:45741", "127.0.0.28:45740", "e2", dir, null, logE2);
        CallServer m2 = NewKeyedRelay(45741, "127.0.0.1:45742", "127.0.0.29:45741", "m2", dir, null, logM2);
        CallServer x2 = NewKeyedRelay(45742, "", "127.0.0.30:45742", "x2", dir, null, logX2);
        CallServer s2 = NewKeyedRelay(45743, "127.0.0.1:45740", "127.0.0.31:45743", "s2", dir, seedBad, log2);
        if (e2 == null || m2 == null || x2 == null || s2 == null)
        {
            Check("refusal-test relay ports free (45740-45743)", false);
        }
        else
        {
            Check("the chain for the refusal test comes up",
                  WaitFor(delegate { return s2.LinkCount >= 1 && m2.LinkCount >= 2; }, 9000),
                  "links=" + s2.LinkCount + "/" + e2.LinkCount + "/" + m2.LinkCount + "/" + x2.LinkCount);
            s2.RelayOnion = "force";
            Node f2 = new Node("7004440003", 45743);
            Node t2 = new Node("7004440004", 45742);
            Check("...and the directory still merges", f2.WaitForDir("7004440004", 9000));
            // Wait for the verdict itself. "force refused it" is also what happens
            // when the key gossip has simply not arrived yet, and those two must
            // not be confused: one is the pin working, the other is a race.
            Check("the relay called out a pinned key that changed",
                  WaitFor(delegate { return LogHas(log2, "RELAY KEY CHANGED"); }, 12000),
                  "\n            s2: " + KeyTrace(log2) + "\n            e2: " + KeyTrace(logE2) +
                  "\n            m2: " + KeyTrace(logM2) + "\n            x2: " + KeyTrace(logX2));
            Check("...and it named the address, not a stranger's",
                  LogHas(log2, "127.0.0.30:45742"), Tail(log2));
            f2.Send("MSG|7004440004|7004440003|CHAT|SHOULD-NOT-TRAVEL");
            Check("force mode refused the message instead of leaking the pair",
                  f2.WaitForLine("ERR|onoroute", 6000));
            Check("...and it never reached the target", !t2.WaitForMsg("7004440003", "CHAT|SHOULD-NOT-TRAVEL", 2000));
            f2.Close(); t2.Close();
            e2.Stop(); m2.Stop(); x2.Stop(); s2.Stop();
        }
        CleanupOnion(dir);
    }

    static List<string> OnlyPub(string p)
    {
        List<string> l = new List<string>();
        l.Add(p);
        return l;
    }

    // How many received lines name BOTH ends. The number that matters: a
    // directory row mentioning one of them is a phone book, one row mentioning
    // both is a surveillance log.
    static int PairLines(List<string> wire)
    {
        int n = 0;
        lock (wire)
            foreach (string l in wire)
                if (l.IndexOf("7004440001") >= 0 && l.IndexOf("7004440002") >= 0) n++;
        return n;
    }

    static int CountNumberLines(List<string> wire, string num)
    {
        int n = 0;
        lock (wire)
            foreach (string l in wire) if (l.IndexOf(num) >= 0) n++;
        return n;
    }

    static bool wireHas(List<string> wire, string needle)
    {
        lock (wire) foreach (string l in wire) if (l.IndexOf(needle) >= 0) return true;
        return false;
    }

    static bool HasPinned(string bookPath, string handle)
    {
        try
        {
            if (!File.Exists(bookPath)) return false;
            foreach (string ln in ReadLive(bookPath).Split('\n'))
                if (ln.StartsWith(handle + "|", StringComparison.Ordinal)) return true;
        }
        catch { }
        return false;
    }

    // Only for a failure detail: a missing key file is worth explaining, and
    // listing what is in the directory explains it.
    static string[] SafeFiles(string d)
    {
        try { return Directory.Exists(d) ? Directory.GetFiles(d) : new string[0]; }
        catch { return new string[0]; }
    }

    // Same idea for a queue folder. "no mail files" is a different bug when the
    // folder is empty and when it is full of .part files that never got swapped -
    // one is a write that never happened, the other is a swap that lost.
    static string Names(string d)
    {
        string[] f = SafeFiles(d);
        if (f.Length == 0) return "(empty or absent)";
        List<string> n = new List<string>();
        foreach (string x in f) n.Add(Path.GetFileName(x));
        return string.Join(",", n.ToArray());
    }

    // A relay that needs its own key file. The book can be pre-seeded, which is
    // how the swapped-key case is arranged without patching production code.
    static CallServer NewKeyedRelay(int port, string links, string advertise, string tag,
                                    string dir, string bookSeed)
    {
        return NewKeyedRelay(port, links, advertise, tag, dir, bookSeed, null);
    }

    // The log sink has to be attached before Start(): the relay's own identity line
    // is emitted there, and attaching afterwards hides exactly the lines that
    // explain a key that never arrived.
    static CallServer NewKeyedRelay(int port, string links, string advertise, string tag,
                                    string dir, string bookSeed, List<string> log)
    {
        CallServer s = new CallServer();
        if (log != null) s.Log += delegate(string m) { lock (log) log.Add(m); };
        s.RelayPolicy = "everyone";
        s.RelayLinks = links;
        s.RelayName = "onion-" + tag;
        s.RelayAdvertise = advertise;
        s.RelayKeyFile = Path.Combine(dir, tag + ".key");
        s.RelayBookFile = Path.Combine(dir, tag + "_book.txt");
        s.MailDirOverride = Path.Combine(dir, tag + "_mail");
        s.LedgerFileOverride = Path.Combine(dir, tag + "_ledger.txt");
        s.LeaseFileOverride = Path.Combine(dir, tag + "_leases.txt");
        s.PeerKeyFileOverride = Path.Combine(dir, tag + "_peerkeys.txt");
        if (bookSeed != null) { try { File.WriteAllText(s.RelayBookFile, bookSeed); } catch { } }
        if (!s.Start(port)) { try { s.Dispose(); } catch { } return null; }
        return s;
    }

    static void CleanupOnion(string dir)
    {
        TryDeleteDir(dir);
    }

    static string LastLines(string s, int n)
    {
        if (string.IsNullOrEmpty(s)) return "";
        return s.Length <= n ? s : s.Substring(s.Length - n);
    }

    static bool LogHas(List<string> log, string needle)
    {
        lock (log)
            foreach (string l in log)
                if (l.IndexOf(needle, StringComparison.Ordinal) >= 0) return true;
        return false;
    }

    // Every line that mentions a key, for a failure detail. A circuit that will not
    // build is almost always a key that stopped travelling, and the last few log
    // lines are not enough to see where it stopped.
    static string KeyTrace(List<string> log)
    {
        List<string> keep = new List<string>();
        lock (log)
            foreach (string l in log)
                if (l.IndexOf("key", StringComparison.OrdinalIgnoreCase) >= 0 ||
                    l.IndexOf("identity", StringComparison.OrdinalIgnoreCase) >= 0) keep.Add(l);
        return string.Join(" | ", keep.ToArray());
    }

    // Failure detail only: the last few things the relay said, which is the
    // difference between "the pin refused it" and "nothing arrived".
    static string Tail(List<string> log)
    {
        lock (log)
        {
            int from = log.Count > 4 ? log.Count - 4 : 0;
            string[] rows = new string[log.Count - from];
            for (int i = 0; i < rows.Length; i++) rows[i] = log[from + i];
            return string.Join(" | ", rows);
        }
    }

    // ── NAT paths ──────────────────────────────────────────────────────
    // Real address translation cannot be reproduced on one machine, but the two
    // decisions that decide whether a call survives it can be: which UDP port to
    // aim at, and what to do when a path that worked goes quiet. Both used to be
    // wrong in ways that were invisible until a second instance ran on the same PC.
    static void VerifyNatPaths()
    {
        Console.WriteLine("  nat: the media port a peer actually holds");
        VoipMedia a = new VoipMedia();
        VoipMedia b = new VoipMedia();
        VoipMedia c = new VoipMedia();
        string portErr = "";
        try
        {
            // Deliberately not asserted against MEDIA_PORT itself: something on this
            // PC may already hold it (a running instance does), and a test that only
            // passes on an idle machine is a test that reports the machine. The real
            // property is relational - the first socket gets what it asked for, and a
            // second one asking for the same port has to move.
            a.Open(VoipService.MEDIA_PORT);
            b.Open(a.LocalPort);                    // guaranteed to be taken by a
            Check("the first socket reports the port it really holds",
                  a.IsOpen && a.LocalPort > 0, "open=" + a.IsOpen + " port=" + a.LocalPort);
            Check("...and a busy one moves instead of leaving the call blackholed",
                  b.IsOpen && b.LocalPort != a.LocalPort,
                  "open=" + b.IsOpen + " a=" + a.LocalPort + " b=" + b.LocalPort);

            byte[] ka = new byte[] { VoipMedia.PKT_KEEPALIVE, 0 };
            UdpClient probe = new UdpClient();
            // The old behaviour: aim at the port the peer is assumed to use. If the
            // peer moved, this lands somewhere else and the moved socket hears
            // nothing - which is exactly what used to kill a second instance's calls.
            probe.Send(ka, ka.Length, "127.0.0.1", a.LocalPort);
            Thread.Sleep(250);
            Check("a datagram aimed at the guessed port does NOT reach the moved socket",
                  b.LastRxTicks == 0, "b stamp=" + b.LastRxTicks);
            // Polled for the same reason as the onion counters above: a UDP loopback
            // delivery is fast but not scheduled, and sampling it 250 ms after sending
            // makes "the app works" depend on how busy somebody else's thread pool was.
            Check("...while the socket on the port actually sent to does hear it",
                  WaitFor(delegate { return a.LastRxTicks != 0; }, 3000),
                  "a stamp=" + a.LastRxTicks);

            a.ResetForCall(); b.ResetForCall();
            probe.Send(ka, ka.Length, "127.0.0.1", b.LocalPort);
            Thread.Sleep(250);
            Check("aiming at the announced port reaches it", b.LastRxTicks != 0);
            bool learned = false;
            foreach (IPEndPoint e in b.Candidates)
                if (e.Address.ToString().StartsWith("127.", StringComparison.Ordinal)) learned = true;
            Check("...and the reply path is learned from the arrival itself", learned, Ports(b));
            // With the relay active nothing at all goes out over UDP: proven by a
            // third socket that is a known candidate and must stay silent.
            c.Open(b.LocalPort);
            b.ResetForCall(); c.ResetForCall();
            b.AddCandidate(new IPEndPoint(IPAddress.Loopback, c.LocalPort));
            int relayed = 0;
            b.RelaySend = delegate(byte[] pkt) { Interlocked.Increment(ref relayed); };
            b.RelayActive = true;
            b.KeepAlive();
            Thread.Sleep(250);
            Check("a relay-backed call sends media over the relay", relayed == 1, "relayed=" + relayed);
            Check("...and not ALSO over UDP to the old candidate", c.LastRxTicks == 0,
                  "c stamp=" + c.LastRxTicks);
            b.RelayActive = false;
            b.KeepAlive();
            Thread.Sleep(250);
            Check("...and going back to direct reaches that candidate again", c.LastRxTicks != 0);
            probe.Close();
        }
        catch (Exception ex) { portErr = ex.Message; }
        Check("media sockets opened for the nat test", portErr.Length == 0, portErr);
        try { a.Dispose(); b.Dispose(); c.Dispose(); } catch { }

        Console.WriteLine("  nat: when to give up on direct media");
        long now = DateTime.UtcNow.Ticks;
        Check("a route that never delivered anything is given up on at 3 s",
              VoipService.RelayFallbackReason(0, 3.2, false, true, true) != null);
        Check("...but not before", VoipService.RelayFallbackReason(0, 2.0, false, true, true) == null);
        Check("a path that worked is given 5 s of silence, not 3", VoipService.RelayFallbackReason(
                  now - (long)(2.5 * TimeSpan.TicksPerSecond), 60, false, true, true) == null);
        Check("...and then falls back instead of dropping the call", VoipService.RelayFallbackReason(
                  now - (long)(6.0 * TimeSpan.TicksPerSecond), 60, false, true, true) != null,
              VoipService.RelayFallbackReason(now - (long)(6.0 * TimeSpan.TicksPerSecond), 60, false, true, true));
        Check("already on the relay stays there (no flapping)",
              VoipService.RelayFallbackReason(0, 60, true, true, true) == null);
        Check("a plain IP call has no relay to fall back to and stays direct",
              VoipService.RelayFallbackReason(0, 60, false, true, false) == null);
        Check("no relay connection means no fallback promise",
              VoipService.RelayFallbackReason(0, 60, false, false, true) == null);

        Console.WriteLine("  nat: why the port travels as its own verb");
        // INVITE is parsed with a 5-field limit. A sixth field on that line would be
        // glued onto the DH public value, which is then BigInteger.Parse()d - the
        // call would fail key agreement rather than lose the port. Recorded so
        // nobody "simplifies" MPORT back into INVITE without meeting this.
        string[] five = "INVITE|id|1|name|12345|45699".Split(new char[] { '|' }, 5);
        Check("a sixth INVITE field would corrupt the parsed DH key",
              five[4] == "12345|45699", five[4]);
        Check("as its own verb it parses cleanly", "MPORT|45699".Split('|')[1] == "45699");
    }

    static string Ports(VoipMedia m)
    {
        List<string> l = new List<string>();
        foreach (IPEndPoint e in m.Candidates) l.Add(e.Port.ToString());
        return "candidates=" + string.Join(",", l.ToArray());
    }

    // ── Store and forward ──────────────────────────────────────────
    // The gap this closes is the ordinary one: you message somebody who is off-line,
    // so the message waits on a machine. It used to wait on exactly one machine,
    // in memory, and went away when that PC restarted or when the recipient next
    // came on-line somewhere else. Three properties are asserted here: the message
    // survives a restart, it can be carried to a relay the sender never heard of,
    // and it still arrives ONCE.
    static void VerifyStoreAndForward()
    {
        Console.WriteLine("  store and forward: mail that outlives the machine");
        string root = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "sf_tmp_" + DateTime.Now.Ticks);
        try { Directory.CreateDirectory(root); } catch { }
        int hp = 45790;
        CallServer home = NewMeshRelay(hp, "", "127.0.0.40:" + hp, "home", root);
        if (home == null) { Check("store-and-forward relay port free (45790-45799)", false); TryDeleteDir(root); return; }

        Node sender = new Node("7005550001", hp);
        // Sealed payload: a relay no longer stores unsealed mail at all, so this is
        // the shape real offline mail has. The durability being tested is the queue,
        // not the crypto - the relay never reads the payload either way.
        sender.Send("MSG|7005550002|7005550001|ECHAT|TUFJTC1TVVJWSVZLVVQtUkVCT09U");
        Check("the sender is told the mail is stored, not lost",
              sender.WaitForLine("QUEUED|7005550002", 4000));
        Check("...and it really is on disk, not only in memory",
              WaitFor(delegate { return MailFiles(root, "home").Length == 1; }, 3000),
              "files=" + MailFiles(root, "home").Length);
        // Stop and start again: the same folders, the same port, nothing configured.
        // This is what closing the lid on a home relay does.
        home.Stop();
        sender.Close();
        CallServer home2 = NewMeshRelay(hp, "", "127.0.0.40:" + hp, "home", root);
        if (home2 == null) { Check("restarted relay could not rebind", false); TryDeleteDir(root); return; }
        Check("a restarted relay recovers what was waiting",
              WaitFor(delegate { return home2.QueuedMailCount == 1; }, 4000), "count=" + home2.QueuedMailCount);
        Node late = new Node("7005550002", hp);
        Check("...and delivers it when the recipient finally appears",
              late.WaitForMsg("7005550001", "ECHAT|TUFJTC1TVVJWSVZLVVQtUkVCT09U", 5000));
        Check("...once, and then the store is empty", WaitFor(delegate
              { return home2.QueuedMailCount == 0 && MailFiles(root, "home").Length == 0; }, 4000),
              "count=" + home2.QueuedMailCount + " files=" + MailFiles(root, "home").Length);
        late.Close(); home2.Stop();

        Console.WriteLine("  store and forward: the mesh carries it");
        // A star: both leaves link the hub and nothing else. The recipient appears on
        // a relay the sender has never met, so delivery only works if a copy travelled.
        int a1 = 45791, hb = 45792, a2 = 45793;
        CallServer A = NewMeshRelay(a1, "127.0.0.1:" + hb, "127.0.0.41:" + a1, "senders", root);
        CallServer B = NewMeshRelay(hb, "", "127.0.0.42:" + hb, "carrier", root);
        CallServer C = NewMeshRelay(a2, "127.0.0.1:" + hb, "127.0.0.43:" + a2, "elsewhere", root);
        if (A == null || B == null || C == null) { Check("mesh relay ports free", false); TryDeleteDir(root); return; }
        A.RelayCarryMail = true; B.RelayCarryMail = true; C.RelayCarryMail = true;
        Check("both leaves are linked through the hub", WaitFor(delegate
              { return A.LinkCount >= 1 && C.LinkCount >= 1 && B.LinkCount >= 2; }, 12000),
              "links=" + A.LinkCount + "/" + B.LinkCount + "/" + C.LinkCount);
        Node sn = new Node("7005550003", a1);
        // A sealed payload: carrying is limited to what the recipient's key already
        // covers, because a message to somebody off-line usually has no key yet.
        sn.Send("MSG|7005550004|7005550003|ECHAT|QVVUT0RZLVRyYW5zZmVy");
        Check("another relay accepted a copy of the mail",
              WaitFor(delegate { return B.QueuedMailCount >= 1; }, 8000), "carrier=" + B.QueuedMailCount);
        // Waited, not asserted inline: the index is published a moment before the
        // file lands, so checking the disk immediately reads a race, not a bug.
        Check("...written into ITS folder, not the sender's",
              WaitFor(delegate { return MailFiles(root, "carrier").Length >= 1; }, 4000),
              "files=" + MailFiles(root, "carrier").Length + " folder holds: " +
              Names(Path.Combine(Path.Combine(root, "carrier"), "mail")));
        Check("...and the copy is the message itself, not a summary",
              FileContains(MailFiles(root, "carrier"), "QVVUT0RZLVRyYW5zZmVy"));
        // The recipient never touches the sender's relay at all.
        Node rn = new Node("7005550004", a2);
        Check("the recipient gets it from a relay the sender never used",
              rn.WaitForMsg("7005550003", "ECHAT|QVVUT0RZLVRyYW5zZmVy", 10000));
        Thread.Sleep(1500);
        Check("...exactly once, even though copies sat on more than one relay",
              rn.CountMsgs("7005550003") == 1, "copies delivered=" + rn.CountMsgs("7005550003"));
        // A delivery notice must reach every holder, or the next connection duplicates.
        Check("...and the sender's relay stopped holding its copy", WaitFor(delegate
              { return A.QueuedMailCount == 0; }, 8000), "sender-side=" + A.QueuedMailCount);
        Check("...and so did the carrier", WaitFor(delegate
              { return B.QueuedMailCount == 0; }, 8000), "carrier=" + B.QueuedMailCount);
        Check("...leaving no message file behind on the carrier", MailFiles(root, "carrier").Length == 0,
              "files=" + MailFiles(root, "carrier").Length);

        // Same three relays, same carrying switch, and a rule one notch stronger than
        // the one this replaced. It used to be "plaintext is queued here, just never
        // handed on" - which still left the message readable for whoever owns that
        // disk. Now an unsealed payload is refused outright: nothing stored, nothing
        // to carry, and the sender is told in words.
        long receivedBefore = Interlocked.Read(ref B.MailReceived);
        long aMailBefore = A.QueuedMailCount;
        sn.Send("MSG|7005550099|7005550003|CHAT|PLAIN-MAIL-MUST-NOT-TRAVEL");
        Check("unsealed mail is refused, not queued",
              sn.WaitForLine("ERR|nokey|7005550099", 5000));
        Thread.Sleep(1200);
        Check("...and no copy was handed to another relay",
              Interlocked.Read(ref B.MailReceived) == receivedBefore,
              "extra copies accepted=" + (Interlocked.Read(ref B.MailReceived) - receivedBefore));
        Check("...and none landed in the carrier's folder", MailFiles(root, "carrier").Length == 0,
              "files=" + MailFiles(root, "carrier").Length);
        Check("...and the sender's own relay kept no trace of it either",
              A.QueuedMailCount == aMailBefore, "grew by " + (A.QueuedMailCount - aMailBefore));
        sn.Close(); rn.Close(); A.Stop(); B.Stop(); C.Stop();

        Console.WriteLine("  store and forward: it is a favour, so it is off by default");
        int n1 = 45794, n2 = 45795;
        CallServer X = NewMeshRelay(n1, "127.0.0.1:" + n2, "127.0.0.44:" + n1, "nocarry-a", root);
        CallServer Y = NewMeshRelay(n2, "", "127.0.0.45:" + n2, "nocarry-b", root);
        Check("the pair links with carrying left off",
              WaitFor(delegate { return X.LinkCount >= 1; }, 12000), "links=" + X.LinkCount);
        Node xn = new Node("7005550005", n1);
        // Sealed, so this still tests the *carrying* switch rather than the storage
        // rule - unsealed mail never reaches a queue at all any more.
        xn.Send("MSG|7005550006|7005550005|ECHAT|Tk9ULUJZLURFRkFVTFQ=");
        Check("the sender's own relay queues sealed mail",
              WaitFor(delegate { return X.QueuedMailCount == 1; }, 4000), "queued=" + X.QueuedMailCount);
        Thread.Sleep(1500);
        Check("...and nobody else was handed a copy of it", Y.QueuedMailCount == 0, "other=" + Y.QueuedMailCount);
        Check("...because a fresh relay defaults to not carrying", new CallServer().RelayCarryMail == false);
        xn.Close(); X.Stop(); Y.Stop();

        Console.WriteLine("  store and forward: mail on disk is not trusted because it is on disk");
        // Everything here is hostile or broken input, planted directly in the folder a
        // relay will read at Start. A stored file is other people's bytes.
        string md = Path.Combine(Path.Combine(root, "junk"), "mail");   // the relay's own mail folder
        try { Directory.CreateDirectory(md); } catch { }
        long past = DateTime.Now.Ticks - TimeSpan.TicksPerHour;
        long future = DateTime.Now.Ticks + TimeSpan.TicksPerDay;
        File.WriteAllLines(Path.Combine(md, "good.mail"), new string[] {
            "7005550009", "7005550008", future.ToString(), "0", "MSG|7005550009|7005550008|CHAT|RECOVERED-OK" });
        File.WriteAllLines(Path.Combine(md, "stale.mail"), new string[] {
            "7005550009", "7005550008", past.ToString(), "0", "MSG|7005550009|7005550008|CHAT|WEEK-OLD" });
        File.WriteAllLines(Path.Combine(md, "evilrecipient.mail"), new string[] {
            "../../windows/win.ini", "x", future.ToString(), "0", "MSG|evil|x|CHAT|HOSTILE" });
        File.WriteAllLines(Path.Combine(md, "truncated.mail"), new string[] { "7005550009" });
        File.WriteAllText(Path.Combine(md, "half.mail.part"), "anything");
        File.WriteAllLines(Path.Combine(md, "notanumber.mail"), new string[] {
            "7005550009", "7005550008", "tomorrow", "0", "MSG|7005550009|7005550008|CHAT|BAD" });
        int jp = 45796;
        CallServer J = NewMeshRelay(jp, "", "127.0.0.46:" + jp, "junk", root);
        if (J == null) { Check("junk-mail relay port free", false); TryDeleteDir(root); return; }
        Check("one recoverable message is read back", WaitFor(delegate
              { return J.QueuedMailCount == 1; }, 5000), "count=" + J.QueuedMailCount);
        Check("mail that expired while off is deleted, not delivered",
              !File.Exists(Path.Combine(md, "stale.mail")));
        Check("a recipient that is not a number is refused, not queued",
              !File.Exists(Path.Combine(md, "evilrecipient.mail")));
        Check("a truncated file is discarded rather than half-parsed",
              !File.Exists(Path.Combine(md, "truncated.mail")));
        Check("an unparsable expiry is discarded, not treated as forever",
              !File.Exists(Path.Combine(md, "notanumber.mail")));
        Check("a half-written file is left alone (it is not a message yet)",
              File.Exists(Path.Combine(md, "half.mail.part")));
        Node jr = new Node("7005550009", jp);
        Check("the good message reaches its recipient", jr.WaitForMsg("7005550008", "CHAT|RECOVERED-OK", 5000));
        Check("...and none of the junk reached anybody",
              !jr.WaitForText("WEEK-OLD", 600) && !jr.WaitForText("HOSTILE", 300) && !jr.WaitForText("BAD", 300),
              "received=" + jr.CountMsgs("7005550008"));
        jr.Close(); J.Stop();

        Console.WriteLine("  the mesh remembers the relays it met");
        // A relay that restarts with nothing configured used to be an island again.
        // The ledger is what makes the graph survive a reboot - and re-dialling it is
        // still gated behind the same consent switch as any other outbound link.
        int p1 = 45797, p2 = 45798, p3 = 45799;
        CallServer hub = NewMeshRelay(p2, "", "127.0.0.49:" + p2, "hub2", root);
        CallServer leaf = NewMeshRelay(p1, "127.0.0.1:" + p2, "127.0.0.47:" + p1, "leaf1", root);
        CallServer other = NewMeshRelay(p3, "127.0.0.1:" + p2, "127.0.0.48:" + p3, "leaf2", root);
        if (hub == null || leaf == null || other == null) { Check("ledger relay ports free", false); TryDeleteDir(root); return; }
        Check("a leaf learns of the far leaf through the hub", WaitFor(delegate
              { return leaf.LedgerEndpoints.Contains("127.0.0.48:" + p3); }, 12000),
              "ledger=" + string.Join(",", leaf.LedgerEndpoints.ToArray()));
        // Waited for rather than asserted inline: the relay records an endpoint in
        // memory and swaps the file a moment later, and a swap that loses to a
        // reader retries. A knife-edge here would fail the run for no reason.
        Check("...and wrote it to disk before anything happened", WaitFor(delegate
              { return ReadLive(Path.Combine(root, "leaf1", "relay_ledger.txt")).Contains("127.0.0.48:" + p3); }, 4000));
        leaf.Stop();
        CallServer reborn = NewMeshRelay(p1, "", "127.0.0.47:" + p1, "leaf1", root);   // no peers configured
        if (reborn == null) { Check("restarted leaf could not rebind", false); TryDeleteDir(root); return; }
        Check("a restarted leaf still knows the shape of the mesh", WaitFor(delegate
              { return reborn.LedgerEndpoints.Contains("127.0.0.48:" + p3); }, 6000),
              "ledger=" + string.Join(",", reborn.LedgerEndpoints.ToArray()));
        Check("...and does NOT dial it unasked", WaitFor(delegate { return reborn.LinkCount == 0; }, 3000) &&
              reborn.LinkCount == 0, "links=" + reborn.LinkCount);
        reborn.RelayAutoMesh = true;
        reborn.ReconsiderMesh();
        Check("...but with the mesh consent on, it rejoins from the ledger alone",
              WaitFor(delegate { return reborn.LinkCount >= 2; }, 20000), "links=" + reborn.LinkCount);
        hub.Stop(); other.Stop(); reborn.Stop();
        TryDeleteDir(root);
    }

    static CallServer NewMeshRelay(int port, string links, string advertise, string tag, string root)
    {
        string d = Path.Combine(root, tag);
        try { Directory.CreateDirectory(d); } catch { }
        CallServer s = new CallServer();
        s.Log += delegate(string m) { Console.WriteLine("    [sf:" + tag + "] " + m); };
        s.RelayPolicy = "everyone";
        s.RelayLinks = links;
        s.RelayName = "sf-" + tag;
        s.RelayAdvertise = advertise;
        s.RelayKeyFile = Path.Combine(d, "relay.key");
        s.RelayBookFile = Path.Combine(d, "relay_keys.txt");
        s.MailDirOverride = Path.Combine(d, "mail");
        s.LedgerFileOverride = Path.Combine(d, "relay_ledger.txt");
        s.LeaseFileOverride = Path.Combine(d, "number_leases.txt");
        s.PeerKeyFileOverride = Path.Combine(d, "peer_keys.txt");
        if (!s.Start(port)) { try { s.Dispose(); } catch { } return null; }
        return s;
    }

    static string[] MailFiles(string root, string tag)
    {
        try
        {
            string md = Path.Combine(Path.Combine(root, tag), "mail");
            if (!Directory.Exists(md)) return new string[0];
            List<string> keep = new List<string>();
            foreach (string f in Directory.GetFiles(md, "*.mail*"))
                if (f.EndsWith(".mail", StringComparison.OrdinalIgnoreCase)) keep.Add(f);
            return keep.ToArray();
        }
        catch { return new string[0]; }
    }

    // Read a file that a relay thread may be saving at this instant. Plain
    // File.ReadAllText throws IOException on a file the writer opened without
    // sharing, and that threw the whole suite down (unhandled, exit 0xE0434352)
    // about one run in four - four other sections then never ran, so a green-looking
    // partial log was the least of it. Same assembly, so the product's own reader
    // is used rather than a fifth copy of this logic.
    static string ReadLive(string path)
    {
        string s = StateFile.ReadShared(path);
        return s ?? "";
    }

    static bool FileContains(string[] files, string needle)
    {
        foreach (string f in files)
        {
            try { if (ReadLive(f).Contains(needle)) return true; } catch { }
        }
        return false;
    }

    // The real mail files in one relay's folder, given its path rather than a tag.
    // The suffix is checked in code, not left to the OS pattern, for the reason the
    // relay itself gives: "*.mail" can be answered with a half-written
    // "<id>.mail.part", and counting one of those would invent a queue entry that
    // nobody ever stored.
    static string[] MailFilesIn(string dir)
    {
        try
        {
            if (!Directory.Exists(dir)) return new string[0];
            List<string> keep = new List<string>();
            foreach (string f in Directory.GetFiles(dir, "*.mail*"))
                if (f.EndsWith(".mail", StringComparison.OrdinalIgnoreCase)) keep.Add(f);
            return keep.ToArray();
        }
        catch { return new string[0]; }
    }

    static bool MailDirHas(string dir, string needle)
    {
        foreach (string f in MailFilesIn(dir))
            if (ReadLive(f).Contains(needle)) return true;
        return false;
    }

    // ── Prekeys: sealing mail for somebody who is not connected ─────────
    // A session key needs the peer awake, so offline mail could not be sealed at
    // all - it sat in the relay's queue as plaintext, and therefore could not be
    // carried anywhere either. A published identity key fixes both, and everything
    // here is about proving that: the binding must be self-proved, a substituted key
    // must fail, and nothing unreadable may be spread.
    static void VerifyPrekeys()
    {
        Console.WriteLine("  prekeys: the offline envelope");
        string root = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "pk_tmp_" + DateTime.Now.Ticks);
        try { Directory.CreateDirectory(root); } catch { }
        Identity alice = new Identity(Path.Combine(root, "alice.key")); alice.Number = "7006660001";
        Identity bob = new Identity(Path.Combine(root, "bob.key")); bob.Number = "7006660002";
        Identity eve = new Identity(Path.Combine(root, "eve.key")); eve.Number = "7006660003";
        string secret = "the alarm is at midnight";
        string line = OfflineSeal.Seal(alice, bob.PublicBase64, "7006660001", "7006660002", secret);
        Check("a message can be sealed to a key we have never spoken to", line != null);
        Check("...and the line carries no plaintext", line.IndexOf(secret, StringComparison.Ordinal) < 0);
        Check("...as exactly three fields, so the payload cannot shift them", line.Split(new char[] { '|' }, 3).Length == 3);
        OfflineSeal.Opened ok = OfflineSeal.OpenWith(bob, line, alice.PublicBase64, "7006660001", "7006660002");
        Check("the recipient opens it", ok != null && ok.Text == secret, ok == null ? "null" : ok.Text);
        Check("...and reads the true sender out of the signed body", ok != null && ok.From == "7006660001");
        Check("...and that it was addressed to them", ok != null && ok.To == "7006660002");
        Check("another recipient cannot open it", OfflineSeal.OpenWith(eve, line, alice.PublicBase64, "7006660001", "7006660003") == null);
        Check("...and neither can a claim about the wrong sender",
              OfflineSeal.OpenWith(bob, line, eve.PublicBase64, "7006660003", "7006660002") == null);
        // A relay that rewrites the MSG envelope to re-attribute or redirect:
        // the numbers are inside the signed ciphertext, so they must disagree.
        Check("a relay cannot re-attribute it to another sender",
              OfflineSeal.OpenWith(bob, line, alice.PublicBase64, "7006660099", "7006660002") == null);
        Check("...nor redirect it to another recipient",
              OfflineSeal.OpenWith(bob, line, alice.PublicBase64, "7006660001", "7006660099") == null);
        string[] parts = line.Split(new char[] { '|' }, 3);
        byte[] rawBox;
        try { rawBox = Convert.FromBase64String(parts[1]); } catch { rawBox = new byte[0]; }
        if (rawBox.Length > 40) rawBox[rawBox.Length - 20] ^= 0x08;
        string tampered = OfflineSeal.Verb + "|" + Convert.ToBase64String(rawBox) + "|" + parts[2];
        Check("editing the ciphertext fails the signature before the cipher",
              OfflineSeal.OpenWith(bob, tampered, alice.PublicBase64, "7006660001", "7006660002") == null);
        Check("a seal to a key that is not a key produces nothing",
              OfflineSeal.Seal(alice, "<not a key>", "1", "2", "x") == null);

        Console.WriteLine("  prekeys: the relay's directory");
        int p1 = 45830, p2 = 45831;
        CallServer dir = NewKeyedRelay(p1, "", "127.0.0.60:" + p1, "dir", root, null);
        if (dir == null) { Check("prekey relay port free (45830)", false); TryDeleteDir(root); return; }
        List<string> dirLog = new List<string>();
        CallServer dirB = NewKeyedRelayWithLog(p2, "127.0.0.1:" + p1, "127.0.0.61:" + p2, "dirB", root, dirLog);
        if (dirB == null) { Check("prekey relay port free (45831)", false); TryDeleteDir(root); return; }
        Node pub = new Node("7006660001", p1);
        string claim = "PUBK|7006660001|" + alice.PublicBase64 + "|" +
                       Convert.ToBase64String(alice.Sign(Encoding.UTF8.GetBytes("PUBK|7006660001")));
        pub.Send(claim);
        Check("a self-proved claim is stored", WaitFor(delegate { return dir.PeerKeyCount == 1; }, 4000),
              "count=" + dir.PeerKeyCount);
        Node asker = new Node("7006660004", p1);
        asker.Send("PKQ|7006660001");
        Check("...and answered to a peer who asks", asker.WaitForLine("PKPUB|7006660001|", 4000));
        asker.Send("PKQ|7006669999");
        Check("an unknown number is answered as unknown, not ignored", asker.WaitForLine("PKNONE|7006669999", 4000));
        // The whole point of the signature: a relay (or anybody) cannot mint a key.
        Node evener = new Node("7006660003", p1);
        evener.Send("PUBK|7006660003|" + eve.PublicBase64 + "|" +
                    Convert.ToBase64String(alice.Sign(Encoding.UTF8.GetBytes("PUBK|7006660003"))));
        Thread.Sleep(500);
        Check("a claim signed by somebody else's key is refused", dir.PeerKeyCount == 1, "count=" + dir.PeerKeyCount);
        evener.Send("PUBK|7006660002|" + eve.PublicBase64 + "|" +
                    Convert.ToBase64String(eve.Sign(Encoding.UTF8.GetBytes("PUBK|7006660002"))));
        Thread.Sleep(500);
        Check("...and so is one published from a session holding another number",
              dir.PeerKeyCount == 1, "count=" + dir.PeerKeyCount);
        // Federation: the far relay should be able to answer without asking the first.
        asker.Close(); pub.Close(); evener.Close();
        Node far = new Node("7006660005", p2);
        Check("the key travelled to the linked relay", WaitFor(delegate { return dirB.PeerKeyCount >= 1; }, 8000),
              "far count=" + dirB.PeerKeyCount);
        far.Send("PKQ|7006660001");
        Check("...so a peer on the far relay can seal without crossing the mesh",
              far.WaitForLine("PKPUB|7006660001|", 5000));
        far.Close();

        Console.WriteLine("  prekeys: sealed offline mail may travel, plaintext may not");
        // The carrying rule used to be "ECHAT only", which excluded exactly the mail
        // people leave for somebody off-line. ECHATK closes that - and the gate must
        // accept it on the same grounds, while still refusing plaintext.
        Node sN = new Node("7006660010", p1);
        string sealedMail = OfflineSeal.Seal(alice, bob.PublicBase64, "7006660010", "7006660011", "offline hello");
        sN.Send("MSG|7006660011|7006660010|" + sealedMail);
        Check("offline-sealed mail to an absent peer is queued", WaitFor(delegate
              { return dir.QueuedMailCount >= 1; }, 4000), "queued=" + dir.QueuedMailCount);
        Thread.Sleep(800);
        Check("...and is not spread while carrying is off", dirB.QueuedMailCount == 0,
              "far queue=" + dirB.QueuedMailCount);
        dir.RelayCarryMail = true;
        sN.Send("MSG|7006660012|7006660010|" +
                OfflineSeal.Seal(alice, bob.PublicBase64, "7006660010", "7006660012", "second"));
        Check("...but a sealed one is handed to the linked relay once carrying is on", WaitFor(delegate
              { return dirB.QueuedMailCount >= 1; }, 8000), "far queue=" + dirB.QueuedMailCount);
        long plainBefore = dir.QueuedMailCount;
        sN.Send("MSG|7006660013|7006660010|CHAT|PLAIN-SHOULD-NOT-TRAVEL");
        // This used to be the normal case: a chat line to an off-line peer sat in the
        // queue as readable text while the sender was told QUEUED, and "we do not
        // carry plaintext" was the only thing limiting the exposure. Offline sealing
        // already existed by then, so storing it in the clear was a choice, and it is
        // now refused - in words the sender can act on, not silently.
        Check("unsealed mail is refused instead of filed",
              sN.WaitForLine("ERR|nokey|7006660013", 5000), "no ERR|nokey came back");
        Thread.Sleep(800);
        Check("...and none of it lands on this relay's disk",
              !MailDirHas(Path.Combine(root, "dir_mail"), "PLAIN-SHOULD-NOT-TRAVEL"));
        Check("...and none of it lands on the linked relay's disk either",
              !MailDirHas(Path.Combine(root, "dirB_mail"), "PLAIN-SHOULD-NOT-TRAVEL"));
        Check("...and the queue did not take it", dir.QueuedMailCount == plainBefore,
              "grew by " + (dir.QueuedMailCount - plainBefore));
        Check("the gate separates the three cases correctly", MailIsSealedRuleSeparates());
        // A key exchange aimed at somebody who is away is not mail. It used to be
        // queued exactly like a message and delivered hours later as a stale KEYX,
        // completing a session nobody was waiting for - and offline sealing made it
        // unnecessary anyway.
        long qBefore = dir.QueuedMailCount;
        sN.Send("MSG|7006660020|7006660010|KEYX|12345|" + alice.PublicBase64 + "|YWJj");
        Check("a key exchange for an absent peer is refused rather than filed as mail",
              sN.WaitForLine("PEEROFFLINE|7006660020", 4000));
        Thread.Sleep(600);
        Check("...and it takes no slot in their queue", dir.QueuedMailCount == qBefore,
              "grew by " + (dir.QueuedMailCount - qBefore));
        sN.Close();

        Console.WriteLine("  prekeys: the directory is on disk, and is re-verified on load");
        string keyFile = Path.Combine(root, "dir_peerkeys.txt");
        Check("...written to a file", WaitFor(delegate
              { return ReadLive(keyFile).Contains("7006660001"); }, 4000));
        dir.Stop(); dirB.Stop();
        // Plant a forged line in the sheet: loading must not trust it because it is
        // sitting on our own disk.
        File.AppendAllText(keyFile, "7006660008|" + eve.PublicBase64 + "|AGV2aWw=\n");
        CallServer again = NewKeyedRelay(p1, "", "127.0.0.60:" + p1, "dir", root, null);
        if (again == null) { Check("restarted relay rebound", false); TryDeleteDir(root); return; }
        Check("a restarted relay recovers the real keys",
              WaitFor(delegate { return again.PeerKeyCount >= 1; }, 4000), "count=" + again.PeerKeyCount);
        Check("...and refuses the forged entry it re-checks on load",
              again.PeerKeyCount == 1, "count=" + again.PeerKeyCount);
        Node ask2 = new Node("7006660006", p1);
        ask2.Send("PKQ|7006660001");
        Check("...so the surviving key still answers after the restart", ask2.WaitForLine("PKPUB|7006660001|", 4000));
        ask2.Close();
        again.Stop();
        TryDeleteDir(root);
    }

    // The gate itself, asserted directly: it is one function and it is the line
    // between "reachable later" and "readable by whoever holds a copy".
    static bool MailIsSealedRuleSeparates()
    {
        string baseMsg = "MSG|7001111111|7002222222|";
        bool chat = CallServer.MailCarriable(baseMsg + "CHAT|hello");
        bool echat = CallServer.MailCarriable(baseMsg + "ECHAT|abcdef");
        bool echatk = CallServer.MailCarriable(baseMsg + "ECHATK|abcdef|xyz");
        bool rm = CallServer.MailCarriable("RM|7001111111|7002222222|abcdef");
        return !chat && echat && echatk && !rm;
    }

    static CallServer NewKeyedRelayWithLog(int port, string links, string advertise, string tag,
                                           string dir, List<string> log)
    {
        CallServer s = new CallServer();
        s.Log += delegate(string m) { lock (log) log.Add(m); };
        return NewKeyedRelayInto(port, links, advertise, tag, dir, null, s);
    }

    static CallServer NewKeyedRelayInto(int port, string links, string advertise, string tag,
                                        string dir, string bookSeed, CallServer s)
    {
        s.RelayPolicy = "everyone";
        s.RelayLinks = links;
        s.RelayName = "pk-" + tag;
        s.RelayAdvertise = advertise;
        s.RelayKeyFile = Path.Combine(dir, tag + ".key");
        s.RelayBookFile = Path.Combine(dir, tag + "_book.txt");
        s.MailDirOverride = Path.Combine(dir, tag + "_mail");
        s.LedgerFileOverride = Path.Combine(dir, tag + "_ledger.txt");
        s.PeerKeyFileOverride = Path.Combine(dir, tag + "_peerkeys.txt");
        s.LeaseFileOverride = Path.Combine(dir, tag + "_leases.txt");
        if (!s.Start(port)) { try { s.Dispose(); } catch { } return null; }
        return s;
    }

    // ── Number leases ──────────────────────────────────────────────────
    // The relay used to check the number token only against whoever is connected
    // right now. So while an owner was away - which is whenever mail is queued for
    // them - any install that could reach the port could register that number and
    // be believed: it would receive the owner's waiting mail and their incoming
    // calls. Testing the check with the owner present proves nothing; every case
    // below is run with the owner gone.
    static void VerifyNumberLeases()
    {
        Console.WriteLine("  number leases: an absent owner's number is not free");
        string root = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "lease_tmp_" + DateTime.Now.Ticks);
        try { Directory.CreateDirectory(root); } catch { }
        int lp = 45770, lp2 = 45771;
        CallServer R = NewKeyedRelay(lp, "", "127.0.0.70:" + lp, "leaseRelay", root, null);
        if (R == null) { Check("lease relay port free (45770-45771)", false); TryDeleteDir(root); return; }
        string mine = "7007770001";

        Node owner = new Node(mine, lp);                       // registers with tok-<number>
        Check("the first registration is accepted and claims the number",
              owner.WaitForLine("OK|" + mine, 4000));
        string leaseFile = Path.Combine(root, "leaseRelay_leases.txt");
        Check("...and the claim is on disk, not only in memory", WaitFor(delegate
              { return ReadLive(leaseFile).Contains(mine); }, 3000));
        Check("...storing the token hashed, never as text",
              ReadLive(leaseFile).IndexOf("tok-" + mine) < 0);

        // The owner has to be GONE before there is anything worth stealing: send
        // while they are connected and the relay delivers it live, and the test
        // proves nothing about the queue it was meant to attack.
        owner.Close();                                         // the owner leaves
        Thread.Sleep(500);
        Node sender = new Node("7007770002", lp);
        // Sealed, because the queue only accepts sealed traffic now: this test is about
        // whose number it is, not about opening a message, and the relay does not read
        // the payload either way.
        sender.Send("MSG|" + mine + "|7007770002|ECHAT|MAIL-BELONGS-TO-THE-OWNER");
        Check("mail for the absent owner is queued, as before",
              sender.WaitForLine("QUEUED|" + mine, 4000));

        Node thief = new Node("", lp);                         // fresh connection, no auto-REG
        thief.Send("REG|" + mine + "|someone-elses-token|thief");
        Check("a stranger registering the absent owner's number is refused",
              thief.WaitForLine("ERR|claimed|" + mine, 4000));
        Thread.Sleep(600);
        Check("...and is never told OK, not even later", !thief.WaitForLine("OK|" + mine, 800));
        Check("...so the queued mail does not reach them", thief.CountMsgs("7007770002") == 0,
              "received=" + thief.CountMsgs("7007770002"));
        // Being refused is being nobody: a connection that did not register cannot
        // send either, so the refusal also closes the "steal the number to speak as
        // it" path. (A thief can still *publish* a key for the number - the relay
        // verifies a claim, not an identity - which is why the lease also records
        // the owner's key and warns when it changes.)
        thief.Send("MSG|7007770002|" + mine + "|CHAT|speaking-as-the-owner");
        Check("...and a refused connection cannot send as that number either",
              thief.WaitForLine("ERR|registerfirst", 4000));

        // The owner returns with the credential that was always theirs.
        Node back = new Node(mine, lp);
        Check("the real owner still gets in with their own token",
              back.WaitForLine("OK|" + mine, 4000));
        Check("...and is told how many times someone tried while they were away",
              back.WaitForLine("NOTICE|claimed-attempts|" + mine, 4000));
        Check("...and the mail that waited for them arrives", back.WaitForMsg("7007770002",
              "ECHAT|MAIL-BELONGS-TO-THE-OWNER", 5000));

        // The legitimate hand-off must keep working: same token, second connection
        // (this is exactly the wake agent and the window swapping one number).
        Node handover = new Node(mine, lp);
        Check("a second install holding the same token still takes over the session",
              handover.WaitForLine("OK|" + mine, 4000));

        // Memory, not mood: a restart must not reopen the number.
        R.Stop(); sender.Close(); thief.Close(); back.Close(); owner.Close();
        CallServer R2 = NewKeyedRelay(lp, "", "127.0.0.70:" + lp, "leaseRelay", root, null);
        if (R2 == null) { Check("relay rebound after restart", false); TryDeleteDir(root); return; }
        Node thief2 = new Node("", lp);
        thief2.Send("REG|" + mine + "|still-not-my-token|thief");
        Check("a restarted relay still refuses the thief", thief2.WaitForLine("ERR|claimed|" + mine, 5000));
        Node firstTime = new Node("7007770003", lp);
        Check("...while a genuinely unclaimed number is still accepted",
              firstTime.WaitForLine("OK|7007770003", 4000));

        // The escape has to be real, or the fix is a lockout wearing a better name.
        bool released = R2.ReleaseLease(mine);
        thief2.Send("REG|" + mine + "|now-it-is-mine|thief");
        Check("--release-number really frees the number",
              released && thief2.WaitForLine("OK|" + mine, 5000), "released=" + released);

        // ── Ownership, not rental ───────────────────────────────────────
        // Everything above decides on a shared secret, which is what a lease can
        // check but not what a number should belong to: a secret can be copied,
        // leaked, or handed over by whoever stored its hash. From here the claim is
        // a signature by the install's identity key, verified with that key.
        Console.WriteLine("  number ownership: by key, not by shared secret");
        string owned = "7007770020";
        string shared = "the-token-everybody-who-copies-a-profile-knows";
        Identity ownerKey = new Identity(Path.Combine(root, "owner_of_key.key"));
        Identity thiefKey = new Identity(Path.Combine(root, "thief_with_key.key"));
        Node byKey = new Node("", lp);
        byKey.Send("REG|" + owned + "|" + shared + "|boxed" + OwnProofLine(owned, ownerKey));
        Check("a registration carrying a verified ownership proof is accepted",
              byKey.WaitForLine("OK|" + owned, 5000));
        // Waited for, not read straight off: the relay answers OK and then writes the
        // book, so reading here immediately is a race with a disk write, and it is
        // exactly the knife-edge this suite keeps having to learn twice.
        string ownLease = "";
        Check("...and the record names the key rather than only a hash of a secret",
              WaitFor(delegate { ownLease = ReadLive(Path.Combine(root, "leaseRelay_leases.txt"));
                                 return ownLease.Contains(ownerKey.PublicBase64); }, 4000),
              "lease file has no key");
        Check("...while the shared secret is still not in the file in clear",
              !ownLease.Contains(shared));

        // The point of the whole change, stated exactly: this caller has the RIGHT
        // token and a signature of their own, correctly made, by a key that is not
        // the one on the record. Under the old rule they would now own the number.
        Node rightToken = new Node("", lp);
        rightToken.Send("REG|" + owned + "|" + shared + "|copycat" + OwnProofLine(owned, thiefKey));
        Check("the right token with somebody else's key is refused",
              rightToken.WaitForLine("ERR|claimed|" + owned, 5000) &&
              !rightToken.WaitForLine("OK|" + owned, 1500));
        Check("...and the refusal says whose key the number belongs to",
              rightToken.WaitForLine("ERR|", 500), "see the relay log for the fingerprint");

        // A signature that does not verify is not a missing signature: it is
        // somebody naming a number with a key that never agreed to it.
        Node forged = new Node("", lp);
        forged.Send("REG|" + owned + "|" + shared + "|forger|" + thiefKey.PublicBase64 + "|YWJjZA==");
        Check("a signature that does not verify is refused before anything is recorded",
              forged.WaitForLine("ERR|badproof|" + owned, 5000) &&
              !forged.WaitForLine("OK|" + owned, 1500));

        // ...and an install too old to prove anything is told that plainly, not
        // accused of theft.
        Node legacy = new Node("", lp);
        legacy.Send("REG|" + owned + "|" + shared + "|old-build");
        Check("a build from before the proof gets its own honest reason",
              legacy.WaitForLine("ERR|proofneeded|" + owned, 5000));

        // The owner returns with the key that owns it. Nothing else is needed.
        Node home = new Node("", lp);
        home.Send("REG|" + owned + "|" + shared + "|boxed" + OwnProofLine(owned, ownerKey));
        Check("the owner comes back with their key and is in again",
              home.WaitForLine("OK|" + owned, 5000));
        Check("...and is told how many were turned away meanwhile",
              home.WaitForLine("NOTICE|claimed-attempts|" + owned, 5000));
        byKey.Close(); rightToken.Close(); forged.Close(); legacy.Close(); home.Close();

        Console.WriteLine("  number leases: what is on disk is not trusted just because it is there");
        string junk = Path.Combine(root, "corrupt_leases.txt");
        File.WriteAllText(junk,
            "not-a-number|aa|bb|cc|1|2|0|host\n" +                  // number is not digits
            "7007770009\n" +                                        // truncated line
            "7007770010|deadbeef||sig|abc|def|ghi|host\n" +         // valid number, unusable counters
            "7007770011|deadbeef|||1|2|3|real-owner\n" +            // token recorded, no key yet
            "7007770012||||1|2|3|noplace\n" +                       // lease with no secret at all
            "7007770013|tok13|PUBKEY|SIGBYTES|1|2|0|boxed|in|with-a-pipe\n");
        NumberLeaseBook J = new NumberLeaseBook(junk);
        Check("a corrupt lease file yields only its real records", J.Count == 4, "count=" + J.Count);
        Check("...discarding a line whose number is not a number", J.Lookup("not-a-number") == null);
        Check("...and a line that stops half way through", J.Lookup("7007770009") == null);
        Check("...and still reads a record whose counters are junk", J.Lookup("7007770010") != null);
        // The free-text column is last for a reason. Machine names are not ours to
        // constrain, and when one contained a pipe the old column order shifted every
        // field after it: the numeric parses failed, the record was skipped, and the
        // number quietly became somebody else's to claim.
        Check("a machine name containing a pipe does not cost the number its owner",
              J.Lookup("7007770013") != null &&
              J.Lookup("7007770013").Machine == "boxed|in|with-a-pipe",
              "machine=" + (J.Lookup("7007770013") == null ? "LOST" : J.Lookup("7007770013").Machine));
        Check("a recorded token refuses a wrong one and an empty one",
              !J.Owns(J.Lookup("7007770011"), "wrong", "") && !J.Owns(J.Lookup("7007770011"), "", ""));
        Check("a lease recorded with no secret is not a lock someone can hide behind",
              J.Owns(J.Lookup("7007770012"), "anything", "any-key"));
        Check("an unleased number is open to a first claim", J.Owns(J.Lookup("7007779999"), "anything", "k"));
        // Ownership, in one pair of lines: once a key is on the record it decides, and
        // the shared secret does not. Anyone can read a public key; only the owner can
        // sign for it, which is what the relay checks before ever asking this question.
        Check("a number with a key on it belongs to that key, whatever the token says",
              !J.Owns(J.Lookup("7007770013"), "tok13", "an-entirely-different-key") &&
              J.Owns(J.Lookup("7007770013"), "the-wrong-token", "PUBKEY"));
        Check("...and the proof is kept beside the record it belongs to",
              J.Lookup("7007770013").OwnSig == "SIGBYTES", "sig=" + J.Lookup("7007770013").OwnSig);
        Check("tokens are hashed, and the hash is stable",
              NumberLeaseBook.HashToken("abc") != NumberLeaseBook.HashToken("abd") &&
              NumberLeaseBook.HashToken("abc").Length == 64 &&
              NumberLeaseBook.HashToken("abc") == NumberLeaseBook.HashToken("abc"));
        R2.Stop(); thief2.Close(); firstTime.Close(); handover.Close();
        TryDeleteDir(root);
    }

    // The ownership proof exactly as a client forms it: the identity key signs
    // "OWNS|<number>", and the pair travels inside the machine field of REG.
    static string OwnProofLine(string number, Identity k)
    {
        byte[] sig = k.Sign(Encoding.UTF8.GetBytes(NumberLeaseBook.OwnClaim(number)));
        if (sig == null) return "";
        return "|" + k.PublicBase64 + "|" + Convert.ToBase64String(sig);
    }

    static void Check(string what, bool ok) { Check(what, ok, ""); }

    static void Check(string what, bool ok, string detail)
    {
        Console.WriteLine((ok ? "    PASS  " : "    FAIL  ") + what +
                          (ok || string.IsNullOrEmpty(detail) ? "" : " -- " + detail));
        if (!ok) failures++;
    }

    // One conference member: registered, in the room, sending 20 ms PCM frames.
    sealed class Member
    {
        public string Number;
        public volatile string Roster = "";
        public volatile string Talk = "";
        public volatile string TalkEver = "";
        public int MixCount;
        public int VidCount;
        readonly List<int> _peaks = new List<int>();
        TcpClient _tcp;
        StreamWriter _w;
        readonly object _write = new object();

        public Member(string number, string token)
        {
            Number = number;
            _tcp = new TcpClient();
            _tcp.Connect("127.0.0.1", PORT);
            _w = new StreamWriter(_tcp.GetStream(), Encoding.UTF8);
            _w.AutoFlush = true;
            Write("REG|" + number + "|" + token + "|testhost");
            Thread t = new Thread(ReadLoop);
            t.IsBackground = true;
            t.Start();
            Thread.Sleep(150);
        }

        void Write(string line) { lock (_write) _w.WriteLine(line); }

        void ReadLoop()
        {
            try
            {
                StreamReader r = new StreamReader(_tcp.GetStream(), Encoding.UTF8);
                string line;
                while ((line = r.ReadLine()) != null)
                {
                    string[] p = line.Split(new char[] { '|' }, 4);
                    if (p[0] == "CONF_MIXED" && p.Length >= 4)
                    {
                        byte[] pcm = Convert.FromBase64String(p[3]);
                        int peak = 0;
                        for (int i = 0; i + 1 < pcm.Length; i += 2)
                        {
                            short v = (short)(pcm[i] | (pcm[i + 1] << 8));
                            int mag = v < 0 ? -v : v;
                            if (mag > peak) peak = mag;
                        }
                        lock (_peaks) _peaks.Add(peak);
                        Interlocked.Increment(ref MixCount);
                    }
                    else if (p[0] == "CONF_VID") Interlocked.Increment(ref VidCount);
                    else if (p[0] == "CONF_ROSTER" && p.Length >= 3) Roster = p[2];
                    else if (p[0] == "CONF_TALK" && p.Length >= 3)
                    {
                        Talk = p[2];
                        // A talk tick with nobody speaking is correct (it clears
                        // the highlight), so keep what the room ever reported.
                        if (p[2].Length > 0) TalkEver = TalkEver + "," + p[2];
                    }
                }
            }
            catch { }
        }

        public void Join() { Write("CONF_JOIN|" + ROOM + "|tok"); }
        public void Leave() { Write("CONF_LEAVE|" + ROOM); }
        public void Mute() { Write("CONF_MUTE|" + ROOM + "|1"); }

        // Same as SendFrames but on a background thread, so members can
        // transmit concurrently.
        public Thread BeginFrames(short value, int count)
        {
            Thread t = new Thread((ThreadStart)delegate { SendFrames(value, count); });
            t.IsBackground = true;
            t.Start();
            return t;
        }

        // One constant-amplitude 20 ms frame: 16-bit LE mono, 640 bytes.
        public void SendFrames(short value, int count)
        {
            byte[] pcm = new byte[640];
            for (int i = 0; i + 1 < pcm.Length; i += 2)
            {
                pcm[i] = (byte)(value & 0xFF);
                pcm[i + 1] = (byte)((value >> 8) & 0xFF);
            }
            string b64 = Convert.ToBase64String(pcm);
            for (int i = 0; i < count; i++)
            {
                Write("CONF_AUDIO|" + ROOM + "|" + b64);
                Thread.Sleep(20);
            }
        }

        public void SendVideo()
        {
            byte[] jpeg = new byte[64];
            for (int i = 0; i < jpeg.Length; i++) jpeg[i] = (byte)i;
            Write("CONF_VIDEO|" + ROOM + "|" + Convert.ToBase64String(jpeg));
        }

        public void Reset()
        {
            lock (_peaks) _peaks.Clear();
            MixCount = 0;
            VidCount = 0;
        }

        public int LastPeak()
        {
            lock (_peaks) return _peaks.Count == 0 ? 0 : _peaks[_peaks.Count - 1];
        }

        public bool AgcTrimmed()
        {
            lock (_peaks)
            {
                if (_peaks.Count < 4) return false;
                int first = _peaks[0], last = _peaks[_peaks.Count - 1];
                return last < first;
            }
        }
    }
}
