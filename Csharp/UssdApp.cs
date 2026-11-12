using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.IO.Compression;
using System.IO.Ports;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Animation;
using System.Windows.Media.Imaging;
using System.Windows.Interop;
using System.Windows.Threading;

namespace UssdApp
{
    // ======================= Boot / entry =======================
    public static class Boot
    {
        private static readonly System.Diagnostics.Stopwatch _sw = System.Diagnostics.Stopwatch.StartNew();

        public static void Mark(string msg)
        {
            if (Environment.GetEnvironmentVariable("USSD_TRACE") != "1") return;
            try
            {
                string path = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "startup.log");
                File.AppendAllText(path, _sw.ElapsedMilliseconds + "ms [t" +
                    Thread.CurrentThread.ManagedThreadId + "] " + msg + "\r\n");
            }
            catch { }
        }
    }

    public static class Program
    {
        [STAThread]
        public static int Main(string[] args)
        {
            try
            {
                Boot.Mark("Main entered");
                Cli.Parse(args);
                // Set the data home before anything reads a user file, so the
                // window and the wake agent can be aimed at the same profile.
                Home.Set(Cli.HomeOverride);
                if (args.Length > 0 && args[0] == "--selftest")
                    return SelfTest.Run();
                if (Cli.Serve)
                    return Headless.RunRelay();
                if (Cli.HeadlessWanted)
                    return Cli.Agent ? Headless.RunAgent() : Headless.Run();
                Application app = new Application();
                Boot.Mark("Application created");
                var win = new MainWindow();
                Boot.Mark("MainWindow constructed");
                win.Show();
                Boot.Mark("Show returned");
                app.Run();
                Boot.Mark("Application.Run returned");
                return 0;
            }
            catch (Exception ex)
            {
                try
                {
                    File.WriteAllText(
                        Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "crash.log"),
                        ex.ToString());
                }
                catch { }
                return 2;
            }
        }
    }

    // ======================= Self test (headless) =======================
    public static class SelfTest
    {
        public static int Run()
        {
            StringBuilder sb = new StringBuilder();
            bool pass = false;
            try
            {
                string[] ports = SerialPort.GetPortNames();
                sb.AppendLine("Ports: " + string.Join(", ", ports));
                List<PortInfo> ranked = PortDetector.RankCandidates(PortDetector.GetPortsWithNames(), null);
                List<string> candidates = new List<string>();
                foreach (PortInfo pi in ranked) candidates.Add(pi.Port);
                foreach (string p in ports) if (!candidates.Contains(p)) candidates.Add(p);
                sb.AppendLine("Trying ports: " + string.Join(", ", candidates));

                foreach (string p in candidates)
                {
                    try
                    {
                        sb.AppendLine("--- try " + p + " ---");
                        using (ModemService svc = new ModemService())
                        {
                            svc.Open(p, 115200);
                            string[] r = svc.SendCommand("AT", ModemService.OkTerm, 5000);
                            string joined = string.Join(" | ", r);
                            sb.AppendLine("AT => " + joined);
                            if (!HasOk(r)) { sb.AppendLine("no OK, next port"); svc.Close(); continue; }
                            pass = true;
                            sb.AppendLine("MODEM OK ON: " + p);
                            RunBatch(svc, sb);
                            svc.Close();
                        }
                        break;
                    }
                    catch (Exception ex2) { sb.AppendLine(p + " failed: " + ex2.Message); }
                }
            }
            catch (Exception ex) { sb.AppendLine("ERROR: " + ex.Message); }

            sb.AppendLine("--- VoIP crypto ---");
            try
            {
                sb.AppendLine("--- TNSRL route flow ---");
                IPAddress localPeer = IPAddress.Parse("192.168.10.22");
                string announcement = Tnsrl.BuildAnnouncement("peer|one", localPeer, 45672);
                TnsrlRoute parsedRoute;
                bool parsed = Tnsrl.TryParse(announcement, localPeer, out parsedRoute);
                TnsrlRouteFlow flow = new TnsrlRouteFlow();
                flow.Observe(parsedRoute);
                List<IPEndPoint> flowCandidates = flow.Candidates(localPeer);
                bool tnsrlOk = parsed && parsedRoute != null &&
                    parsedRoute.Name == "peer|one" && flowCandidates.Count == 1 &&
                    flowCandidates[0].Port == 45672;
                sb.AppendLine("TNSRL route announcement and flow: " + (tnsrlOk ? "OK" : "FAIL"));
                TnsrlRoute rejectedRoute;
                bool rejected = Tnsrl.TryParse(
                    Tnsrl.BuildAnnouncement("public", IPAddress.Parse("8.8.8.8"), 45672),
                    IPAddress.Parse("8.8.8.8"), out rejectedRoute);
                sb.AppendLine("TNSRL public endpoint rejected: " + (!rejected ? "OK" : "FAIL"));
                if (!tnsrlOk || rejected) pass = false;
            }
            catch (Exception ex)
            {
                sb.AppendLine("TNSRL EX: " + ex.Message);
                pass = false;
            }

            try
            {
                VoipCrypto a = new VoipCrypto();
                VoipCrypto b = new VoipCrypto();
                byte[] ka = a.DeriveSharedKey(b.Pub);
                byte[] kb = b.DeriveSharedKey(a.Pub);
                bool match = ka.Length == kb.Length;
                if (match)
                    for (int i = 0; i < ka.Length; i++)
                        if (ka[i] != kb[i]) { match = false; break; }
                sb.AppendLine("DH key agreement: " + (match ? "OK (" + ka.Length + " bytes)" : "MISMATCH"));
                byte[] iv = new byte[16];
                for (int i = 0; i < 16; i++) iv[i] = (byte)(i + 1);
                byte[] plain = Encoding.UTF8.GetBytes("voip selftest payload 1234567890");
                byte[] enc = VoipCrypto.AesCtr(ka, plain, iv);
                byte[] dec = VoipCrypto.AesCtr(ka, enc, iv);
                bool eq = plain.Length == dec.Length;
                if (eq)
                    for (int i = 0; i < plain.Length; i++)
                        if (plain[i] != dec[i]) { eq = false; break; }
                sb.AppendLine("AES-CTR roundtrip: " + (eq ? "OK" : "FAIL"));
                if (!match || !eq) pass = false;
            }
            catch (Exception ex) { sb.AppendLine("VoIP EX: " + ex.Message); pass = false; }

            sb.AppendLine("--- Identity + sealed chat (hostile relay model) ---");
            try
            {
                bool secOk = true;
                string tmp = Path.Combine(Path.GetTempPath(), "ussd_sec_" + DateTime.Now.Ticks);
                Directory.CreateDirectory(tmp);
                Identity ia = new Identity(Path.Combine(tmp, "id_a.key")); ia.Number = "7003256013";
                Identity ib = new Identity(Path.Combine(tmp, "id_b.key")); ib.Number = "7003256099";

                // 1. Signatures bind key + context + signer number.
                byte[] s = ia.SignText("KEYX|abc");
                if (!Identity.VerifyText(ia.PublicBase64, "KEYX|abc", s, "7003256013"))
                { sb.AppendLine("Identity signature roundtrip: FAIL"); secOk = false; }
                else sb.AppendLine("Identity signature roundtrip: OK");
                if (Identity.VerifyText(ib.PublicBase64, "KEYX|abc", s, "7003256013"))
                { sb.AppendLine("Signature accepted a stranger's identity key: FAIL"); secOk = false; }
                else sb.AppendLine("Signature rejects a stranger's identity key: OK");
                if (Identity.VerifyText(ia.PublicBase64, "KEYXOK|abc", s, "7003256013"))
                { sb.AppendLine("Signature accepted a different context: FAIL"); secOk = false; }
                else sb.AppendLine("Signature binds the handshake context: OK");
                if (Identity.VerifyText(ia.PublicBase64, "KEYX|abc", s, "7003256099"))
                { sb.AppendLine("Signature accepted another App ID: FAIL"); secOk = false; }
                else sb.AppendLine("Signature binds the App ID: OK");

                // 2. Authenticated agreement, both sides deriving one key.
                ChatHandshake ha = new ChatHandshake();
                ChatHandshake hb = new ChatHandshake();
                string keyX = ha.Build(ia, false);            // KEYX|dh|id|sig
                string ack = hb.Build(ib, true);              // KEYXOK|dh|id|sig
                string[] qx = keyX.Split('|');
                string[] qk = ack.Split('|');
                ChatKey ka = ha.Accept("KEYXOK", qk[1], qk[2], qk[3], "7003256099");
                ChatKey kb = hb.Accept("KEYX", qx[1], qx[2], qx[3], "7003256013");
                if (ka == null || kb == null)
                { sb.AppendLine("Authenticated handshake: FAIL (signature did not verify)"); secOk = false; }
                else
                {
                    string canary = "canary-never-leave-this-device";
                    string sealedLine = "ECHAT|" + ka.Encrypt("CHAT|" + canary);
                    string opened = kb.Decrypt(sealedLine.Substring(6));
                    if (opened != "CHAT|" + canary)
                    { sb.AppendLine("Both peers derive one session key: FAIL (" + opened + ")"); secOk = false; }
                    else sb.AppendLine("Both peers derive one session key: OK");

                    // 3. Everything the relay forwards is opaque to the relay.
                    List<string> wire = new List<string>();
                    wire.Add(keyX); wire.Add(ack); wire.Add(sealedLine);
                    bool leaked = false;
                    foreach (string w in wire)
                        if (w.Contains(canary)) { leaked = true; break; }
                    if (leaked) { sb.AppendLine("Relay-visible lines hide the message: FAIL"); secOk = false; }
                    else sb.AppendLine("Relay-visible lines hide the message: OK (" + wire.Count + " lines inspected)");

                    // 4. Tampering with a sealed line is caught, not decrypted.
                    // Flip a payload BIT (not a base64 character) so this can
                    // only pass by the MAC actually rejecting it.
                    byte[] rawB = Convert.FromBase64String(sealedLine.Substring(6));
                    rawB[rawB.Length / 2] ^= 1;
                    string tampered = kb.Decrypt(Convert.ToBase64String(rawB));
                    if (tampered != null) { sb.AppendLine("HMAC rejects a tampered ciphertext: FAIL"); secOk = false; }
                    else sb.AppendLine("HMAC rejects a tampered ciphertext: OK");
                    string replay = kb.Decrypt(sealedLine.Substring(6));
                    if (replay != null) { sb.AppendLine("Replay of a sealed message is rejected: FAIL"); secOk = false; }
                    else sb.AppendLine("Replay of a sealed message is rejected: OK");
                }

                // 5. A relay that swaps keys is detected by the signature check.
                Identity mallory = new Identity(Path.Combine(tmp, "id_m.key")); mallory.Number = "7003256013";
                ChatHandshake hm = new ChatHandshake();
                string swapped = hb.Build(ib, true).Replace(qk[2], mallory.PublicBase64);
                string[] sw = swapped.Split('|');
                ChatKey victim = ha.Accept("KEYXOK", sw[1], sw[2], sw[3], "7003256099");
                if (victim != null) { sb.AppendLine("Key-swap (MITM) rejected: FAIL"); secOk = false; }
                else sb.AppendLine("Key-swap (MITM) rejected: OK");

                // 6. Trust-on-first-use flags a replaced peer key.
                PeerIdentityBook book = new PeerIdentityBook(Path.Combine(tmp, "peers.txt"));
                PeerIdentityBook.Trust t1 = book.Check("7003256099", ib.PublicBase64);
                PeerIdentityBook.Trust t2 = book.Check("7003256099", ib.PublicBase64);
                PeerIdentityBook.Trust t3 = book.Check("7003256099", mallory.PublicBase64);
                if (t1 != PeerIdentityBook.Trust.New || t2 != PeerIdentityBook.Trust.Same || t3 != PeerIdentityBook.Trust.Changed)
                { sb.AppendLine("TOFU book (new/same/changed): FAIL -> " + t1 + "," + t2 + "," + t3); secOk = false; }
                else if (!string.Equals(book.Lookup("7003256099"), ib.PublicBase64, StringComparison.Ordinal))
                { sb.AppendLine("TOFU book keeps the original key until the user accepts a replacement: FAIL"); secOk = false; }
                else sb.AppendLine("TOFU book detects a replaced peer key without overwriting the trusted one: OK");

                // 7. Safety numbers match for both directions.
                string sn1 = Identity.SafetyNumber(ia.PublicBase64, ib.PublicBase64);
                string sn2 = Identity.SafetyNumber(ib.PublicBase64, ia.PublicBase64);
                if (sn1 != sn2 || sn1.Length < 60) { sb.AppendLine("Safety number symmetry: FAIL"); secOk = false; }
                else sb.AppendLine("Safety number symmetric: OK (" + sn1.Substring(0, 11) + "...)");

                // 8. Release metadata is authenticated without giving the app
                // permission to fetch or execute an untrusted update.
                string hash = new string('A', 64);
                string updateUri = "https://updates.example.invalid/ussd/UssdApp-4.3.0.exe";
                string updateClaim = SignedUpdateManifest.Claim("4.3.0", hash, 123456, updateUri);
                string updateSig = Convert.ToBase64String(ia.Sign(Encoding.UTF8.GetBytes(updateClaim)));
                SignedUpdateManifest update;
                bool parsedUpdate = SignedUpdateManifest.TryParse(
                    "USSDUPDATE|1|4.3.0|" + hash + "|123456|" + updateUri + "|" + updateSig,
                    out update);
                if (!parsedUpdate || !update.Verify(ia.PublicBase64))
                { sb.AppendLine("Signed update manifest verification: FAIL"); secOk = false; }
                else sb.AppendLine("Signed update manifest verification: OK");
                if (parsedUpdate && update.Verify(ib.PublicBase64))
                { sb.AppendLine("Signed update rejects the wrong publisher key: FAIL"); secOk = false; }
                else sb.AppendLine("Signed update rejects the wrong publisher key: OK");

                // 9. A file chunk is independently encrypted/authenticated by
                // the one-time transfer key disclosed only in the sealed offer.
                byte[] transferSecret = new byte[32];
                for (int i = 0; i < transferSecret.Length; i++) transferSecret[i] = (byte)(i * 7 + 3);
                ChatKey transferTx = ChatKey.FromMaterial(transferSecret);
                ChatKey transferRx = ChatKey.FromMaterial(transferSecret);
                byte[] fileChunk = new byte[1024];
                for (int i = 0; i < fileChunk.Length; i++) fileChunk[i] = (byte)(i * 13);
                string sealedChunk = transferTx.Encrypt(Convert.ToBase64String(fileChunk));
                byte[] sealedRaw = Convert.FromBase64String(sealedChunk);
                sealedRaw[sealedRaw.Length / 2] ^= 1;
                bool tamperRejected = transferRx.Decrypt(Convert.ToBase64String(sealedRaw)) == null;
                string openedChunk = transferRx.Decrypt(sealedChunk);
                bool chunkOk = false;
                if (openedChunk != null)
                {
                    byte[] openedBytes = Convert.FromBase64String(openedChunk);
                    chunkOk = openedBytes.Length == fileChunk.Length;
                    if (chunkOk)
                        for (int i = 0; i < fileChunk.Length; i++)
                            if (openedBytes[i] != fileChunk[i]) { chunkOk = false; break; }
                }
                if (!chunkOk || !tamperRejected)
                { sb.AppendLine("Encrypted file chunk roundtrip and tamper rejection: FAIL"); secOk = false; }
                else sb.AppendLine("Encrypted file chunk roundtrip and tamper rejection: OK");

                // 10. Tracker bridge requires an HTTPS endpoint without embedded credentials.
                bool tr0 = TrackerBridge.IsSafeServerUrl("http://127.0.0.1:8080");
                bool tr1 = TrackerBridge.IsSafeServerUrl("https://example.com");
                bool tr2 = TrackerBridge.IsSafeServerUrl("file://c:/tmp");
                bool tr3 = TrackerBridge.IsSafeServerUrl("javascript:alert(1)");
                bool tr4 = TrackerBridge.IsSafeServerUrl("https://user@example.com");
                if (tr0 || !tr1 || tr2 || tr3 || tr4)
                { sb.AppendLine("Tracker bridge endpoint policy: FAIL"); secOk = false; }
                else sb.AppendLine("Tracker bridge endpoint policy: OK");

                sb.AppendLine("Security: " + (secOk ? "OK" : "FAIL"));
                if (!secOk) pass = false;
                try { Directory.Delete(tmp, true); } catch { }
            }
            catch (Exception ex) { sb.AppendLine("Security EX: " + ex.Message); pass = false; }

            sb.AppendLine("--- Transport routing (capability policy) ---");
            try
            {
                bool routeOk = true;
                LoopTransport.Reset();

                // A relay transport that records the exact bytes it was handed.
                List<byte[]> relayTx = new List<byte[]>();
                RelayTransport relay = new RelayTransport(
                    delegate(string to, byte[] frame) { relayTx.Add(frame); return true; },
                    delegate() { return true; });
                LoopTransport lan = new LoopTransport("lan", 0, 0);
                LoopTransport radio = new LoopTransport("radio", 60, 1200);
                LoopTransport mesh = new LoopTransport("mesh", 0, 0, true);

                TransportRouter all = new TransportRouter();
                all.Add(relay); all.Add(lan); all.Add(radio); all.Add(mesh);
                TransportRouter radioOnly = new TransportRouter();
                radioOnly.Add(radio);
                TransportRouter relayOnly = new TransportRouter();
                relayOnly.Add(relay);
                TransportRouter meshOnly = new TransportRouter();
                meshOnly.Add(mesh);
                TransportRouter empty = new TransportRouter();

                string why;

                // 1. A link the user owns beats the third-party relay hop.
                ITransport pick = all.Pick(200, PayloadClass.Text, out why);
                if (pick == null || pick.Name == "relay")
                { sb.AppendLine("Own link preferred over the relay: FAIL -> " + (pick == null ? "none" : pick.Name)); routeOk = false; }
                else sb.AppendLine("Own link preferred over the relay: OK (" + pick.Name + ")");

                // 2. The relay still takes what a narrow link physically cannot.
                pick = relayOnly.Pick(5000, PayloadClass.Text, out why);
                if (pick == null || pick.Name != "relay")
                { sb.AppendLine("Relay carries a 5000B text frame: FAIL"); routeOk = false; }
                else sb.AppendLine("Relay carries a 5000B text frame: OK");
                TransportRouter relayPlusRadio = new TransportRouter();
                relayPlusRadio.Add(relay); relayPlusRadio.Add(radio);
                if (!relayPlusRadio.RadioCanCarry(40, PayloadClass.Text) || relayPlusRadio.RadioCanCarry(5000, PayloadClass.Text))
                { sb.AppendLine("Radio frame ceiling (40B yes, 5000B no): FAIL"); routeOk = false; }
                else sb.AppendLine("Radio frame ceiling (40B yes, 5000B no): OK");

                // 3. Media is never routed onto a link too slow for voice.
                //    A real LoRa frame ceiling rejects media on size first, so
                //    use a wide-but-slow link to prove the bitrate floor itself.
                LoopTransport slowwide = new LoopTransport("slowwide", 65536, 1200);
                TransportRouter slowOnly = new TransportRouter();
                slowOnly.Add(slowwide);
                pick = slowOnly.Pick(4000, PayloadClass.Media, out why);
                if (pick != null || why.IndexOf("too slow") < 0)
                { sb.AppendLine("Media refused on a 1200 bps link: FAIL -> " + (pick == null ? why : pick.Name)); routeOk = false; }
                else sb.AppendLine("Media refused on a 1200 bps link: OK (" + why + ")");
                pick = slowOnly.Pick(4000, PayloadClass.Text, out why);
                if (pick == null) { sb.AppendLine("Same slow link still carries text: FAIL -> " + why); routeOk = false; }
                else sb.AppendLine("Same slow link still carries text: OK");
                pick = radioOnly.Pick(4000, PayloadClass.Media, out why);
                if (pick != null) { sb.AppendLine("Narrow radio refuses media outright: FAIL -> " + pick.Name); routeOk = false; }
                else sb.AppendLine("Narrow radio refuses media outright: OK (" + why + ")");

                // 4. Carrying strangers' traffic needs an explicit opt-in.
                pick = meshOnly.Pick(200, PayloadClass.Text, out why);
                if (pick != null) { sb.AppendLine("Consent withheld blocks a peer-relay node: FAIL"); routeOk = false; }
                else sb.AppendLine("Consent withheld blocks a peer-relay node: OK (" + why + ")");
                meshOnly.SetConsent("mesh", true);
                pick = meshOnly.Pick(200, PayloadClass.Text, out why);
                if (pick == null || pick.Name != "mesh")
                { sb.AppendLine("Consent granted opens the peer-relay node: FAIL"); routeOk = false; }
                else sb.AppendLine("Consent granted opens the peer-relay node: OK");
                meshOnly.SetConsent("mesh", false);
                if (meshOnly.Pick(200, PayloadClass.Text, out why) != null)
                { sb.AppendLine("Consent revoked closes it again: FAIL"); routeOk = false; }
                else sb.AppendLine("Consent revoked closes it again: OK");

                // 5. A frame put on a link really arrives at the peer, and the
                //    router says out loud which way it went.
                LoopTransport tx = new LoopTransport("lan", 0, 0);
                LoopTransport rx = new LoopTransport("lanPeer", 0, 0);
                tx.Bind("7003256013"); rx.Bind("7003256099");
                string gotFrom = ""; byte[] gotBytes = null;
                rx.Frame += delegate(string from, byte[] payload) { gotFrom = from; gotBytes = payload; };
                List<string> notices = new List<string>();
                TransportRouter live = new TransportRouter();
                live.Add(tx);
                live.RouteNotice += delegate(string n, string d) { notices.Add(n + " " + d); };
                string via;
                byte[] body = Encoding.UTF8.GetBytes("ECHAT|route-canary");
                if (!live.TrySend("7003256099", body, PayloadClass.Text, out via))
                { sb.AppendLine("Frame delivered over the link: FAIL -> " + via); routeOk = false; }
                else if (gotFrom != "7003256013" || gotBytes == null || gotBytes.Length != body.Length)
                { sb.AppendLine("Frame delivered over the link: FAIL (arrived as " + gotFrom + "/" + (gotBytes == null ? 0 : gotBytes.Length) + "B)"); routeOk = false; }
                else if (notices.Count == 0)
                { sb.AppendLine("Frame delivered over the link: FAIL (no route notice for the UI)"); routeOk = false; }
                else sb.AppendLine("Frame delivered over the link: OK (via " + via + ", " + notices.Count + " notice)");

                // 6. "No route" is an explanation, not a silent drop.
                if (empty.TrySend("7003256099", body, PayloadClass.Text, out via) || via == null || via.IndexOf("none") != 0)
                { sb.AppendLine("Empty router reports no route: FAIL -> " + via); routeOk = false; }
                else sb.AppendLine("Empty router reports no route: OK (" + via + ")");

                // 7. The relay transport hands the socket the bytes, unchanged.
                relayTx.Clear();
                string via2;
                if (!relayOnly.TrySend("7003256099", body, PayloadClass.Text, out via2) || relayTx.Count != 1 ||
                    Encoding.UTF8.GetString(relayTx[0]) != "ECHAT|route-canary")
                { sb.AppendLine("Relay transport forwards the exact sealed line: FAIL"); routeOk = false; }
                else sb.AppendLine("Relay transport forwards the exact sealed line: OK");

                // 8. The route table the settings page will show actually names
                //    the consent state instead of hiding it.
                List<string> table = all.Describe();
                string meshRow = "";
                foreach (string row in table) if (row.StartsWith("mesh")) meshRow = row;
                if (table.Count != 4 || meshRow.IndexOf("consent=withheld") < 0)
                { sb.AppendLine("Route table reports consent state: FAIL -> " + meshRow); routeOk = false; }
                else sb.AppendLine("Route table reports consent state: OK (" + table.Count + " rows)");

                // 9. The settings page binds structured rows, and they must say
                //    the same thing as the summary: one computation, two views.
                List<RouteRow> rows = all.Rows();
                RouteRow meshR = null;
                foreach (RouteRow r in rows) if (r.Name == "mesh") meshR = r;
                string meshDesc = meshR == null ? "no mesh row" : meshR.Link + "/" + meshR.Ready + "/" +
                                  meshR.MaxFrame + "/" + meshR.BitRate + "/" + meshR.Consent;
                if (rows.Count != table.Count || meshR == null || meshR.Consent != "refused" ||
                    meshR.Ready != "ready" || meshR.MaxFrame != "any size" || meshR.BitRate != "unknown")
                { sb.AppendLine("Route rows agree with the route summary: FAIL -> " + meshDesc); routeOk = false; }
                else sb.AppendLine("Route rows agree with the route summary: OK (" + rows.Count + " rows, mesh=" + meshR.Consent + ")");

                // 10. One opt-in covers links that appear later (a radio adapter
                //    plugged in tomorrow), and refusing that one link still wins.
                TransportRouter later = new TransportRouter();
                later.DefaultConsentGranted = true;
                LoopTransport meshNew = new LoopTransport("meshNew", 0, 0, true);
                later.Add(meshNew);
                bool byDefault = later.Pick(200, PayloadClass.Text, out why) != null;
                later.SetConsent("meshNew", false);
                bool overruled = later.Pick(200, PayloadClass.Text, out why) == null;
                if (!byDefault || !overruled)
                { sb.AppendLine("Opt-in covers later links, per-link no wins: FAIL (default=" + byDefault + ", overruled=" + overruled + ")"); routeOk = false; }
                else sb.AppendLine("Opt-in covers later links, per-link no wins: OK");

                sb.AppendLine("Routing: " + (routeOk ? "OK" : "FAIL"));
                if (!routeOk) pass = false;
                LoopTransport.Reset();
            }
            catch (Exception ex) { sb.AppendLine("Routing EX: " + ex.Message); pass = false; }

            sb.AppendLine("--- Wake agent hand-off (agent stores, window replays) ---");
            try
            {
                bool wakeOk = true;
                string wh = Path.Combine(Path.GetTempPath(), "ussd_wake_" + DateTime.Now.Ticks);
                Home.Set(wh);
                if (Home.Dir != wh + Path.DirectorySeparatorChar)
                { sb.AppendLine("Home is settable and normalized: FAIL -> " + Home.Dir); wakeOk = false; }
                else sb.AppendLine("Home is settable and normalized: OK");

                // 1. A body that contains the field separator and newlines still
                //    crosses intact, because the hand-off is one file per message.
                string nasty = "line one|with a pipe\nline 2 ECHAT|opaque";
                WakeInbox.Save(Home.Dir, "7003256099", nasty);
                List<string[]> one = WakeInbox.Take(Home.Dir);
                if (one.Count != 1 || one[0][0] != "7003256099" || one[0][1] != nasty)
                { sb.AppendLine("Hand-off keeps a hostile message body: FAIL -> " +
                                (one.Count == 0 ? "nothing returned" : "[" + one[0][0] + "][" + one[0][1] + "]")); wakeOk = false; }
                else sb.AppendLine("Hand-off keeps a hostile message body: OK");

                // 2. Reading consumes, or every start would replay the same chat.
                if (WakeInbox.Take(Home.Dir).Count != 0 || WakeInbox.Count(Home.Dir) != 0)
                { sb.AppendLine("Hand-off is consumed once: FAIL"); wakeOk = false; }
                else sb.AppendLine("Hand-off is consumed once: OK");

                // 3. Two messages arrive in the order they were stored, and a
                //    half-written .part file is never replayed as a message.
                WakeInbox.Save(Home.Dir, "7003256013", "first");
                Thread.Sleep(15);
                WakeInbox.Save(Home.Dir, "7003256013", "second");
                File.WriteAllText(Path.Combine(WakeInbox.DirFor(Home.Dir), "9999999999999999999.msg.part"), "broken|body");
                List<string[]> two = WakeInbox.Take(Home.Dir);
                if (two.Count != 2 || two[0][1] != "first" || two[1][1] != "second")
                { sb.AppendLine("Hand-off order + ignores a partial file: FAIL -> " + two.Count +
                                " row(s), " + (two.Count == 2 ? two[0][1] + "/" + two[1][1] : "")); wakeOk = false; }
                else sb.AppendLine("Hand-off order + ignores a partial file: OK");

                // 4. The notice file is only a count hint, but it must survive
                //    the trip and be clearable.
                PendingNotice.Record(Home.Dir, "call", "7003256013", "video");
                List<string[]> ns = PendingNotice.ReadAll(Home.Dir);
                if (ns.Count != 1 || ns[0].Length < 4 || ns[0][1] != "call" || ns[0][3] != "video")
                { sb.AppendLine("Missed-call notice roundtrip: FAIL -> " + ns.Count); wakeOk = false; }
                else sb.AppendLine("Missed-call notice roundtrip: OK");
                PendingNotice.Clear(Home.Dir);
                if (PendingNotice.ReadAll(Home.Dir).Count != 0)
                { sb.AppendLine("Notices clear after being raised: FAIL"); wakeOk = false; }
                else sb.AppendLine("Notices clear after being raised: OK");

                sb.AppendLine("Wake hand-off: " + (wakeOk ? "OK" : "FAIL"));
                if (!wakeOk) pass = false;
                try { Directory.Delete(wh, true); } catch { }
                Home.Set(AppDomain.CurrentDomain.BaseDirectory);
            }
            catch (Exception ex) { sb.AppendLine("Wake hand-off EX: " + ex.Message); pass = false; }

            sb.AppendLine("--- Theme + Numbers ---");
            try
            {
                bool themeOk = true;
                string[] themeFiles = new string[] { "Light", "Dark", "Controls" };
                for (int i = 0; i < themeFiles.Length; i++)
                {
                    string f = themeFiles[i];
                    try
                    {
                        System.Windows.ResourceDictionary rd = Theme.LoadEmbedded(f);
                        sb.AppendLine(f + ".xaml parse: OK (" + rd.Count + " entries)");
                        if (f == "Controls")
                        {
                            if (rd["DialerCircleButton"] == null) { sb.AppendLine("Controls missing DialerCircleButton"); themeOk = false; }
                            if (rd["CallButton"] == null) { sb.AppendLine("Controls missing CallButton"); themeOk = false; }
                        }
                        else
                        {
                            if (rd["AppBg"] == null) { sb.AppendLine(f + " missing AppBg"); themeOk = false; }
                            if (rd["CardBrush"] == null) { sb.AppendLine(f + " missing CardBrush"); themeOk = false; }
                            if (rd["DangerBrush"] == null) { sb.AppendLine(f + " missing DangerBrush"); themeOk = false; }
                        }
                    }
                    catch (Exception ex) { sb.AppendLine(f + " parse FAIL: " + ex.Message); themeOk = false; }
                }
                // shared instances must stay mutable or live theming breaks
                if (Theme.Bg.IsFrozen) { sb.AppendLine("Theme.Bg is FROZEN - FAIL"); themeOk = false; }
                else sb.AppendLine("Theme.Bg mutable: OK");
                sb.AppendLine("Theme: " + (themeOk ? "OK" : "FAIL"));
                if (!themeOk) pass = false;

                bool numOk = true;
                if (!AppNum.IsApp("7001111111")) { sb.AppendLine("IsApp 7001111111 should be true"); numOk = false; }
                if (!AppNum.IsApp("700 111-1111")) { sb.AppendLine("IsApp formatted should be true"); numOk = false; }
                if (AppNum.IsApp("09123456789")) { sb.AppendLine("IsApp GSM number should be false"); numOk = false; }
                if (AppNum.IsApp("700111111")) { sb.AppendLine("IsApp 9 digits should be false"); numOk = false; }
                if (AppNum.Format("7001111111") != "700 111 1111") { sb.AppendLine("Format failed: " + AppNum.Format("7001111111")); numOk = false; }
                if (AppNum.NormalizeForCall("700 111 1111") != "7001111111") { sb.AppendLine("NormalizeForCall failed"); numOk = false; }
                if (AppNum.NormalizeForCall("+49 171 1234567") != "+49 171 1234567") { sb.AppendLine("NormalizeForCall GSM trim failed"); numOk = false; }
                sb.AppendLine("AppNum: " + (numOk ? "OK" : "FAIL"));
                if (!numOk) pass = false;
            }
            catch (Exception ex) { sb.AppendLine("Theme/Num EX: " + ex.Message); pass = false; }

            File.WriteAllText(Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "selftest.log"), sb.ToString());
            return pass ? 0 : 1;
        }

        private static bool HasOk(string[] lines)
        {
            foreach (string l in lines) if (Regex.IsMatch(l, @"(^|\s)OK(\s|$)", RegexOptions.IgnoreCase)) return true;
            return false;
        }

        private static void RunBatch(ModemService svc, StringBuilder sb)
        {
            // full Init (includes CFUN wake + SMS/USSD config + CSCA)
            sb.AppendLine("--- Init() ---");
            string[] init = svc.Init();
            foreach (string line in init) sb.AppendLine("  " + line);

            sb.AppendLine("--- SIM slot reader ---");
            try
            {
                SimSlotReader.SimCardInfo card = SimSlotReader.Read(svc);
                sb.AppendLine("  Present: " + card.Present);
                sb.AppendLine("  PinStatus: " + card.PinStatus);
                sb.AppendLine("  Fault: " + (card.Fault ?? "-"));
                sb.AppendLine("  Ready: " + card.Ready);
                sb.AppendLine("  SimType: " + card.SimType);
                sb.AppendLine("  FormFactor: " + card.FormFactor);
                sb.AppendLine("  Carrier: " + card.Carrier);
                sb.AppendLine("  Country: " + card.Country);
                sb.AppendLine("  MCC/MNC: " + card.MccMnc);
                sb.AppendLine("  ICCID: " + card.Iccid);
                sb.AppendLine("  IMSI: " + card.Imsi);
                sb.AppendLine("  IMEI: " + card.Imei);
            }
            catch (Exception ex) { sb.AppendLine("  SIM reader EX: " + ex.Message); }

            string[] cmds = new string[]
            {
                "AT+CPIN?", "AT+ICCID", "AT+CIMI", "AT+GSN", "AT+COPS?", "AT+CSQ",
                "AT+CREG?", "AT+CBC", "AT+CPBS?", "AT+CSCA?", "AT+CMGF?", "AT+CSCS?"
            };
            foreach (string c in cmds)
            {
                try
                {
                    string[] r = svc.SendCommand(c, ModemService.OkTerm, 10000);
                    sb.AppendLine(c + " => " + string.Join(" | ", r));
                }
                catch (Exception ex) { sb.AppendLine(c + " => EX " + ex.Message); }
            }
        }
    }

    // ======================= Port detection =======================
    public static class PortDetector
    {
        public static List<PortInfo> GetPortsWithNames()
        {
            List<PortInfo> list = new List<PortInfo>();
            Dictionary<string, string> captions = new Dictionary<string, string>();
            try
            {
                using (System.Management.ManagementObjectSearcher searcher =
                    new System.Management.ManagementObjectSearcher(
                        "SELECT Name FROM Win32_PnPEntity WHERE Name LIKE '%(COM%'"))
                {
                    foreach (System.Management.ManagementObject o in searcher.Get())
                    {
                        string name = o["Name"] == null ? "" : o["Name"].ToString();
                        Match m = Regex.Match(name, @"\((COM\d+)\)");
                        if (m.Success) captions[m.Groups[1].Value] = name;
                    }
                }
            }
            catch { }
            foreach (string p in SerialPort.GetPortNames())
            {
                string cap;
                if (!captions.TryGetValue(p, out cap)) cap = p;
                list.Add(new PortInfo { Port = p, Caption = cap });
            }
            return list;
        }

        public static string FindModemPort(string[] ports)
        {
            List<PortInfo> ranked = RankCandidates(GetPortsWithNames(), null);
            return ranked.Count > 0 ? ranked[0].Port : (ports.Length > 0 ? ports[0] : null);
        }

        public static List<PortInfo> RankCandidates(List<PortInfo> ports, string savedPort)
        {
            List<PortInfo> ranked = new List<PortInfo>();
            // Application-interface caption always outranks the saved port: a stale
            // saved COM (e.g. the low-level Modem interface) must not beat COM3.
            AddWhere(ranked, ports, delegate (PortInfo p) { return L(p).Contains("application interface"); });
            // Saved port wins only among the remaining candidates (still a good class).
            if (savedPort != null)
                foreach (PortInfo p in ports)
                    if (p.Port == savedPort && !ranked.Contains(p)) { ranked.Add(p); break; }
            AddWhere(ranked, ports, delegate (PortInfo p) { return L(p).Contains("modem"); });
            AddWhere(ranked, ports, delegate (PortInfo p) { return !L(p).Contains("nmea") && !L(p).Contains("diagnostic"); });
            AddWhere(ranked, ports, delegate (PortInfo p) { return true; });
            return ranked;
        }

        private static string L(PortInfo p) { return p.Caption == null ? "" : p.Caption.ToLowerInvariant(); }

        private static void AddWhere(List<PortInfo> target, List<PortInfo> source, Predicate<PortInfo> pred)
        {
            foreach (PortInfo p in source)
                if (!target.Contains(p) && pred(p)) target.Add(p);
        }

        public static string ProbeWorkingPort(List<PortInfo> candidates, int baud, Action<string> progress)
        {
            foreach (PortInfo pi in candidates)
            {
                if (progress != null) progress("Probing " + pi.Port + " (" + pi.Caption + ") ...");
                try
                {
                    string reply = SerialUssd.AtHandshake(pi.Port, baud, null);
                    bool ok = reply != null && reply.Contains("OK");
                    if (progress != null)
                        progress(pi.Port + ": " + (ok ? "OK - AT ready" : "no AT response"));
                    if (ok) return pi.Port;
                }
                catch (Exception ex)
                {
                    if (progress != null) progress(pi.Port + " failed: " + ex.Message);
                }
            }
            return null;
        }
    }

    public class PortInfo
    {
        public string Port;
        public string Caption;
    }

    // ======================= Serial helpers (probe / legacy) =======================
    public static class SerialUssd
    {
        public static string AtHandshake(string port, int baud, StringBuilder log)
        {
            using (SerialPort sp = new SerialPort(port, baud, Parity.None, 8, StopBits.One))
            {
                sp.ReadTimeout = 800;
                sp.WriteTimeout = 2000;
                sp.DtrEnable = true;
                sp.Open();
                Thread.Sleep(300);
                sp.DiscardInBuffer();
                sp.Write("AT\r");
                Thread.Sleep(500);
                string reply = sp.ReadExisting();
                if (log != null) log.AppendLine("handshake raw: " + reply.Trim());
                sp.Close();
                return reply;
            }
        }

        public static string ExtractUssdText(string raw)
        {
            foreach (string line in raw.Split('\n'))
            {
                string l = line.Trim();
                if (l.Contains("+CUSD:"))
                {
                    Match m = Regex.Match(l, @"\+CUSD:\s*\d+\s*,\s*""([^""]*)""");
                    if (m.Success) return m.Groups[1].Value;
                    m = Regex.Match(l, @",""(.+)""");
                    if (m.Success) return m.Groups[1].Value;
                }
            }
            if (Regex.IsMatch(raw, @"\+CME ERROR:.*")) return raw.Trim();
            if (raw.Trim().Equals("OK")) return "(empty response)";
            return raw.Trim();
        }
    }

    // ======================= Modem service (persistent serial + URC reader) =======================
    public sealed class ModemService : IDisposable
    {
        public const string OkTerm = "^(OK|ERROR|\\+CME ERROR|\\+CMS ERROR)";

        private SerialPort _sp;
        private Thread _th;
        private volatile bool _run;
        private readonly object _cmdLock = new object();
        private readonly object _sync = new object();
        private readonly object _wlock = new object();
        private List<string> _resp = new List<string>();
        private bool _collecting;
        private bool _done;
        private bool _prompt;
        private string _term = "";
        private readonly StringBuilder _lineBuf = new StringBuilder();

        public string PortName { get; private set; }
        public int BaudRate { get; private set; }
        public bool IsOpen { get { return _sp != null && _sp.IsOpen; } }

        public event Action<string> LineReceived;
        public event Action<string> UrcReceived;
        public event Action<string> ConnectionLost;

        public void Open(string port, int baud)
        {
            if (IsOpen) return;
            PortName = port;
            BaudRate = baud;
            _sp = new SerialPort(port, baud, Parity.None, 8, StopBits.One);
            _sp.ReadTimeout = 300;
            _sp.WriteTimeout = 5000;
            _sp.DtrEnable = true;
            _sp.RtsEnable = true; // required by this modem (DW5821e/T77W968) for .NET SerialPort
            _sp.Open();
            lock (_sync) { _lineBuf.Length = 0; }
            _run = true;
            _th = new Thread(ReaderLoop);
            _th.IsBackground = true;
            _th.Start();
        }

        public void Close()
        {
            _run = false;
            try { if (_sp != null && _sp.IsOpen) _sp.Close(); } catch { }
            lock (_sync) { _done = true; Monitor.PulseAll(_sync); }
        }

        public void Dispose() { Close(); }

        private void ReaderLoop()
        {
            byte[] buf = new byte[512];
            while (_run)
            {
                int n = 0;
                try { n = _sp.Read(buf, 0, buf.Length); }
                catch (TimeoutException) { continue; }
                catch (Exception ex)
                {
                    if (_run) Raise(ConnectionLost, ex.Message);
                    break;
                }
                if (n <= 0) continue;
                ProcessChunk(Encoding.ASCII.GetString(buf, 0, n));
            }
        }

        private void ProcessChunk(string chunk)
        {
            for (int i = 0; i < chunk.Length; i++)
            {
                char c = chunk[i];
                if (c == '\n')
                {
                    string line;
                    lock (_sync)
                    {
                        line = _lineBuf.ToString().Trim();
                        _lineBuf.Length = 0;
                    }
                    if (line.Length > 0) HandleLine(line);
                }
                else if (c != '\r')
                {
                    bool promptHit = false;
                    lock (_sync)
                    {
                        _lineBuf.Append(c);
                        if (_collecting && _prompt && _lineBuf.ToString().IndexOf('>') >= 0)
                        {
                            _done = true;
                            promptHit = true;
                            _lineBuf.Length = 0;
                            Monitor.PulseAll(_sync);
                        }
                    }
                    if (promptHit) Raise(LineReceived, ">");
                }
            }
        }

        private static bool IsAlwaysUrc(string line)
        {
            return Regex.IsMatch(line, @"^(RING|NO CARRIER|NO ANSWER|BUSY|\+CLIP:|\+CMTI:|\+CMT:|\+CRING:)", RegexOptions.IgnoreCase);
        }

        private void HandleLine(string line)
        {
            bool consumed = false;
            lock (_sync)
            {
                if (_collecting && !_prompt)
                {
                    _resp.Add(line);
                    consumed = true;
                    if (_term.Length > 0 && Regex.IsMatch(line, _term, RegexOptions.IgnoreCase))
                    {
                        _done = true;
                        Monitor.PulseAll(_sync);
                    }
                }
            }
            Raise(LineReceived, line);
            if (!consumed || IsAlwaysUrc(line))
                Raise(UrcReceived, line);
        }

        private void Raise(Action<string> ev, string line)
        {
            if (ev != null) ev(line);
        }

        private void WriteRaw(string data)
        {
            lock (_wlock)
            {
                byte[] b = Encoding.ASCII.GetBytes(data);
                _sp.Write(b, 0, b.Length);
            }
        }

        private string[] WaitDone(int timeoutMs)
        {
            lock (_sync)
            {
                DateTime deadline = DateTime.Now.AddMilliseconds(timeoutMs);
                while (!_done)
                {
                    int ms = (int)(deadline - DateTime.Now).TotalMilliseconds;
                    if (ms <= 0) break;
                    Monitor.Wait(_sync, ms);
                }
                _collecting = false;
                return _resp.ToArray();
            }
        }

        public string[] SendCommand(string cmd, string term, int timeoutMs)
        {
            lock (_cmdLock)
            {
                if (!IsOpen) throw new InvalidOperationException("Modem not connected");
                lock (_sync)
                {
                    _resp = new List<string>();
                    _done = false;
                    _collecting = true;
                    _prompt = false;
                    _term = term == null ? "" : term;
                    _lineBuf.Length = 0;
                }
                WriteRaw(cmd + "\r");
                return WaitDone(timeoutMs);
            }
        }

        public string[] SendSms(string number, string body, int timeoutMs)
        {
            lock (_cmdLock)
            {
                if (!IsOpen) throw new InvalidOperationException("Modem not connected");
                lock (_sync)
                {
                    _resp = new List<string>();
                    _done = false;
                    _collecting = true;
                    _prompt = true;
                    _term = "";
                    _lineBuf.Length = 0;
                }
                WriteRaw("AT+CMGS=\"" + number + "\"\r");
                bool gotPrompt;
                lock (_sync)
                {
                    DateTime deadline = DateTime.Now.AddSeconds(12);
                    while (!_done)
                    {
                        int ms = (int)(deadline - DateTime.Now).TotalMilliseconds;
                        if (ms <= 0) break;
                        Monitor.Wait(_sync, ms);
                    }
                    gotPrompt = _done;
                    _prompt = false;
                    _collecting = false;
                }
                if (!gotPrompt)
                {
                    lock (_sync) { return _resp.ToArray(); }
                }
                lock (_sync)
                {
                    _resp = new List<string>();
                    _done = false;
                    _collecting = true;
                    _prompt = false;
                    _term = OkTerm;
                    _lineBuf.Length = 0;
                }
                WriteRaw(body + "\u001A");
                return WaitDone(timeoutMs);
            }
        }

        public string[] Init()
        {
            List<string> results = new List<string>();
            // 1) Radio must be on and SIM must be READY before SMS/USSD config
            try
            {
                string cfun = ModemService.QueryValue(this, "AT+CFUN?", @"\+CFUN:\s*(\d)", 5000);
                results.Add("AT+CFUN? => " + (cfun ?? "unknown"));

                string pin = ModemService.QueryValue(this, "AT+CPIN?", @"^\+CPIN:\s*(.+)$", 8000);
                if (pin == null)
                {
                    string[] r0 = SendCommand("AT+CPIN?", OkTerm, 8000);
                    foreach (string l in r0)
                        if (Regex.IsMatch(l, @"\+CME ERROR", RegexOptions.IgnoreCase)) { pin = "ERROR"; break; }
                }
                results.Add("AT+CPIN? (pre) => " + (pin ?? "unknown"));

                // If radio off OR SIM failure/stale after CFUN toggling, do a full radio cycle
                bool needCycle = (cfun == "0")
                    || (pin != null && pin.IndexOf("failure", StringComparison.OrdinalIgnoreCase) >= 0)
                    || (pin == null);

                if (needCycle)
                {
                    if (cfun != "0")
                    {
                        results.Add("SIM not ready (" + (pin ?? "no answer") + ") - cycling radio...");
                        string[] rOff = SendCommand("AT+CFUN=0", OkTerm, 15000);
                        results.Add("AT+CFUN=0 => " + string.Join(" | ", rOff));
                        System.Threading.Thread.Sleep(2000);
                    }
                    else
                    {
                        results.Add("Radio off - enabling (AT+CFUN=1)...");
                    }
                    string[] rOn = SendCommand("AT+CFUN=1", OkTerm, 20000);
                    results.Add("AT+CFUN=1 => " + string.Join(" | ", rOn));

                    // wait for SIM to come up (poll CPIN up to ~30s)
                    for (int i = 0; i < 15; i++)
                    {
                        string pinLine = ModemService.QueryValue(this, "AT+CPIN?", @"\+CPIN:\s*(.+)", 5000);
                        if (pinLine != null)
                        {
                            results.Add("AT+CPIN? (wait " + (i + 1) + ") => " + pinLine);
                            if (pinLine.IndexOf("READY", StringComparison.OrdinalIgnoreCase) >= 0) break;
                            if (pinLine.IndexOf("SIM PIN", StringComparison.OrdinalIgnoreCase) >= 0) break; // needs user PIN
                            if (pinLine.IndexOf("SIM PUK", StringComparison.OrdinalIgnoreCase) >= 0) break; // needs user PUK
                            if (pinLine.IndexOf("not inserted", StringComparison.OrdinalIgnoreCase) >= 0) break; // no SIM
                        }
                        System.Threading.Thread.Sleep(2000);
                    }
                }
            }
            catch (Exception ex) { results.Add("CFUN/SIM-wake => EX " + ex.Message); }

            // 2) Standard configuration (each best-effort)
            string[] inits = new string[]
            {
                "ATE0", "AT+CMEE=2", "AT+CMGF=1", "AT+CSCS=\"GSM\"",
                "AT+CPMS=\"MT\",\"MT\",\"MT\"", "AT+CNMI=2,1,0,0,0", "AT+CLIP=1"
            };
            foreach (string c in inits)
            {
                try
                {
                    string[] r = SendCommand(c, OkTerm, 8000);
                    results.Add(c + " => " + string.Join(" | ", r));
                }
                catch (Exception ex) { results.Add(c + " => EX " + ex.Message); }
            }
            // fallback SMS storage if MT not supported
            try
            {
                string[] probe = SendCommand("AT+CPMS?", OkTerm, 5000);
                bool cpmsOk = false;
                foreach (string l in probe) if (Regex.IsMatch(l, @"\+CPMS:")) { cpmsOk = true; break; }
                if (!cpmsOk)
                {
                    string[] alt = SendCommand("AT+CPMS=\"SM\",\"SM\",\"SM\"", OkTerm, 8000);
                    results.Add("AT+CPMS=\"SM\" fallback => " + string.Join(" | ", alt));
                }
            }
            catch { }
            // read SMS center (needed to send SMS)
            try
            {
                string[] csca = SendCommand("AT+CSCA?", OkTerm, 5000);
                results.Add("AT+CSCA? => " + string.Join(" | ", csca));
            }
            catch { }
            return results.ToArray();
        }

        public static string QueryValue(ModemService svc, string cmd, string pattern, int timeout)
        {
            try
            {
                string[] r = svc.SendCommand(cmd, OkTerm, timeout);
                foreach (string raw in r)
                {
                    Match m = Regex.Match(raw, pattern, RegexOptions.IgnoreCase);
                    if (m.Success) return m.Groups[1].Value;
                }
            }
            catch { }
            return null;
        }
    }

    // ======================= SIM slot reader =======================
    // Reads the SIM card in the modem's SIM slot: type, carrier, ICCID/IMSI.
    // Works on Qualcomm/Sierra (DW5821e, EM7455, T77W968) and generic modems.
    public static class SimSlotReader
    {
        public class SimCardInfo
        {
            public string Iccid;
            public string Imsi;
            public string Imei;
            public string Carrier;
            public string Country;
            public string SimType;      // USIM / SIM / RUIM / unknown
            public string FormFactor;   // from ICCID length heuristic (standard 19-20 digit = 2FF/3FF/4FF)
            public string MccMnc;
            public bool Present;
            public bool Ready;
            public string PinStatus;    // READY / SIM PIN / SIM PUK / NOT INSERTED
            public string Fault;        // hardware fault detail (e.g. $QCSIMSTAT: SIM ERROR)
        }

        // ICCID (ITU-T E.111) ï¿½ country code from issuer identification number (IIN)
        private static readonly Dictionary<string, string> IccidCountry = new Dictionary<string, string>
        {
            { "233", "Ghana" }, { "234", "United Kingdom" }, { "235", "United Kingdom" },
            { "310", "USA" }, { "311", "USA" }, { "312", "USA" },
            { "313", "USA" }, { "316", "USA" }, { "262", "Germany" },
            { "222", "Italy" }, { "208", "France" }, { "214", "Spain" },
            { "260", "Poland" }, { "226", "Romania" }, { "255", "Ukraine" },
            { "250", "Russia" }, { "440", "Japan" }, { "450", "South Korea" },
            { "86", "China" }, { "852", "Hong Kong" }, { "525", "Singapore" },
            { "510", "Indonesia" }, { "520", "Thailand" }, { "452", "Vietnam" },
            { "62", "Nigeria" }, { "639", "Kenya" }, { "655", "South Africa" },
            { "641", "Uganda" }, { "620", "Ghana" }, { "640", "Tanzania" },
            { "611", "Guinea" }, { "619", "Sierra Leone" }, { "624", "Cameroon" },
            { "625", "Cape Verde" }, { "626", "Sao Tome" }, { "627", "Equatorial Guinea" },
            { "628", "Gabon" }, { "629", "Congo" }, { "630", "Congo DRC" },
            { "631", "Angola" }, { "632", "Guinea-Bissau" }, { "633", "Benin" },
            { "634", "Chad" }, { "635", "Rwanda" }, { "636", "Ethiopia" },
            { "637", "Somalia" }, { "638", "Djibouti" }, { "642", "Burundi" },
            { "643", "Mozambique" }, { "645", "Zambia" }, { "646", "Madagascar" },
            { "647", "Reunion" }, { "648", "Zimbabwe" }, { "649", "Namibia" },
            { "650", "Botswana" }, { "651", "Lesotho" }, { "652", "Eswatini" },
            { "653", "Mayotte" }, { "654", "Comoros" }, { "609", "Mauritania" },
            { "610", "Mali" }, { "612", "Ivory Coast" }, { "613", "Burkina Faso" },
            { "614", "Niger" }, { "615", "Togo" }, { "616", "Benin" },
            { "617", "Mauritius" }, { "618", "Liberia" }, { "621", "Senegal" },
            { "622", "Gambia" }, { "623", "Central African Republic" }, { "724", "Brazil" },
            { "722", "Argentina" }, { "706", "El Salvador" }, { "712", "Costa Rica" },
            { "334", "Mexico" }, { "338", "Jamaica" }, { "342", "Barbados" },
            { "344", "Antigua" }, { "350", "Bermuda" }, { "363", "Aruba" },
            { "365", "Anguilla" }, { "366", "Dominica" }, { "368", "Guadeloupe" },
            { "369", "Puerto Rico" }, { "502", "Malaysia" }, { "505", "Australia" },
            { "515", "Philippines" }, { "530", "New Zealand" }, { "404", "India" },
            { "405", "India" }, { "406", "India" }, { "413", "Sri Lanka" },
            { "414", "Myanmar" }, { "415", "Maldives" }, { "416", "Jordan" },
            { "417", "Syria" }, { "418", "Iraq" }, { "419", "Kuwait" },
            { "420", "Saudi Arabia" }, { "421", "Yemen" }, { "422", "Oman" },
            { "424", "UAE" }, { "425", "Israel" }, { "426", "Bahrain" },
            { "427", "Qatar" }, { "429", "Lebanon" }, { "430", "UAE" },
            { "431", "UAE" }, { "432", "Iran" }, { "434", "Uzbekistan" },
            { "435", "Tajikistan" }, { "436", "Turkmenistan" }, { "437", "Kyrgyzstan" },
            { "438", "Kazakhstan" }, { "441", "Japan" }, { "454", "Hong Kong" },
            { "455", "Macau" }, { "456", "Cambodia" }, { "457", "Laos" },
            { "460", "China" }, { "466", "Taiwan" }, { "467", "North Korea" },
            { "470", "Bangladesh" }, { "480", "South Korea" }, { "602", "Egypt" },
            { "603", "Algeria" }, { "604", "Morocco" }, { "605", "Tunisia" },
            { "606", "Libya" }, { "607", "Gambia" }, { "608", "Senegal" },
            { "730", "Chile" }, { "732", "Colombia" }, { "734", "Venezuela" },
            { "736", "Bolivia" }, { "740", "Ecuador" }, { "744", "Paraguay" },
            { "746", "Uruguay" }, { "748", "Uruguay" },
        };

        // common mobile network operators by MCC+MNC (subset, expandable)
        private static readonly Dictionary<string, string> MccMncCarrier = new Dictionary<string, string>
        {
            { "62001", "MTN Ghana" }, { "62002", "Vodafone Ghana" }, { "62003", "AirtelTigo Ghana" },
            { "62004", "Glo Ghana" }, { "62005", "Expresso Ghana" }, { "63902", "Safaricom Kenya" },
            { "63903", "Airtel Kenya" }, { "63907", "Telkom Kenya" }, { "65501", "Vodacom South Africa" },
            { "65507", "Cell C South Africa" }, { "65510", "MTN South Africa" }, { "65519", "Telkom South Africa" },
            { "64001", "Vodacom Tanzania" }, { "64002", "Tigo Tanzania" }, { "64004", "Airtel Tanzania" },
            { "64101", "MTN Uganda" }, { "64110", "Airtel Uganda" }, { "64501", "MTN Zambia" },
            { "64502", "Airtel Zambia" }, { "64801", "Econet Zimbabwe" }, { "64804", "NetOne Zimbabwe" },
            { "64903", "MTC Namibia" }, { "65001", "Mascom Botswana" }, { "62401", "MTN Cameroon" },
            { "62402", "Orange Cameroon" }, { "61203", "MTN Ivory Coast" }, { "61202", "Moov Ivory Coast" },
            { "61303", "Orange Burkina Faso" }, { "61501", "Togocom Togo" }, { "61101", "Orange Guinea" },
            { "61901", "Airtel Sierra Leone" }, { "60201", "Orange Egypt" }, { "60202", "Vodafone Egypt" },
            { "60203", "Etisalat Egypt" }, { "60301", "Mobilis Algeria" }, { "60401", "IAM Morocco" },
            { "60503", "Orange Tunisia" }, { "310260", "T-Mobile USA" }, { "310410", "AT&T USA" },
            { "311480", "Verizon USA" }, { "23415", "Vodafone UK" }, { "23420", "Three UK" },
            { "23430", "EE UK" }, { "26201", "Telekom Germany" }, { "26202", "Vodafone Germany" },
            { "26203", "O2 Germany" }, { "20801", "Orange France" }, { "20810", "SFR France" },
            { "20815", "Free France" }, { "22201", "TIM Italy" }, { "22210", "Vodafone Italy" },
            { "22288", "Iliad Italy" }, { "21401", "Vodafone Spain" }, { "21403", "Orange Spain" },
            { "21407", "Movistar Spain" }, { "25001", "MTS Russia" }, { "25099", "Beeline Russia" },
            { "44010", "NTT Docomo Japan" }, { "44020", "SoftBank Japan" }, { "45005", "SK Telecom Korea" },
            { "45008", "KT Korea" }, { "52501", "SingTel Singapore" }, { "52503", "StarHub Singapore" },
            { "40411", "Airtel India" }, { "40490", "Vodafone India" }, { "40585", "Jio India" },
            { "50501", "Telstra Australia" }, { "50502", "Optus Australia" }, { "50503", "Vodafone Australia" },
            { "53001", "Vodafone New Zealand" }, { "40586", "Jio India" }, { "334020", "Telcel Mexico" },
            { "72405", "Vivo Brazil" }, { "72406", "TIM Brazil" }, { "72410", "Claro Brazil" },
            { "732101", "Claro Colombia" },
        };

        public static SimCardInfo Read(ModemService modem)
        {
            SimCardInfo info = new SimCardInfo();
            if (modem == null || !modem.IsOpen) return info;

            // PIN / presence
            string pin = ModemService.QueryValue(modem, "AT+CPIN?", @"^\+CPIN:\s*(.+)$", 8000);
            if (pin == null)
            {
                string[] r = modem.SendCommand("AT+CPIN?", ModemService.OkTerm, 8000);
                foreach (string l in r)
                {
                    if (Regex.IsMatch(l, @"\+CME ERROR:\s*SIM not inserted", RegexOptions.IgnoreCase))
                    {
                        info.PinStatus = "NOT INSERTED";
                        info.Present = false;
                        info.Fault = ProbeReaderFault(modem);
                        return info;
                    }
                    if (Regex.IsMatch(l, @"\+CME ERROR:\s*SIM failure", RegexOptions.IgnoreCase))
                    {
                        // SIM is in the slot but not talking - radio cycle needed (handled by Init)
                        info.PinStatus = "SIM failure (radio re-init needed)";
                        info.Present = true;
                        info.Ready = false;
                        // still try to read identity - may work after re-init
                        break;
                    }
                    if (Regex.IsMatch(l, @"\+CME ERROR", RegexOptions.IgnoreCase))
                    { info.PinStatus = "ERROR: " + l; info.Present = true; info.Ready = false; break; }
                    if (Regex.IsMatch(l, @"^\+CPIN:", RegexOptions.IgnoreCase))
                    { pin = l.Substring(l.IndexOf(':') + 1).Trim(); break; }
                }
            }
            if (info.PinStatus == null) info.PinStatus = pin ?? "unknown";
            if (info.PinStatus != "SIM failure (radio re-init needed)" && !info.PinStatus.StartsWith("ERROR"))
            {
                info.Present = true;
                info.Ready = pin != null && pin.IndexOf("READY", StringComparison.OrdinalIgnoreCase) >= 0;
            }

            // ICCID ï¿½ multiple vendor variants
            info.Iccid = FirstDigits(ModemService.QueryValue(modem, "AT+ICCID", @"(\d{14,22})", 8000));
            if (info.Iccid == null) info.Iccid = FirstDigits(ModemService.QueryValue(modem, "AT+CCID", @"(\d{14,22})", 8000));
            if (info.Iccid == null) info.Iccid = FirstDigits(ModemService.QueryValue(modem, "AT!ICCID?", @"(\d{14,22})", 8000));
            if (info.Iccid == null) info.Iccid = FirstDigits(ModemService.QueryValue(modem, "AT+QCCID", @"(\d{14,22})", 8000));
            if (info.Iccid == null) info.Iccid = FirstDigits(ModemService.QueryValue(modem, "AT+CICCID", @"(\d{14,22})", 8000));
            if (info.Iccid == null)
            {
                // restricted SIM access: read EF.ICC (2FE2 = 28423) via CRSM
                string crsm = ModemService.QueryValue(modem, "AT+CRSM=176,28423,0,0,20", @"""+CRSM:\s*\d+,\s*\d+,\s*\""?([0-9A-Fa-f]+)\""?", 8000);
                if (crsm != null) info.Iccid = IccidFromHex(crsm);
            }

            // IMSI ï¿½ read EF.IMSI via CRSM (28417 = 0x6F07) as fallback
            info.Imsi = FirstDigits(ModemService.QueryValue(modem, "AT+CIMI", @"(\d{14,16})", 8000));
            if (info.Imsi == null)
            {
                string crsm = ModemService.QueryValue(modem, "AT+CRSM=176,28417,0,0,9", @"""+CRSM:\s*\d+,\s*\d+,\s*\""?([0-9A-Fa-f]+)\""?", 8000);
                if (crsm != null) info.Imsi = ImsiFromHex(crsm);
            }

            // IMEI
            info.Imei = FirstDigits(ModemService.QueryValue(modem, "AT+GSN", @"(\d{14,18})", 8000));
            if (info.Imei == null) info.Imei = FirstDigits(ModemService.QueryValue(modem, "AT+CGSN", @"(\d{14,18})", 8000));

            // SIM type: USIM if CSIM/CRSM file access works; else classic SIM
            info.SimType = DetectSimType(modem);

            // Carrier / country from IMSI (MCC+MNC) then ICCID country
            if (info.Imsi != null && info.Imsi.Length >= 5)
            {
                info.MccMnc = info.Imsi.Substring(0, 5);
                if (MccMncCarrier.ContainsKey(info.MccMnc)) info.Carrier = MccMncCarrier[info.MccMnc];
                else if (info.Imsi.Length >= 6)
                {
                    string m6 = info.Imsi.Substring(0, 6);
                    if (MccMncCarrier.ContainsKey(m6)) { info.Carrier = MccMncCarrier[m6]; info.MccMnc = m6; }
                }
                string mcc3 = info.Imsi.Substring(0, Math.Min(3, info.Imsi.Length));
                if (IccidCountry.ContainsKey(mcc3)) info.Country = IccidCountry[mcc3];
            }
            if (info.Country == null && info.Iccid != null && info.Iccid.Length >= 5)
            {
                // ICCID: 89 + country (2-3) + ...
                string after89 = info.Iccid.Substring(2);
                if (after89.Length >= 3)
                {
                    string c3 = after89.Substring(0, 3);
                    if (IccidCountry.ContainsKey(c3)) info.Country = IccidCountry[c3];
                    else if (after89.Length >= 2)
                    {
                        string c2 = after89.Substring(0, 2);
                        if (IccidCountry.ContainsKey(c2)) info.Country = IccidCountry[c2];
                    }
                }
            }
            if (info.Carrier == null && info.Country != null)
                info.Carrier = info.Country + " operator";

            // Form factor: standard SIM ICCID is 19-20 digits (2FF/3FF/4FF all same size on wire)
            if (info.Iccid != null)
                info.FormFactor = (info.Iccid.Length >= 19 && info.Iccid.Length <= 20) ? "2FF/3FF/4FF (standard)" : "unusual (" + info.Iccid.Length + " digits)";

            return info;
        }

        // Distinguishes a genuinely empty tray from a faulty SIM reader.
        // Qualcomm DW5821e/EM7455 expose AT$QCSIMSTAT?: 0|1,SIM OK|SIM ERROR.
        private static string ProbeReaderFault(ModemService modem)
        {
            try
            {
                string st = ModemService.QueryValue(modem, "AT$QCSIMSTAT?", @"\$QCSIMSTAT:\s*([^\r\n]+)", 6000);
                if (st != null)
                {
                    st = st.Trim();
                    if (st.IndexOf("SIM ERROR", StringComparison.OrdinalIgnoreCase) >= 0)
                        return "reader electrical fault ($QCSIMSTAT: " + st + ") ï¿½ check tray contacts / slot hardware";
                    if (st.IndexOf("SIM OK", StringComparison.OrdinalIgnoreCase) >= 0)
                        return "reader OK, card not detected ($QCSIMSTAT: " + st + ") ï¿½ reseat SIM";
                    return "$QCSIMSTAT: " + st;
                }
            }
            catch { }
            return null;
        }

        private static string DetectSimType(ModemService modem)
        {
            // AT+CSIM=? ï¿½ SIM application interface support (3G USIM exposes CSIM)
            bool csim = false;
            try
            {
                string[] r = modem.SendCommand("AT+CSIM=?", ModemService.OkTerm, 5000);
                foreach (string l in r) if (Regex.IsMatch(l, @"(^|\s)OK(\s|$)", RegexOptions.IgnoreCase)) { csim = true; break; }
            }
            catch { }

            // CRSM file access ï¿½ restricted SIM access (USIM/CSIM)
            bool crsm = false;
            try
            {
                string[] r = modem.SendCommand("AT+CRSM=176,28423,0,0,1", ModemService.OkTerm, 5000);
                foreach (string l in r)
                {
                    if (Regex.IsMatch(l, @"\+CRSM:", RegexOptions.IgnoreCase)) { crsm = true; break; }
                    if (Regex.IsMatch(l, @"\+CME ERROR", RegexOptions.IgnoreCase)) break; // command exists but no SIM file
                    if (Regex.IsMatch(l, @"(^|\s)OK(\s|$)", RegexOptions.IgnoreCase)) { crsm = true; break; }
                }
            }
            catch { }

            // CPIN READY + CSIM/CRSM => USIM (3G/4G/5G); otherwise classic SIM
            string pin = ModemService.QueryValue(modem, "AT+CPIN?", @"^\+CPIN:\s*(.+)$", 5000);
            bool ready = pin != null && pin.IndexOf("READY", StringComparison.OrdinalIgnoreCase) >= 0;

            if (ready && (csim || crsm)) return "USIM (3G/4G/5G)";
            if (ready) return "SIM (GSM)";
            if (pin != null) return "SIM (" + pin + ")";
            return "unknown";
        }

        private static string FirstDigits(string s)
        {
            if (string.IsNullOrEmpty(s)) return null;
            s = s.Trim();
            return s.Length == 0 ? null : s;
        }

        private static string IccidFromHex(string hex)
        {
            if (string.IsNullOrEmpty(hex)) return null;
            hex = hex.Trim();
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i + 1 < hex.Length && sb.Length < 22; i += 2)
            {
                int v;
                if (!int.TryParse(hex.Substring(i, 2), System.Globalization.NumberStyles.HexNumber, null, out v)) break;
                if (v >= 0 && v <= 9) sb.Append((char)('0' + v));
                else if (v >= 0xA0 && v <= 0xA9) sb.Append((char)('0' + (v - 0xA0))); // BCD with 0xA nibble
                else if (v == 0xFF) break;
                else break;
            }
            return sb.Length >= 14 ? sb.ToString() : null;
        }

        private static string ImsiFromHex(string hex)
        {
            if (string.IsNullOrEmpty(hex)) return null;
            hex = hex.Trim();
            StringBuilder sb = new StringBuilder();
            // EF.IMSI: first byte = length, then BCD digits (low nibble first)
            for (int i = 0; i + 1 < hex.Length && sb.Length < 16; i += 2)
            {
                int hi = Convert.ToInt32(hex.Substring(i, 2), 16);
                int lo = hi & 0x0F;
                int hn = (hi >> 4) & 0x0F;
                if (lo <= 9) sb.Append((char)('0' + lo)); else break;
                if (hn <= 9 && sb.Length < 15) sb.Append((char)('0' + hn));
            }
            return sb.Length >= 14 ? sb.ToString() : null;
        }
    }

    // ======================= MiFi HTTP API (Method 1) =======================
    public static class MifiApi
    {
        public static string PostUssd(string ip, string code)
        {
            ip = ip.TrimEnd('/');
            HttpWebRequest req = (HttpWebRequest)WebRequest.Create(ip + "/goform/goform_set_cmd_process");
            req.Method = "POST";
            req.Referer = ip + "/index.html";
            req.Timeout = 10000;
            req.ContentType = "application/x-www-form-urlencoded";
            string body = "isAsync=true&goformId=USSD_PROCESS&USSD_cmd=" +
                          Uri.EscapeDataString(code) + "&USSD_action=1";
            byte[] data = Encoding.ASCII.GetBytes(body);
            req.ContentLength = data.Length;
            using (Stream s = req.GetRequestStream()) s.Write(data, 0, data.Length);
            using (HttpWebResponse resp = (HttpWebResponse)req.GetResponse())
            using (StreamReader r = new StreamReader(resp.GetResponseStream(), Encoding.UTF8))
                return r.ReadToEnd();
        }

        public static string GetResult(string ip)
        {
            ip = ip.TrimEnd('/');
            HttpWebRequest req = (HttpWebRequest)WebRequest.Create(
                ip + "/goform/goform_get_cmd_process?cmd=USSD_result&multi_data=1");
            req.Method = "GET";
            req.Referer = ip + "/index.html";
            req.Timeout = 10000;
            using (HttpWebResponse resp = (HttpWebResponse)req.GetResponse())
            using (StreamReader r = new StreamReader(resp.GetResponseStream(), Encoding.UTF8))
                return r.ReadToEnd();
        }

        public static string Session(string ip, string code, Action<string> onProgress)
        {
            string send = PostUssd(ip, code);
            if (onProgress != null) onProgress("Send: " + send);
            Thread.Sleep(3000);
            string result = GetResult(ip);
            if (onProgress != null) onProgress("Result: " + result);
            return result;
        }

        public static string TestConnection(string ip)
        {
            ip = ip.TrimEnd('/');
            HttpWebRequest req = (HttpWebRequest)WebRequest.Create(ip + "/");
            req.Method = "GET";
            req.Timeout = 5000;
            using (HttpWebResponse resp = (HttpWebResponse)req.GetResponse())
                return "HTTP " + (int)resp.StatusCode;
        }

        // Capability probe: classify the MiFi's web firmware.
        // Returns one of:
        //   "unreachable:<err>"
        //   "huawei-goform" - Huawei/ZTE style goform API (USSD supported via USSD_PROCESS)
        //   "himi-spa"      - Himi Vue SPA (/himiapi/json) - no USSD/SMS command in firmware
        //   "unknown:<hint>"
        public static string Probe(string ip)
        {
            ip = ip.TrimEnd('/');
            string body;
            try
            {
                HttpWebRequest root = (HttpWebRequest)WebRequest.Create(ip + "/");
                root.Method = "GET";
                root.Timeout = 5000;
                using (HttpWebResponse resp = (HttpWebResponse)root.GetResponse())
                using (StreamReader r = new StreamReader(resp.GetResponseStream(), Encoding.UTF8))
                    body = r.ReadToEnd();
            }
            catch (Exception ex) { return "unreachable:" + ex.Message; }

            // Huawei/ZTE goform devices serve index.html with goform JS.
            if (body.Contains("goform") || body.Contains("USSD_PROCESS"))
                return "huawei-goform";

            // Himi Vue SPA: API is POST /himiapi/json {cmdid:...} (no USSD command).
            // Detect by trying the API itself (200 = present), regardless of page hints.
            bool looksHimi = body.Contains("himiapi") || body.Contains("cmdid") ||
                             body.Contains("__VUE") || body.Contains("app.js");
            try
            {
                HttpWebRequest api = (HttpWebRequest)WebRequest.Create(ip + "/himiapi/json");
                api.Method = "POST";
                api.Timeout = 5000;
                api.ContentType = "application/json;charset=UTF-8";
                byte[] data = Encoding.UTF8.GetBytes("{\"cmdid\":\"getoverview\"}");
                api.ContentLength = data.Length;
                using (Stream s = api.GetRequestStream()) s.Write(data, 0, data.Length);
                using (HttpWebResponse resp = (HttpWebResponse)api.GetResponse())
                    return "himi-spa"; // reachable, but firmware has no USSD cmdid
            }
            catch (WebException wex2)
            {
                HttpWebResponse hr = wex2.Response as HttpWebResponse;
                if (hr != null && hr.StatusCode == HttpStatusCode.NotFound)
                {
                    if (looksHimi) return "unknown:/himiapi/json not found";
                    return "unknown:page not recognized";
                }
                if (hr != null) return "himi-spa"; // API exists (non-404), still no USSD
            }
            return looksHimi ? "himi-spa" : "unknown:page not recognized";
        }

        public static bool ProbeHasUssd(string ip)
        {
            string p = Probe(ip);
            return p == "huawei-goform";
        }
    }

    // ======================= Python bridge =======================
    public static class PythonBridge
    {
        public static string ScriptsDir
        {
            get { return Path.GetFullPath(Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "..", "Python")); }
        }

        public static async Task RunScriptAsync(MainWindow win, string script, string args)
        {
            string dir = ScriptsDir;
            string path = Path.Combine(dir, script);
            if (!File.Exists(path))
            {
                win.Log("Python script not found: " + path, MainWindow.BrushError);
                return;
            }
            win.Log("python " + script + " " + args, MainWindow.BrushAccent);
            try
            {
                ProcessStartInfo psi = new ProcessStartInfo
                {
                    FileName = "python",
                    Arguments = "\"" + path + "\" " + args,
                    WorkingDirectory = dir,
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true
                };
                using (Process p = Process.Start(psi))
                {
                    string stdout = await p.StandardOutput.ReadToEndAsync();
                    string stderr = await p.StandardError.ReadToEndAsync();
                    await Task.Run(delegate { p.WaitForExit(); });
                    if (!string.IsNullOrWhiteSpace(stdout))
                        foreach (string line in stdout.TrimEnd().Split('\n'))
                            win.Log(line.TrimEnd(), MainWindow.BrushSuccess);
                    if (!string.IsNullOrWhiteSpace(stderr))
                        foreach (string line in stderr.TrimEnd().Split('\n'))
                            win.Log(line.TrimEnd(), MainWindow.BrushError);
                    win.Log("python exit code: " + p.ExitCode, MainWindow.BrushGray);
                }
            }
            catch (Exception ex)
            {
                win.Log("Python error: " + ex.Message, MainWindow.BrushError);
            }
        }
    }

    // ======================= Data models =======================
    // =====================================================================
    // Status icons: the tray badge (green / amber / red) is composited at
    // runtime so the app ships one .ico and no per-state asset files.
    //
    // The encoder is written by hand rather than using
    // Icon.FromHandle(bitmap.GetHicon()), because GetHicon discards the alpha
    // channel: the notification area then shows a black square behind the icon,
    // which is the exact thing this badge is supposed to avoid.
    // =====================================================================
    public static class StatusIcons
    {
        // A filled dot with a dark ring, bottom-right of a square base bitmap.
        // The ring keeps it legible on both a dark and a light taskbar.
        public static System.Drawing.Bitmap Badge(System.Drawing.Bitmap baseBmp, System.Drawing.Color dot, int size)
        {
            System.Drawing.Bitmap outp = new System.Drawing.Bitmap(size, size,
                System.Drawing.Imaging.PixelFormat.Format32bppArgb);
            using (System.Drawing.Graphics g = System.Drawing.Graphics.FromImage(outp))
            {
                g.SmoothingMode = System.Drawing.Drawing2D.SmoothingMode.AntiAlias;
                g.InterpolationMode = System.Drawing.Drawing2D.InterpolationMode.HighQualityBicubic;
                g.DrawImage(baseBmp, new System.Drawing.Rectangle(0, 0, size, size),
                    new System.Drawing.Rectangle(0, 0, baseBmp.Width, baseBmp.Height),
                    System.Drawing.GraphicsUnit.Pixel);
                int d = Math.Max(9, size * 2 / 5);
                System.Drawing.Rectangle rc = new System.Drawing.Rectangle(size - d - 1, size - d - 1, d - 2, d - 2);
                using (System.Drawing.Brush b = new System.Drawing.SolidBrush(dot)) g.FillEllipse(b, rc);
                using (System.Drawing.Pen p = new System.Drawing.Pen(
                    System.Drawing.Color.FromArgb(0x14, 0x16, 0x22), Math.Max(1, size / 16)))
                    g.DrawEllipse(p, rc);
            }
            return outp;
        }

        public static System.Drawing.Icon IconFromBitmap(System.Drawing.Bitmap bmp, int size)
        {
            byte[] ico = EncodeIco(bmp, size);
            return new System.Drawing.Icon(new MemoryStream(ico, 0, ico.Length, true, false));
        }

        // Single-image 32 bpp .ico: ICONDIR + ICONDIRENTRY + BITMAPINFOHEADER +
        // BGRA scanlines (bottom-up) + 1bpp AND mask.
        public static byte[] EncodeIco(System.Drawing.Bitmap bmp, int size)
        {
            System.Drawing.Bitmap square = new System.Drawing.Bitmap(size, size,
                System.Drawing.Imaging.PixelFormat.Format32bppArgb);
            using (System.Drawing.Graphics g = System.Drawing.Graphics.FromImage(square))
                g.DrawImage(bmp, new System.Drawing.Rectangle(0, 0, size, size),
                    new System.Drawing.Rectangle(0, 0, bmp.Width, bmp.Height),
                    System.Drawing.GraphicsUnit.Pixel);

            System.Drawing.Imaging.BitmapData data = square.LockBits(
                new System.Drawing.Rectangle(0, 0, size, size),
                System.Drawing.Imaging.ImageLockMode.ReadOnly,
                System.Drawing.Imaging.PixelFormat.Format32bppArgb);
            byte[] pixels = new byte[size * size * 4];
            System.Runtime.InteropServices.Marshal.Copy(data.Scan0, pixels, 0, pixels.Length);
            square.UnlockBits(data);
            square.Dispose();

            int maskRow = ((size + 31) / 32) * 4;      // AND mask rows pad to 32 bits
            byte[] dib = new byte[40 + pixels.Length + maskRow * size];
            using (MemoryStream dm = new MemoryStream(dib))
            using (BinaryWriter bw = new BinaryWriter(dm))
            {
                bw.Write((int)40);                     // BITMAPINFOHEADER size
                bw.Write((int)size);
                bw.Write((int)size * 2);               // XOR + AND rows
                bw.Write((short)1);                    // planes
                bw.Write((short)32);                   // bpp
                bw.Write((int)0);                      // BI_RGB
                bw.Write((int)pixels.Length);
                bw.Write((int)0); bw.Write((int)0); bw.Write((int)0); bw.Write((int)0);
                for (int y = size - 1; y >= 0; y--)    // DIB scanlines run bottom-up
                    bw.Write(pixels, y * size * 4, size * 4);
                // The AND mask stays all zero: the alpha channel carries the shape.
            }

            using (MemoryStream ms = new MemoryStream())
            using (BinaryWriter bw = new BinaryWriter(ms))
            {
                bw.Write((short)0);                    // reserved
                bw.Write((short)1);                    // type: icon
                bw.Write((short)1);                    // image count
                bw.Write((byte)(size >= 256 ? 0 : size));
                bw.Write((byte)(size >= 256 ? 0 : size));
                bw.Write((byte)0);                     // palette entries
                bw.Write((byte)0);                     // reserved
                bw.Write((short)1);                    // planes
                bw.Write((short)32);                   // bpp
                bw.Write((int)dib.Length);
                bw.Write((int)(6 + 16));               // image offset from the file start
                bw.Write(dib);
                bw.Flush();
                byte[] copy = new byte[ms.Length];
                Buffer.BlockCopy(ms.ToArray(), 0, copy, 0, copy.Length);
                return copy;
            }
        }
    }

    // =====================================================================
    // Contact cards (vCard) over chat.
    //
    // A card travels as one token line, [VCARD:FN|TEL|ORG|NOTE]. The chat
    // payload already carries pipe-delimited bodies (voice notes, large-message
    // stubs), and everything after the third field of a stored line is opaque
    // text, so pipes inside the card are safe.
    //
    // Only the four fields the bubble and the contacts list actually use are
    // kept. Real vCard 3.0 text is generated on demand (Copy card / save), so
    // another app still gets a standards-compliant card.
    // =====================================================================
    public static class VCard
    {
        public const string Prefix = "[VCARD:";

        public static string Token(string name, string number, string org, string note)
        {
            return Prefix + Clean(name, 60) + "|" + Clean(number, 24) + "|" +
                   Clean(org, 40) + "|" + Clean(note, 80) + "]";
        }

        public static bool Is(string text)
        {
            return !string.IsNullOrEmpty(text) &&
                   text.StartsWith(Prefix, StringComparison.Ordinal) &&
                   text.EndsWith("]", StringComparison.Ordinal);
        }

        // name, number, org, note - always four entries, never null.
        public static string[] Parse(string token)
        {
            string inner = token.Substring(Prefix.Length, token.Length - Prefix.Length - 1);
            string[] p = inner.Split(new char[] { '|' }, 4);
            string[] outp = new string[4];
            for (int i = 0; i < 4; i++) outp[i] = i < p.Length ? p[i] : "";
            return outp;
        }

        public static string ToVcf(string name, string number, string org, string note)
        {
            StringBuilder sb = new StringBuilder();
            sb.Append("BEGIN:VCARD\r\n");
            sb.Append("VERSION:3.0\r\n");
            sb.Append("N:").Append(Esc(number)).Append(";;;\r\n");
            sb.Append("FN:").Append(Esc(name)).Append("\r\n");
            if (!string.IsNullOrEmpty(org)) sb.Append("ORG:").Append(Esc(org)).Append("\r\n");
            if (!string.IsNullOrEmpty(number)) sb.Append("TEL;TYPE=CELL:").Append(Esc(number)).Append("\r\n");
            if (!string.IsNullOrEmpty(note)) sb.Append("NOTE:").Append(Esc(note)).Append("\r\n");
            sb.Append("END:VCARD\r\n");
            return sb.ToString();
        }

        static string Esc(string s)
        {
            return (s ?? "").Replace("\\", "\\\\").Replace(";", "\\;")
                          .Replace(",", "\\,").Replace("\r", "").Replace("\n", "\\n");
        }

        // A pipe or a bracket inside a field would break the token framing, so
        // they come out; contacts.txt is pipe-split too, which is the other
        // place these strings land.
        static string Clean(string s, int max)
        {
            string r = (s ?? "").Replace("|", "/").Replace("[", "(").Replace("]", ")")
                                .Replace("\r", "").Replace("\n", " ").Trim();
            if (r.Length > max) r = r.Substring(0, max);
            return r;
        }
    }

    public class Contact
    {
        public string Name { get; set; }
        public string Number { get; set; }
        public string Source { get; set; }
        public bool Fav { get; set; }
        public string Star { get { return Fav ? "\u2605" : "\u2606"; } }
    }

    public class SmsMessage
    {
        public string Time { get; set; }
        public string From { get; set; }
        public string Body { get; set; }
        public int Index { get; set; }
    }

    public class SmsCode
    {
        public string Time { get; set; }
        public string From { get; set; }
        public string Code { get; set; }
    }

    // One row of the "Recent" chat conversations panel.
    public class ChatRecent
    {
        public string Number { get; set; }
        public string Display { get; set; }   // contact name or #number (what the To box accepts)
        public string Preview { get; set; }
        public DateTime When { get; set; }
        public int Unread { get; set; }
        public override string ToString()
        {
            string pv = Preview == null ? "" : Preview;
            if (pv.Length > 46) pv = pv.Substring(0, 46) + "...";
            string badge = Unread > 0 ? "(" + Unread + ") " : "";
            return badge + Display + "  \u00B7  " + pv;
        }
    }

    // One chat bubble: relay peer-chat or SMS fallback.
    // Dir: "out" | "in" | "sys" | "sys"
    public class ChatMsg
    {
        public string Dir { get; set; }
        public string Date { get; set; }   // yyyy-MM-dd ("" for legacy lines)
        public string Time { get; set; }   // HH:mm:ss
        public string Text { get; set; }
        public bool Delivered { get; set; }   // my message confirmed by the peer
    }

    // One entry of the persistent call history (Recents list).
    // Dir: "out" | "in" | "missed"   Kind: "sim" | "voip" | "video"
    public class CallRec
    {
        public string Number { get; set; }
        public string Dir { get; set; }
        public string Kind { get; set; }
        public string When { get; set; }   // yyyy-MM-dd HH:mm:ss
        public int Secs { get; set; }
    }

    // Thread-tagged append-only breadcrumbs for hang diagnosis (hang_trace.txt).
    public static class Hang
    {
        public static void Trace(string s)
        {
            try
            {
                string path = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "hang_trace.txt");
                // FileShare.ReadWrite: a watcher reading the trace must never make
                // this append fail (the catch would silently drop the line).
                using (FileStream fs = new FileStream(path, FileMode.Append, FileAccess.Write, FileShare.ReadWrite))
                using (StreamWriter sw = new StreamWriter(fs))
                {
                    sw.WriteLine(DateTime.Now.ToString("HH:mm:ss.fff") + " [t" + System.Threading.Thread.CurrentThread.ManagedThreadId + "] "
                        + s);
                }
            }
            catch { }
        }
    }

    // In-call tone generation: DTMF key tones and the incoming-ring loop,
    // synthesized as 16 kHz mono WAVs (no assets, no extra dependencies).
    public static class ToneSynth
    {
        private static readonly object RingLock = new object();
        private static System.Media.SoundPlayer _ring;
        private static bool _ringing;

        public static byte[] Wav(double[] freqs, int ms)
        {
            int rate = 16000;
            int n = rate * ms / 1000;
            if (n < 1) n = 1;
            byte[] data = new byte[n * 2];
            int fade = rate / 200;               // 5 ms fade in/out, no clicks
            for (int i = 0; i < n; i++)
            {
                double s = 0;
                for (int f = 0; f < freqs.Length; f++)
                    s += Math.Sin(2 * Math.PI * freqs[f] * i / rate);
                s /= freqs.Length;
                double amp = 0.35;
                if (i < fade) amp *= i / (double)fade;
                else if (i > n - fade) amp *= (n - i) / (double)fade;
                short v = (short)(s * amp * short.MaxValue);
                data[i * 2] = (byte)(v & 0xff);
                data[i * 2 + 1] = (byte)((v >> 8) & 0xff);
            }
            byte[] wav = new byte[44 + data.Length];
            wav[0] = (byte)'R'; wav[1] = (byte)'I'; wav[2] = (byte)'F'; wav[3] = (byte)'F';
            BitConverter.GetBytes(36 + data.Length).CopyTo(wav, 4);
            wav[8] = (byte)'W'; wav[9] = (byte)'A'; wav[10] = (byte)'V'; wav[11] = (byte)'E';
            wav[12] = (byte)'f'; wav[13] = (byte)'m'; wav[14] = (byte)'t'; wav[15] = (byte)' ';
            BitConverter.GetBytes(16).CopyTo(wav, 16);
            BitConverter.GetBytes((short)1).CopyTo(wav, 20);      // PCM
            BitConverter.GetBytes((short)1).CopyTo(wav, 22);      // mono
            BitConverter.GetBytes(rate).CopyTo(wav, 24);
            BitConverter.GetBytes(rate * 2).CopyTo(wav, 28);      // byte rate
            BitConverter.GetBytes((short)2).CopyTo(wav, 32);      // block align
            BitConverter.GetBytes((short)16).CopyTo(wav, 34);     // bits
            wav[36] = (byte)'d'; wav[37] = (byte)'a'; wav[38] = (byte)'t'; wav[39] = (byte)'a';
            BitConverter.GetBytes(data.Length).CopyTo(wav, 40);
            Buffer.BlockCopy(data, 0, wav, 44, data.Length);
            return wav;
        }

        public static void Play(double[] freqs, int ms)
        {
            try
            {
                byte[] w = Wav(freqs, ms);
                System.Threading.ThreadPool.QueueUserWorkItem(delegate
                {
                    try
                    {
                        System.Media.SoundPlayer p = new System.Media.SoundPlayer(new System.IO.MemoryStream(w));
                        p.PlaySync();
                    }
                    catch { }
                });
            }
            catch { }
        }

        private static double[] DtmfFreq(string d)
        {
            double[] rows = new double[] { 697, 770, 852, 941 };
            double[] cols = new double[] { 1209, 1336, 1477 };
            int r, c;
            switch (d)
            {
                case "1": r = 0; c = 0; break;
                case "2": r = 0; c = 1; break;
                case "3": r = 0; c = 2; break;
                case "4": r = 1; c = 0; break;
                case "5": r = 1; c = 1; break;
                case "6": r = 1; c = 2; break;
                case "7": r = 2; c = 0; break;
                case "8": r = 2; c = 1; break;
                case "9": r = 2; c = 2; break;
                case "*": r = 3; c = 0; break;
                case "0": r = 3; c = 1; break;
                case "#": r = 3; c = 2; break;
                default: return null;
            }
            return new double[] { rows[r], cols[c] };
        }

        public static void PlayDtmf(string digit)
        {
            double[] f = DtmfFreq(digit);
            if (f != null) { Hang.Trace("tone: dtmf " + digit); Play(f, 130); }
        }

        // Repeating melodic piano-style heartbreak theme ring.
        // Built from synthesized piano harmonics (fundamental + overtones) that
        // approximate a minor-key broken-chord motif: Am → F → C → G
        // Each note is a sum of sine waves at the fundamental + 2nd/3rd harmonics,
        // windowed so there are no clicks on loop.
        public static void StartRing()
        {
            lock (RingLock)
            {
                if (_ringing) return;
                _ringing = true;
                try
                {
                    byte[] w = BuildPianoRing();
                    _ring = new System.Media.SoundPlayer(new System.IO.MemoryStream(w));
                    _ring.PlayLooping();
                    Hang.Trace("tone: piano ring start");
                }
                catch { _ringing = false; }
            }
        }

        // Build a 4-note piano motif WAV: A3 → E4 → A4 → C5 (heartbreak Am arp)
        private static byte[] BuildPianoRing()
        {
            int rate = 16000;
            // note frequencies: A3=220, E4=329.63, A4=440, C5=523.25
            double[] notes = new double[] { 220.0, 329.63, 440.0, 523.25 };
            int noteDurMs = 400;   // ms per note
            int gapMs = 60;        // silence between notes
            int loopMs = 800;      // silence at end before repeat

            List<byte> pcm = new List<byte>();

            foreach (double fund in notes)
            {
                // Piano tone = fundamental + harmonics at decreasing amplitudes
                double[] freqs = new double[] { fund, fund * 2.0, fund * 3.0, fund * 4.0 };
                double[] amps  = new double[] { 1.0,   0.55,       0.30,       0.15 };
                int n = rate * noteDurMs / 1000;
                int attack = rate * 8 / 1000;    // 8 ms attack
                int release = rate * 120 / 1000; // 120 ms release (piano sustain tail)
                for (int i = 0; i < n; i++)
                {
                    double s = 0;
                    for (int h = 0; h < freqs.Length; h++)
                        s += amps[h] * Math.Sin(2 * Math.PI * freqs[h] * i / rate);
                    // Envelope: fast attack, exponential decay (piano-like)
                    double env = 0.38;
                    if (i < attack) env *= (double)i / attack;
                    else env *= Math.Exp(-3.5 * (i - attack) / (double)n);
                    short v = (short)(s * env * short.MaxValue);
                    pcm.Add((byte)(v & 0xff));
                    pcm.Add((byte)((v >> 8) & 0xff));
                }
                // Gap silence
                int gapSamples = rate * gapMs / 1000;
                for (int i = 0; i < gapSamples; i++) { pcm.Add(0); pcm.Add(0); }
            }
            // Loop tail silence
            int loopSamples = rate * loopMs / 1000;
            for (int i = 0; i < loopSamples; i++) { pcm.Add(0); pcm.Add(0); }

            byte[] data = pcm.ToArray();
            byte[] wav = new byte[44 + data.Length];
            wav[0] = (byte)'R'; wav[1] = (byte)'I'; wav[2] = (byte)'F'; wav[3] = (byte)'F';
            BitConverter.GetBytes(36 + data.Length).CopyTo(wav, 4);
            wav[8] = (byte)'W'; wav[9] = (byte)'A'; wav[10] = (byte)'V'; wav[11] = (byte)'E';
            wav[12] = (byte)'f'; wav[13] = (byte)'m'; wav[14] = (byte)'t'; wav[15] = (byte)' ';
            BitConverter.GetBytes(16).CopyTo(wav, 16);
            BitConverter.GetBytes((short)1).CopyTo(wav, 20);
            BitConverter.GetBytes((short)1).CopyTo(wav, 22);
            BitConverter.GetBytes(rate).CopyTo(wav, 24);
            BitConverter.GetBytes(rate * 2).CopyTo(wav, 28);
            BitConverter.GetBytes((short)2).CopyTo(wav, 32);
            BitConverter.GetBytes((short)16).CopyTo(wav, 34);
            wav[36] = (byte)'d'; wav[37] = (byte)'a'; wav[38] = (byte)'t'; wav[39] = (byte)'a';
            BitConverter.GetBytes(data.Length).CopyTo(wav, 40);
            Buffer.BlockCopy(data, 0, wav, 44, data.Length);
            return wav;
        }

        public static void StopRing()
        {
            lock (RingLock)
            {
                if (!_ringing) return;
                _ringing = false;
                Hang.Trace("tone: ring stop");
                try { if (_ring != null) _ring.Stop(); } catch { }
                _ring = null;
            }
        }
    }

    // Bottom-right toast popup for incoming calls/messages while the user is
    // elsewhere (another app or another tab). Never steals focus; clicking
    // navigates and dismisses.
    public static class Toast
    {
        public static void Show(string title, string body, Action onClick)
        {
            try
            {
                ToastWindow w = new ToastWindow(title, body, onClick);
                w.ShowToast();
            }
            catch { }
        }

        private sealed class ToastWindow : Window
        {
            private readonly string _title, _body;
            private readonly Action _onClick;
            private System.Windows.Threading.DispatcherTimer _life;

            public ToastWindow(string title, string body, Action onClick)
            {
                _title = title; _body = body; _onClick = onClick;
                WindowStyle = WindowStyle.None;
                AllowsTransparency = true;
                Background = System.Windows.Media.Brushes.Transparent;
                Topmost = true;
                ShowInTaskbar = false;
                ShowActivated = false;      // never steal input focus
                Width = 320;
                SizeToContent = SizeToContent.Height;

                System.Windows.Controls.Border card = new System.Windows.Controls.Border
                {
                    Background = new SolidColorBrush(System.Windows.Media.Color.FromRgb(0x1a, 0x1d, 0x28)),
                    BorderBrush = new SolidColorBrush(System.Windows.Media.Color.FromRgb(0x4f, 0x8c, 0xff)),
                    BorderThickness = new Thickness(1),
                    CornerRadius = new CornerRadius(10),
                    Padding = new Thickness(14, 10, 14, 10),
                    Margin = new Thickness(8),
                    Effect = Application.Current != null ? Application.Current.TryFindResource("PillShadow") as System.Windows.Media.Effects.Effect : null
                };
                System.Windows.Controls.StackPanel sp = new System.Windows.Controls.StackPanel();
                sp.Children.Add(new TextBlock
                {
                    Text = title,
                    Foreground = System.Windows.Media.Brushes.White,
                    FontWeight = FontWeights.SemiBold,
                    FontSize = 13,
                    TextWrapping = TextWrapping.Wrap
                });
                sp.Children.Add(new TextBlock
                {
                    Text = body,
                    Foreground = new SolidColorBrush(System.Windows.Media.Color.FromRgb(0xc9, 0xd4, 0xe8)),
                    FontSize = 12,
                    TextWrapping = TextWrapping.Wrap,
                    Margin = new Thickness(0, 3, 0, 0)
                });
                card.Child = sp;
                Content = card;

                MouseLeftButtonUp += delegate { Dismiss(true); };
            }

            public void ShowToast()
            {
                Position();
                Opacity = 0;
                Show();
                System.Windows.Media.Animation.DoubleAnimation fade =
                    new System.Windows.Media.Animation.DoubleAnimation(0, 1, TimeSpan.FromMilliseconds(180));
                BeginAnimation(OpacityProperty, fade);
                _life = new System.Windows.Threading.DispatcherTimer { Interval = TimeSpan.FromSeconds(6) };
                _life.Tick += delegate { Dismiss(false); };
                _life.Start();
            }

            private void Position()
            {
                try
                {
                    double wa = SystemParameters.WorkArea.Bottom;
                    double wa2 = SystemParameters.WorkArea.Right;
                    Left = wa2 - Width - 10;
                    Top = wa - 80;
                }
                catch { }
            }

            private void Dismiss(bool clicked)
            {
                try
                {
                    if (_life != null) _life.Stop();
                    Action close = delegate
                    {
                        System.Windows.Media.Animation.DoubleAnimation fade =
                            new System.Windows.Media.Animation.DoubleAnimation(0, TimeSpan.FromMilliseconds(150));
                        fade.Completed += delegate
                        {
                            try { Close(); } catch { }
                        };
                        BeginAnimation(OpacityProperty, fade);
                    };
                    // click navigation must happen before the fade so state is set
                    if (clicked && _onClick != null) { try { _onClick(); } catch { } }
                    close();
                }
                catch { }
            }
        }
    }

    public class AppConfig
    {
        public string mifi_ip = "http://192.168.100.1";
        public string com_port = "";
        public string baud = "115200";
        public bool use_serial = false;
        public bool auto_connect = false;
        // Internet calling: persistent per-device virtual number + relay server.
        public string virtual_number = "";
        public string number_token = "";
        public string relay_server = "";   // host:port of the call server ("" = LAN only)
        public string tracker_server = "";
        public string tracker_pair_code = "";
        public string tracker_device_id = "";
        public string tracker_token_protected = "";
        public string laptop_tracker_exe = "";
        public string calls_companion_exe = "";
        public bool host_calls = false;    // run the call server on this PC
        // Put a call's audio/video on the relay instead of trying UDP first. Off by
        // default; it exists for networks that block or shape UDP, and it is NOT what
        // hides your address from a peer (the directory already carries it to them).
        public bool relay_media = false;
        // Ask the router (UPnP IGD) to forward the relay port when this PC hosts.
        // Default off: it changes something outside this machine, and only some
        // networks have a router that will answer the question.
        public bool relay_port_map = false;
        public bool relay_tls = false;      // require authenticated TLS 1.2 on hosted relay sockets
        // Federation: this PC carrying traffic for other relays, and which
        // relays it dials out to. Defaults keep today's behaviour - hosting is
        // unchanged, and nothing is relayed to strangers until it is turned on.
        public string relay_policy = "allowed";   // nobody | allowed | everyone
        public string relay_allow = "";           // hosts / host:port / relay names allowed to link
        public string relay_peers = "";           // relays to link out to: host:port,host:port
        public string relay_advertise = "";       // address others should dial me on
        public bool relay_autolink = false;       // link relays found by discovery/referral
        public bool relay_automesh = false;       // dial relays a link told us about
        public string relay_onion = "off";        // off | best | force: hide the pair from an intermediate hop
        public bool relay_carry_mail = false;     // hand copies of offline mail to linked relays
        public int relay_store_kb = 2048;         // queue space spent on other relays' mail
        public int relay_bandwidth_kbps = 0;      // 0 = uncapped
        // A KISS radio link (LoRa RNode, TNC, Reticulum modem). Off unless a
        // port is named: the app must not open somebody's serial port because a
        // default value guessed at it.
        public string radio_port = "";           // COM port of a KISS modem, "" = no radio
        public string radio_callsign = "";       // callsign this node sends as
        public bool radio_carries = false;       // this node repeats for others
        // A bridge to the phone network, only if the user already has one.
        // Nothing probes it, nothing is assumed, and it is never chosen while a
        // usable SIM exists.
        public bool gateway_enabled = false;
        public string gateway_name = "";
        // UI / identity / connectivity tokens.
        public string theme = "light";             // "light" | "dark"
        public string display_name = "";           // shown to peers on calls & messages
        public string stun_servers = "stun.l.google.com:19302,stun1.l.google.com:19302,stun.stunprotocol.org:3478,stun.voip.blackberry.com:3478";
        // Call audio quality / archive.
        public bool noise_filter = true;           // mic gate + AGC + echo cancel
        public bool record_calls = false;          // archive VoIP calls to recordings\
        // Call transcription. whisper.cpp is *not* bundled - the user points at
        // a local binary and model, and until both exist the feature stays off.
        public bool transcribe_calls = false;      // subtitles via a local whisper.cpp
        public string whisper_exe = "";            // whisper-cli.exe / main.exe
        public string whisper_model = "";          // ggml-*.bin
        public string whisper_lang = "auto";       // forced language, or auto
        // Chat customisation + AI
        public string chat_bg_color = "";          // hex color e.g. "#101624"
        public string chat_bg_image = "";          // full path to background image
        public string ai_api_key = "";             // OpenAI / Gemini / local API key
        public string ai_model = "gpt-4o-mini";   // model identifier
        public string ai_endpoint = "https://api.openai.com/v1/chat/completions"; // API base URL
        public bool ai_enabled = false;
        // Wake agent (C1): keep a headless listener on the relay after this
        // window closes, so traffic for this number is caught and replayed on
        // the next open instead of being dropped by a peer-less endpoint.
        public bool always_awake = false;
        // Does this node carry other people's traffic over a link that could be
        // used that way? Off by default: it is a favour, not an obligation, and
        // the router refuses it until the owner says otherwise.
        public bool carry_for_peers = false;

        // Every user-data path hangs off Home.Dir, not the exe folder, so the
        // wake agent can launch this exe with --home=<profile> and the window
        // opens on exactly the identity/chats the agent was holding.
        public static string FilePath
        {
            get { return Path.Combine(Home.Dir, "ussd_config.json"); }
        }

        public static string ContactsPath
        {
            get { return Path.Combine(Home.Dir, "contacts.txt"); }
        }

        // Per-number chat logs live here as chat_<number>.txt
        public static string ChatsDir
        {
            get { return Path.Combine(Home.Dir, "chats"); }
        }

        public static string HistoryPath
        {
            get { return Path.Combine(Home.Dir, "call_history.txt"); }
        }

        public static AppConfig Load()
        {
            try
            {
                if (File.Exists(FilePath))
                {
                    string t = File.ReadAllText(FilePath);
                    AppConfig c = new AppConfig();
                    Match m;
                    m = Regex.Match(t, "\"mifi_ip\"\\s*:\\s*\"([^\"]*)\""); if (m.Success) c.mifi_ip = m.Groups[1].Value;
                    m = Regex.Match(t, "\"com_port\"\\s*:\\s*\"([^\"]*)\""); if (m.Success) c.com_port = m.Groups[1].Value;
                    m = Regex.Match(t, "\"baud\"\\s*:\\s*\"([^\"]*)\""); if (m.Success) c.baud = m.Groups[1].Value;
                    m = Regex.Match(t, "\"use_serial\"\\s*:\\s*(true|false)"); if (m.Success) c.use_serial = m.Groups[1].Value == "true";
                    m = Regex.Match(t, "\"auto_connect\"\\s*:\\s*(true|false)"); if (m.Success) c.auto_connect = m.Groups[1].Value == "true";
                    m = Regex.Match(t, "\"virtual_number\"\\s*:\\s*\"([^\"]*)\""); if (m.Success) c.virtual_number = m.Groups[1].Value;
                    m = Regex.Match(t, "\"number_token\"\\s*:\\s*\"([^\"]*)\""); if (m.Success) c.number_token = m.Groups[1].Value;
                    m = Regex.Match(t, "\"relay_server\"\\s*:\\s*\"([^\"]*)\""); if (m.Success) c.relay_server = m.Groups[1].Value;
                    m = Regex.Match(t, "\"tracker_server\"\\s*:\\s*\"([^\"]*)\""); if (m.Success) c.tracker_server = m.Groups[1].Value;
                    m = Regex.Match(t, "\"tracker_pair_code\"\\s*:\\s*\"([^\"]*)\""); if (m.Success) c.tracker_pair_code = m.Groups[1].Value;
                    m = Regex.Match(t, "\"tracker_device_id\"\\s*:\\s*\"([^\"]*)\""); if (m.Success) c.tracker_device_id = m.Groups[1].Value;
                    m = Regex.Match(t, "\"tracker_token_protected\"\\s*:\\s*\"([^\"]*)\""); if (m.Success) c.tracker_token_protected = m.Groups[1].Value;
                    m = Regex.Match(t, "\"laptop_tracker_exe\"\\s*:\\s*\"([^\"]*)\""); if (m.Success) c.laptop_tracker_exe = m.Groups[1].Value;
                    m = Regex.Match(t, "\"calls_companion_exe\"\\s*:\\s*\"([^\"]*)\""); if (m.Success) c.calls_companion_exe = m.Groups[1].Value;
                    m = Regex.Match(t, "\"host_calls\"\\s*:\\s*(true|false)"); if (m.Success) c.host_calls = m.Groups[1].Value == "true";
                    m = Regex.Match(t, "\"relay_media\"\\s*:\\s*(true|false)"); if (m.Success) c.relay_media = m.Groups[1].Value == "true";
                    m = Regex.Match(t, "\"relay_port_map\"\\s*:\\s*(true|false)"); if (m.Success) c.relay_port_map = m.Groups[1].Value == "true";
                    m = Regex.Match(t, "\"relay_tls\"\\s*:\\s*(true|false)"); if (m.Success) c.relay_tls = m.Groups[1].Value == "true";
                    m = Regex.Match(t, "\"theme\"\\s*:\\s*\"([^\"]*)\""); if (m.Success) c.theme = m.Groups[1].Value;
                    m = Regex.Match(t, "\"display_name\"\\s*:\\s*\"([^\"]*)\""); if (m.Success) c.display_name = m.Groups[1].Value;
                    m = Regex.Match(t, "\"stun_servers\"\\s*:\\s*\"([^\"]*)\""); if (m.Success) c.stun_servers = m.Groups[1].Value;
                    m = Regex.Match(t, "\"noise_filter\"\\s*:\\s*(true|false)"); if (m.Success) c.noise_filter = m.Groups[1].Value == "true";
                    m = Regex.Match(t, "\"record_calls\"\\s*:\\s*(true|false)"); if (m.Success) c.record_calls = m.Groups[1].Value == "true";
                    m = Regex.Match(t, "\"transcribe_calls\"\\s*:\\s*(true|false)"); if (m.Success) c.transcribe_calls = m.Groups[1].Value == "true";
                    m = Regex.Match(t, "\"whisper_exe\"\\s*:\\s*\"([^\"]*)\""); if (m.Success) c.whisper_exe = m.Groups[1].Value;
                    m = Regex.Match(t, "\"whisper_model\"\\s*:\\s*\"([^\"]*)\""); if (m.Success) c.whisper_model = m.Groups[1].Value;
                    m = Regex.Match(t, "\"whisper_lang\"\\s*:\\s*\"([^\"]*)\""); if (m.Success) c.whisper_lang = m.Groups[1].Value;
                    m = Regex.Match(t, "\"relay_policy\"\\s*:\\s*\"([^\"]*)\""); if (m.Success) c.relay_policy = m.Groups[1].Value;
                    m = Regex.Match(t, "\"relay_allow\"\\s*:\\s*\"([^\"]*)\""); if (m.Success) c.relay_allow = m.Groups[1].Value;
                    m = Regex.Match(t, "\"relay_peers\"\\s*:\\s*\"([^\"]*)\""); if (m.Success) c.relay_peers = m.Groups[1].Value;
                    m = Regex.Match(t, "\"relay_advertise\"\\s*:\\s*\"([^\"]*)\""); if (m.Success) c.relay_advertise = m.Groups[1].Value;
                    m = Regex.Match(t, "\"relay_autolink\"\\s*:\\s*(true|false)"); if (m.Success) c.relay_autolink = m.Groups[1].Value == "true";
                    m = Regex.Match(t, "\"relay_automesh\"\\s*:\\s*(true|false)"); if (m.Success) c.relay_automesh = m.Groups[1].Value == "true";
                    m = Regex.Match(t, "\"relay_onion\"\\s*:\\s*\"([^\"]*)\""); if (m.Success) c.relay_onion = m.Groups[1].Value;
                    m = Regex.Match(t, "\"relay_carry_mail\"\\s*:\\s*(true|false)"); if (m.Success) c.relay_carry_mail = m.Groups[1].Value == "true";
                    m = Regex.Match(t, "\"relay_store_kb\"\\s*:\\s*(\\d+)"); if (m.Success) { int v; if (int.TryParse(m.Groups[1].Value, out v)) c.relay_store_kb = v; }
                    m = Regex.Match(t, "\"relay_bandwidth_kbps\"\\s*:\\s*(\\d+)"); if (m.Success) { int v; if (int.TryParse(m.Groups[1].Value, out v)) c.relay_bandwidth_kbps = v; }
                    m = Regex.Match(t, "\"gateway_enabled\"\\s*:\\s*(true|false)"); if (m.Success) c.gateway_enabled = m.Groups[1].Value == "true";
                    m = Regex.Match(t, "\"gateway_name\"\\s*:\\s*\"([^\"]*)\""); if (m.Success) c.gateway_name = m.Groups[1].Value;
                    m = Regex.Match(t, "\"radio_port\"\\s*:\\s*\"([^\"]*)\""); if (m.Success) c.radio_port = m.Groups[1].Value;
                    m = Regex.Match(t, "\"radio_callsign\"\\s*:\\s*\"([^\"]*)\""); if (m.Success) c.radio_callsign = m.Groups[1].Value;
                    m = Regex.Match(t, "\"radio_carries\"\\s*:\\s*(true|false)"); if (m.Success) c.radio_carries = m.Groups[1].Value == "true";
                    m = Regex.Match(t, "\"chat_bg_color\"\\s*:\\s*\"([^\"]*)\""); if (m.Success) c.chat_bg_color = m.Groups[1].Value;
                    m = Regex.Match(t, "\"chat_bg_image\"\\s*:\\s*\"([^\"]*)\""); if (m.Success) c.chat_bg_image = m.Groups[1].Value;
                    m = Regex.Match(t, "\"ai_api_key\"\\s*:\\s*\"([^\"]*)\""); if (m.Success) c.ai_api_key = m.Groups[1].Value;
                    m = Regex.Match(t, "\"ai_model\"\\s*:\\s*\"([^\"]*)\""); if (m.Success) c.ai_model = m.Groups[1].Value;
                    m = Regex.Match(t, "\"ai_endpoint\"\\s*:\\s*\"([^\"]*)\""); if (m.Success) c.ai_endpoint = m.Groups[1].Value;
                    m = Regex.Match(t, "\"ai_enabled\"\\s*:\\s*(true|false)"); if (m.Success) c.ai_enabled = m.Groups[1].Value == "true";
                    m = Regex.Match(t, "\"always_awake\"\\s*:\\s*(true|false)"); if (m.Success) c.always_awake = m.Groups[1].Value == "true";
                    m = Regex.Match(t, "\"carry_for_peers\"\\s*:\\s*(true|false)"); if (m.Success) c.carry_for_peers = m.Groups[1].Value == "true";
                    return c;
                }
            }
            catch { }
            return new AppConfig();
        }

        public void Save()
        {
            string json = "{\n" +
                "  \"mifi_ip\": \"" + J(mifi_ip) + "\",\n" +
                "  \"com_port\": \"" + J(com_port) + "\",\n" +
                "  \"baud\": \"" + J(baud) + "\",\n" +
                "  \"use_serial\": " + (use_serial ? "true" : "false") + ",\n" +
                "  \"auto_connect\": " + (auto_connect ? "true" : "false") + ",\n" +
                "  \"virtual_number\": \"" + J(virtual_number) + "\",\n" +
                "  \"number_token\": \"" + J(number_token) + "\",\n" +
                "  \"relay_server\": \"" + J(relay_server) + "\",\n" +
                "  \"tracker_server\": \"" + J(tracker_server) + "\",\n" +
                "  \"tracker_pair_code\": \"" + J(tracker_pair_code) + "\",\n" +
                "  \"tracker_device_id\": \"" + J(tracker_device_id) + "\",\n" +
                "  \"tracker_token_protected\": \"" + J(tracker_token_protected) + "\",\n" +
                "  \"laptop_tracker_exe\": \"" + J(laptop_tracker_exe) + "\",\n" +
                "  \"calls_companion_exe\": \"" + J(calls_companion_exe) + "\",\n" +
                "  \"host_calls\": " + (host_calls ? "true" : "false") + ",\n" +
                "  \"relay_media\": " + (relay_media ? "true" : "false") + ",\n" +
                "  \"relay_port_map\": " + (relay_port_map ? "true" : "false") + ",\n" +
                "  \"relay_tls\": " + (relay_tls ? "true" : "false") + ",\n" +
                "  \"theme\": \"" + J(theme) + "\",\n" +
                "  \"display_name\": \"" + J(display_name) + "\",\n" +
                "  \"stun_servers\": \"" + J(stun_servers) + "\",\n" +
                "  \"noise_filter\": " + (noise_filter ? "true" : "false") + ",\n" +
                "  \"record_calls\": " + (record_calls ? "true" : "false") + ",\n" +
                "  \"transcribe_calls\": " + (transcribe_calls ? "true" : "false") + ",\n" +
                "  \"whisper_exe\": \"" + J(whisper_exe) + "\",\n" +
                "  \"whisper_model\": \"" + J(whisper_model) + "\",\n" +
                "  \"whisper_lang\": \"" + J(string.IsNullOrEmpty(whisper_lang) ? "auto" : whisper_lang) + "\",\n" +
                "  \"relay_policy\": \"" + J(string.IsNullOrEmpty(relay_policy) ? "allowed" : relay_policy) + "\",\n" +
                "  \"relay_allow\": \"" + J(relay_allow) + "\",\n" +
                "  \"relay_peers\": \"" + J(relay_peers) + "\",\n" +
                "  \"relay_advertise\": \"" + J(relay_advertise) + "\",\n" +
                "  \"relay_autolink\": " + (relay_autolink ? "true" : "false") + ",\n" +
                "  \"relay_automesh\": " + (relay_automesh ? "true" : "false") + ",\n" +
                "  \"relay_onion\": \"" + J(relay_onion) + "\",\n" +
                "  \"relay_carry_mail\": " + (relay_carry_mail ? "true" : "false") + ",\n" +
                "  \"relay_store_kb\": " + relay_store_kb + ",\n" +
                "  \"relay_bandwidth_kbps\": " + relay_bandwidth_kbps + ",\n" +
                "  \"gateway_enabled\": " + (gateway_enabled ? "true" : "false") + ",\n" +
                "  \"gateway_name\": \"" + J(gateway_name) + "\",\n" +
                "  \"radio_port\": \"" + J(radio_port) + "\",\n" +
                "  \"radio_callsign\": \"" + J(radio_callsign) + "\",\n" +
                "  \"radio_carries\": " + (radio_carries ? "true" : "false") + ",\n" +
                "  \"chat_bg_color\": \"" + J(chat_bg_color) + "\",\n" +
                "  \"chat_bg_image\": \"" + J(chat_bg_image) + "\",\n" +
                "  \"ai_api_key\": \"" + J(ai_api_key) + "\",\n" +
                "  \"ai_model\": \"" + J(ai_model) + "\",\n" +
                "  \"ai_endpoint\": \"" + J(ai_endpoint) + "\",\n" +
                "  \"ai_enabled\": " + (ai_enabled ? "true" : "false") + ",\n" +
                "  \"always_awake\": " + (always_awake ? "true" : "false") + ",\n" +
                "  \"carry_for_peers\": " + (carry_for_peers ? "true" : "false") + "\n" +
                "}";
            File.WriteAllText(FilePath, json);
        }

        // First run: mint this device's persistent virtual number + secret token.
        // App-network numbers always follow the recognizable 700-XXX-XXXX pattern;
        // legacy random 10-digit numbers are migrated on load.
        //
        // Said out loud when it happens, because minting a number in silence is the
        // difference between "I have an app number" and "I have a string in a file I will
        // never open". Deliberately not written to the JSON: it means "this launch created
        // them", and that is worth one screen of guidance, not a permanent setting.
        public bool FirstRunIdentity;

        public void EnsureIdentity()
        {
            if (!AppNum.IsApp(virtual_number))
            {
                byte[] b = new byte[4];
                using (var rng = System.Security.Cryptography.RandomNumberGenerator.Create())
                    rng.GetBytes(b);
                uint v = BitConverter.ToUInt32(b, 0) % 10000000u; // 7 digits
                virtual_number = "700" + v.ToString("D7");
                FirstRunIdentity = true;
            }
            if (string.IsNullOrEmpty(number_token))
            {
                byte[] t = new byte[16];
                using (var rng = System.Security.Cryptography.RandomNumberGenerator.Create())
                    rng.GetBytes(t);
                StringBuilder sb = new StringBuilder(32);
                foreach (byte x in t) sb.Append(x.ToString("x2"));
                number_token = sb.ToString();
            }
            if (string.IsNullOrEmpty(display_name))
                display_name = Environment.UserName;
        }

        private static string J(string s)
        {
            if (s == null) return "";
            return s.Replace("\\", "\\\\").Replace("\"", "\\\"");
        }
    }

    // App-network number helpers: numbers always follow the recognizable
    // 700-XXX-XXXX pattern (10 digits, leading "700").
    public static class AppNum
    {
        public static string Digits(string s)
        {
            if (string.IsNullOrEmpty(s)) return "";
            StringBuilder sb = new StringBuilder(s.Length);
            foreach (char c in s)
                if (c >= '0' && c <= '9') sb.Append(c);
            return sb.ToString();
        }

        // "700 111 1111" / "700-111-1111" / "7001111111" -> true
        public static bool IsApp(string s)
        {
            string d = Digits(s);
            return d.Length == 10 && d.StartsWith("700");
        }

        // 7001111111 -> "700 111 1111" (anything else returned unchanged)
        public static string Format(string s)
        {
            string d = Digits(s);
            if (d.Length == 10 && d.StartsWith("700"))
                return d.Substring(0, 3) + " " + d.Substring(3, 3) + " " + d.Substring(6);
            return s ?? "";
        }

        // Digits for app numbers; otherwise the trimmed original (GSM side keeps
        // +, * and # so dial codes still work).
        public static string NormalizeForCall(string s)
        {
            if (IsApp(s)) return Digits(s);
            return (s ?? "").Trim();
        }
    }

    // Command-line overrides (testing two instances that share one config file):
    //   --number=2000123456   --relay=host:45675   --host   --no-host   --port=45675
    //   --send=<number>|<text>  --watch=<seconds>  --linger=<seconds>   (headless)
    //   --call=<number> [--video]  dial a relay call headless; --answer accepts one
    //   --bootstrap   with no --relay=, try the relays.seed list (each entry is asked to
    //                 identify itself before anything is registered). The window does the
    //                 same on its own whenever the Relay box is left empty.
    //   --relay-media  start a call on the relay instead of trying UDP first. For networks
    //                 that block UDP; it does NOT hide your address from the peer.
    //   --relay-port-map  (with --serve) ask the router to forward the relay's port and
    //                 advertise the public address it reports. Off unless said.
    //   --relay-tls    (with --serve) require TLS 1.2 and a valid relay_tls.pfx in --home.
    //   --map-media-port  (a caller) also ask for the UDP forward to the media port, which
    //                 is the one a direct call needs; a TCP relay forward does not help it.
    //   --home=<dir>   put every user file (identity, peers, chats, config) there
    //   --tracker-url=https://host[:port]  external laptop-tracker service endpoint
    //   --tracker-generate | --tracker-verify --tracker-pair=<code> | --tracker-info (paired profile)
    //   --tracker-heartbeat [--tracker-device=<id>] [--tracker-lat=<n> --tracker-lng=<n>] [--tracker-source=<tag>]
    //   --tracker-lost-on/--tracker-lost-off [--tracker-device=<id>]
    //   --agent  [--gui=<exe>] [--agent-timeout=<sec>]   always-awake listener (C1)
    public static class Cli
    {
        public static string NumberOverride;
        public static string RelayOverride;
        public static int PortOverride;
        public static bool? HostOverride;
        public static string SendSpec;
        public static int WatchSeconds;
        public static int LingerSeconds = 8;
        public static string HomeOverride;
        public static bool Agent;
        public static string GuiOverride;
        public static int AgentTimeoutSeconds;
        // A relay node with no window: --serve. Hosting a relay currently means
        // keeping a desktop session open with a WPF tree alive for weeks, which
        // is the wrong shape for the node everybody else registers with. These
        // overrides also let a test or a service manager configure federation
        // without editing JSON by hand.
        public static bool Serve;
        public static int ServeTimeoutSeconds;
        public static string PeersOverride;
        public static string PolicyOverride;
        public static string AllowOverride;
        public static string OnionOverride;
        public static bool CarryMailOverride;
        // Ask the router to open the relay's port. Off unless said, because it touches
        // shared infrastructure and fails on networks that never offered it.
        public static bool PortMapOverride;
        public static bool RelayTls;
        // Ask the router for a UDP forward to this machine's media port, so a call can
        // arrive directly instead of only through a relay. Separate from --relay-port-map
        // because a caller and a host are different machines with different needs.
        public static bool MapMediaPort;
        public static string ReleaseNumberOverride;
        // A call with no window: --call=<number> [--video] dials, --answer accepts.
        // Two laptops is the real test, and neither of them can be a person clicking
        // Answer at 3 am for the benefit of a script - so the call path has to be
        // drivable and reportable from the command line like the chat path already is.
        public static string CallNumber;
        public static bool CallVideo;
        // Put a call's media on the relay instead of trying UDP first. A client option,
        // not a relay option - and it is for networks that block UDP, not for hiding
        // anything: the relay directory already carries your address to a peer.
        public static bool RelayMedia;
        public static bool AnswerMode;
        // Find a relay from relays.seed instead of being told one. Kept explicit
        // rather than automatic: quietly connecting to a server the user never chose,
        // in a GUI they can see, is the thing this project has been burned by before.
        public static bool BootstrapRelay;
        // Optional integration with laptop-tracker. Explicit only: no endpoint is
        // contacted unless the user passes tracker flags.
        public static string TrackerUrl;
        public static string TrackerPairCode;
        public static string TrackerDeviceId;
        public static bool TrackerGenerate;
        public static bool TrackerVerify;
        public static bool TrackerInfo;
        public static bool? TrackerLostMode;
        public static bool TrackerHeartbeat;
        public static double? TrackerLat;
        public static double? TrackerLng;
        public static string TrackerSource;

        public static void Parse(string[] args)
        {
            if (args == null) return;
            foreach (string a in args)
            {
                if (a.StartsWith("--number=")) NumberOverride = a.Substring(9).Trim();
                else if (a.StartsWith("--relay=")) RelayOverride = a.Substring(8).Trim();
                else if (a.StartsWith("--send=")) SendSpec = a.Substring(7);
                else if (a.StartsWith("--home=")) HomeOverride = a.Substring(7).Trim();
                else if (a.StartsWith("--gui=")) GuiOverride = a.Substring(6).Trim();
                else if (a.StartsWith("--agent-timeout="))
                {
                    int ats;
                    if (int.TryParse(a.Substring(16), out ats) && ats > 0) AgentTimeoutSeconds = Math.Min(ats, 86400);
                }
                else if (a.StartsWith("--watch="))
                {
                    int ws;
                    if (int.TryParse(a.Substring(8), out ws) && ws > 0) WatchSeconds = Math.Min(ws, 3600);
                }
                else if (a.StartsWith("--linger="))
                {
                    int ls;
                    if (int.TryParse(a.Substring(9), out ls) && ls >= 0) LingerSeconds = Math.Min(ls, 600);
                }
                else if (a.StartsWith("--port="))
                {
                    int p;
                    if (int.TryParse(a.Substring(7), out p) && p > 0 && p < 65536) PortOverride = p;
                }
                else if (a == "--host") HostOverride = true;
                else if (a == "--no-host") HostOverride = false;
                else if (a == "--agent") Agent = true;
                else if (a == "--serve") Serve = true;
                else if (a.StartsWith("--serve-timeout="))
                {
                    int st;
                    if (int.TryParse(a.Substring(16), out st) && st > 0)
                    { ServeTimeoutSeconds = Math.Min(st, 86400); Serve = true; }
                }
                else if (a.StartsWith("--relay-peers=")) { PeersOverride = a.Substring(14).Trim(); Serve = true; }
                else if (a.StartsWith("--relay-policy=")) { PolicyOverride = a.Substring(15).Trim().ToLowerInvariant(); Serve = true; }
                else if (a.StartsWith("--relay-allow=")) { AllowOverride = a.Substring(14).Trim(); }
                else if (a.StartsWith("--relay-onion=")) { OnionOverride = a.Substring(14).Trim().ToLowerInvariant(); Serve = true; }
                else if (a == "--relay-carry-mail") { CarryMailOverride = true; Serve = true; }
                else if (a == "--relay-port-map") { PortMapOverride = true; Serve = true; }
                else if (a == "--relay-tls") { RelayTls = true; Serve = true; }
                else if (a == "--map-media-port") { MapMediaPort = true; }
                else if (a.StartsWith("--release-number=")) { ReleaseNumberOverride = a.Substring(17).Trim(); Serve = true; }
                else if (a.StartsWith("--call=")) { CallNumber = a.Substring(7).Trim(); }
                else if (a == "--video") { CallVideo = true; }
                else if (a == "--relay-media") { RelayMedia = true; }
                else if (a == "--answer") { AnswerMode = true; }
                else if (a == "--bootstrap") { BootstrapRelay = true; }
                else if (a.StartsWith("--tracker-url=")) { TrackerUrl = a.Substring(14).Trim(); }
                else if (a.StartsWith("--tracker-pair=")) { TrackerPairCode = a.Substring(15).Trim(); }
                else if (a.StartsWith("--tracker-device=")) { TrackerDeviceId = a.Substring(17).Trim(); }
                else if (a.StartsWith("--tracker-source=")) { TrackerSource = a.Substring(17).Trim(); }
                else if (a.StartsWith("--tracker-lat="))
                {
                    double d;
                    if (double.TryParse(a.Substring(14), NumberStyles.Float, CultureInfo.InvariantCulture, out d))
                        TrackerLat = d;
                }
                else if (a.StartsWith("--tracker-lng="))
                {
                    double d;
                    if (double.TryParse(a.Substring(14), NumberStyles.Float, CultureInfo.InvariantCulture, out d))
                        TrackerLng = d;
                }
                else if (a == "--tracker-generate") { TrackerGenerate = true; }
                else if (a == "--tracker-verify") { TrackerVerify = true; }
                else if (a == "--tracker-info") { TrackerInfo = true; }
                else if (a == "--tracker-heartbeat") { TrackerHeartbeat = true; }
                else if (a == "--tracker-lost-on") { TrackerLostMode = true; }
                else if (a == "--tracker-lost-off") { TrackerLostMode = false; }
            }
        }

        public static bool TrackerRequested
        {
            get
            {
                return TrackerGenerate || TrackerVerify || TrackerInfo || TrackerHeartbeat || TrackerLostMode.HasValue;
            }
        }

        public static bool HeadlessWanted
        {
            get
            {
                return Agent || Serve || SendSpec != null && SendSpec.Length > 0 || WatchSeconds > 0
                    // A call is only headless if somebody asked for one: --video and
                    // --answer on their own are modifiers, not a reason to run without
                    // a window - launching the app with --video must not swallow the
                    // GUI. Dialling is the trigger.
                    || CallNumber != null && CallNumber.Length > 0
                    || BootstrapRelay && (SendSpec == null || SendSpec.Length == 0) && WatchSeconds == 0
                    || TrackerRequested;
            }
        }
    }

    // ======================= Headless relay endpoint =======================
    // No window, no modem, no media ports: just the identity key, the sealing
    // and the relay socket. Two reasons it exists:
    //   - an always-on endpoint that does not need the GUI open (roadmap C1),
    //   - a chat line can be proven sealed to an outside observer, because the
    //     process can talk to a relay that is not our own code.
    public static class Headless
    {
        public static int Run()
        {
            AppConfig c = AppConfig.Load();
            c.EnsureIdentity();
            try { c.Save(); } catch { }
            string mine = (Cli.NumberOverride != null && Cli.NumberOverride.Length > 0)
                ? Cli.NumberOverride : c.virtual_number;
            string addr = Cli.RelayOverride != null ? Cli.RelayOverride : c.relay_server;
            if (string.IsNullOrEmpty(mine)) { Console.WriteLine("HEADLESS FAIL: no virtual number (--number=)"); return 2; }
            bool trackerOnly = Cli.TrackerRequested &&
                (Cli.SendSpec == null || Cli.SendSpec.Length == 0) &&
                Cli.WatchSeconds == 0 &&
                (Cli.CallNumber == null || Cli.CallNumber.Length == 0) &&
                !Cli.AnswerMode;
            if (trackerOnly)
            {
                bool ok = ExecuteTrackerActions(mine);
                return ok ? 0 : 5;
            }
            if (string.IsNullOrEmpty(addr) && !Cli.BootstrapRelay)
            { Console.WriteLine("HEADLESS FAIL: no relay (--relay=host:port), or --bootstrap to try relays.seed"); return 2; }

            VoipService v = new VoipService();
            v.MyNumber = mine;
            v.NumberToken = (c.number_token != null) ? c.number_token : "";
            // A headless call must be drivable over the relay as well as by the shortest
            // route, or "works where UDP is blocked" stays an assumption nobody tested.
            v.ForceRelayedMedia = Cli.RelayMedia;
            string dn = (c.display_name != null) ? c.display_name.Trim() : "";
            v.LocalName = dn.Length > 0 ? dn : Environment.MachineName;
            v.Log += delegate(string s) { Console.WriteLine("  log: " + s); };

            bool locked = false;
            v.ChatSecurity += delegate(string n, string state, string detail)
            {
                Console.WriteLine("  security #" + n + ": " + state +
                                  (string.IsNullOrEmpty(detail) ? "" : " (" + detail + ")"));
                if (state == "locked") locked = true;
            };
            string gotFrom = null, gotText = null;
            v.ChatReceived += delegate(string from, string text)
            {
                gotFrom = from; gotText = text;
                Console.WriteLine("  INBOUND chat from #" + from + ": " + text);
            };

            if (string.IsNullOrEmpty(addr))
            {
                Say("BOOTSTRAP no relay given - checking relays.seed (" + VoipService.SeedPath + ")");
                if (!v.TryBootstrapRelay())
                {
                    Say("BOOTSTRAP FAIL: no entry answered as itself. Nothing was registered anywhere.");
                    v.DisableRelay();
                    return 4;
                }
                addr = v.BootstrappedFrom;
            }
            else v.EnableRelay(addr);
            DateTime ready = DateTime.Now.AddSeconds(20);
            while (DateTime.Now < ready && !v.RelayReady) Thread.Sleep(200);
            Console.WriteLine("HEADLESS number=" + mine + " identity=" +
                              (v.SecIdentity != null ? v.SecIdentity.Fingerprint : "none") +
                              " relay=" + addr + " connected=" + v.RelayReady +
                              " relay_trust=" + (v.Relay == null ? "n/a" : v.Relay.RelayTrust) +
                              " relay_key=" + (v.Relay == null || string.IsNullOrEmpty(v.Relay.RelayFingerprint) ? "none" : v.Relay.RelayFingerprint));
            if (!v.RelayReady) { v.DisableRelay(); return 3; }
            if (Cli.TrackerRequested)
                ExecuteTrackerActions(mine);

            bool sent = false;
            string to = "";
            if (Cli.SendSpec != null && Cli.SendSpec.Length > 0)
            {
                int bar = Cli.SendSpec.IndexOf('|');
                to = bar < 0 ? Cli.SendSpec : Cli.SendSpec.Substring(0, bar);
                string body = bar < 0 ? "" : Cli.SendSpec.Substring(bar + 1);
                Console.WriteLine("SEND to #" + to + ": " + body);
                sent = v.SendChat(to, body);
                Console.WriteLine("SendChat -> " + sent + " (true = handed to a sealed or pending session)");
            }

            // ---- a call with no window: --call=<number> [--video], --answer opposite ----
            // The chat path has been drivable from a command line for a while; the call
            // path was not, which meant "does a call work between two laptops" could only
            // be answered by two laptops and two people. This makes it a test, and makes
            // the answer visible in one line.
            // The peer number comes from the call itself (VoipService publishes it), so
            // the report names who was actually connected rather than who happened to
            // send a chat line during the same window.
            v.IncomingCall += delegate(string who, bool isVideo)
            {
                Console.WriteLine("CALL incoming from " + who + (isVideo ? " (video)" : " (voice)") +
                    (Cli.AnswerMode ? " - answering (--answer)" : " - leaving it ringing (no --answer)"));
                if (!Cli.AnswerMode) return;
                try { v.AcceptIncomingCall(); }
                catch (Exception ex) { Console.WriteLine("CALL answer failed: " + ex.Message); }
            };
            bool dialling = Cli.CallNumber != null && Cli.CallNumber.Length > 0;
            bool callMode = dialling || Cli.AnswerMode;
            if (callMode)
            {
                // The media socket and the signaling listener the window normally
                // starts with. A headless call without them completes over signaling
                // and moves not one frame - the exact kind of pass that proves nothing,
                // so the whole stack comes up here rather than the call being faked.
                try { v.Start(); }
                catch (Exception ex) { Console.WriteLine("CALL could not start the voip stack: " + ex.Message); }
                // A caller on a home network is the machine that needs the UDP forward:
                // without one, the public address it announces is a port nobody reaches.
                // Asked before dialling, so the address is already known when the peer
                // announces its own and picks a target.
                if (Cli.MapMediaPort)
                {
                    Console.WriteLine("MAP MEDIA asking this machine's router for a UDP forward to the media port");
                    bool mapped = false;
                    try { mapped = v.MapMediaPort(); } catch (Exception ex) { Console.WriteLine("MAP MEDIA failed: " + ex.Message); }
                    Console.WriteLine("MAP MEDIA result=" + (mapped ? "forwarded" : "not forwarded") +
                                      " announce=" + (v.MyMappedMediaEp == null ? "none" : v.MyMappedMediaEp.ToString()));
                }
                // A second instance on the same PC cannot bind the signaling port; it
                // says so in the log and carries on, which is the existing behaviour.
                Console.WriteLine("CALL stack media_port=" + v.Media.LocalPort + " media_open=" + v.Media.IsOpen);
            }
            if (dialling)
            {
                Console.WriteLine("CALL dialling #" + Cli.CallNumber + (Cli.CallVideo ? " (video)" : " (voice)"));
                try
                {
                    if (!v.StartCallByNumber(Cli.CallNumber, Cli.CallVideo))
                        Console.WriteLine("CALL refused before it started (no relay, or already in a call)");
                }
                catch (Exception ex) { Console.WriteLine("CALL start error: " + ex.Message); }
            }

            if (callMode)
            {
                int cs = Cli.WatchSeconds > 0 ? Cli.WatchSeconds : 20;
                // A synthetic 20 ms tone rather than a microphone: what is being proved
                // is that encrypted frames cross the wire between two machines, and a
                // test box may have no capture device at all. Whether the audio SOUNDS
                // correct is a different question and is not claimed here - the report
                // line says so, because a green test that lies is worse than no test.
                byte[] tone = new byte[640];
                for (int i = 0; i < tone.Length; i += 2) { tone[i] = 0x40; tone[i + 1] = 0x08; }
                // For a video call, a frame drawn here rather than captured: a video
                // call that only proved signaling would leave the actual question -
                // do pictures cross, encrypted - unanswered. Chunked exactly the way
                // the camera path chunks (1200 B, the receiver's 128-chunk limit),
                // because a test that invents its own framing tests nothing.
                byte[] jpeg = null;
                if (Cli.CallVideo)
                {
                    try
                    {
                        using (System.Drawing.Bitmap bmp = new System.Drawing.Bitmap(96, 64))
                        using (System.Drawing.Graphics g = System.Drawing.Graphics.FromImage(bmp))
                        using (System.Drawing.SolidBrush br = new System.Drawing.SolidBrush(System.Drawing.Color.Orange))
                        using (System.IO.MemoryStream ms = new System.IO.MemoryStream())
                        {
                            g.Clear(System.Drawing.Color.FromArgb(0x20, 0x60, 0xa0));
                            g.FillRectangle(br, 6, 6, 44, 26);
                            g.FillEllipse(br, 56, 20, 30, 30);
                            bmp.Save(ms, System.Drawing.Imaging.ImageFormat.Jpeg);
                            jpeg = ms.ToArray();
                        }
                    }
                    catch (Exception ex) { Console.WriteLine("CALL could not build a test frame: " + ex.Message); }
                }
                int vfid = 0;
                DateTime nextVideo = DateTime.MinValue;
                // The answerer usually outlives the caller's window: by the time it
                // finishes watching, the call is over, InCall is false and the peer is
                // forgotten. Reporting only the end state made a call that had worked
                // perfectly look like it never happened - so whatever the call proved
                // while it was up is captured here, once, and the report says both.
                bool established = false;
                bool everEncrypted = false;
                string everVerified = "", snapPeer = "", snapSafety = "", everRoute = "none",
                    everPair = "none";
                long everTx = 0, everRx = 0;
                DateTime stop = DateTime.Now.AddSeconds(cs);
                while (DateTime.Now < stop)
                {
                    if (v.InCall)
                    {
                        try { v.Media.SendAudio(tone); } catch { }
                        if (jpeg != null && DateTime.Now >= nextVideo)
                        {
                            nextVideo = DateTime.Now.AddMilliseconds(200);
                            const int CHUNK = 1200;
                            int count = (jpeg.Length + CHUNK - 1) / CHUNK;
                            if (count >= 1 && count <= 128)
                            {
                                vfid = (vfid + 1) & 0x7FFF;
                                for (int i = 0; i < count; i++)
                                {
                                    int off = i * CHUNK;
                                    int n = Math.Min(CHUNK, jpeg.Length - off);
                                    byte[] part = new byte[n];
                                    Buffer.BlockCopy(jpeg, off, part, 0, n);
                                    v.Media.SendVideo(part, vfid, i, count);
                                }
                            }
                        }
                    }
                    if (!established && v.InCall && v.Media.HasKey)
                    {
                        established = true;
                        everEncrypted = true;
                        everVerified = v.CallVerified;
                        everTx = v.Media.TxFrames; everRx = v.Media.RxFrames;
                        snapPeer = v.CallPeerNumber ?? "";
                        if (snapPeer.Length > 0)
                        {
                            try { snapSafety = v.SafetyNumberFor(snapPeer) ?? ""; } catch { snapSafety = ""; }
                        }
                        Console.WriteLine("CALL established peer=" + (snapPeer.Length > 0 ? snapPeer : "?") +
                            " verified=" + everVerified +
                            " safety=" + (string.IsNullOrEmpty(snapSafety) ? "none" : snapSafety));
                    }
                    else if (established)
                    {
                        if (v.Media.HasKey) everEncrypted = true;
                        if (v.Media.TxFrames > everTx) everTx = v.Media.TxFrames;
                        if (v.Media.RxFrames > everRx) everRx = v.Media.RxFrames;
                        if (v.CallVerified == "yes") everVerified = "yes";
                        // Keep the last named route we saw, so a call that went direct and
                        // then fell back is still reported as having been direct at some
                        // point rather than as never having tried.
                        string rNow = v.Route;
                        if (rNow != "none") everRoute = rNow;
                        // The receipt outlives the socket for the same reason the route
                        // does. This report is printed after the call has been torn down,
                        // and a call that proved both ways and then hung up was being
                        // described by the state of the moment AFTER it: a relayed video
                        // call came out as route=relay beside pair=none, which reads as a
                        // contradiction rather than as a report taken too late.
                        string pNow = v.RouteProved;
                        if (pNow != "none") everPair = pNow;
                    }
                    Thread.Sleep(20);
                }
                bool enc = v.Media.HasKey || everEncrypted;
                string peerNum = !string.IsNullOrEmpty(v.CallPeerNumber) ? v.CallPeerNumber : snapPeer;
                string verified = v.CallVerified == "yes" || everVerified == "yes" ? "yes" :
                    (v.CallVerified == "pending" ? everVerified : v.CallVerified);
                string sn = peerNum.Length > 0 ? v.SafetyNumberFor(peerNum) : null;
                if (string.IsNullOrEmpty(sn)) sn = snapSafety;
                bool incallNow = v.InCall || established;
                // Which of the peer's announced addresses actually delivered the frames.
                // "direct" on its own was never enough: a route a router forwarded and a
                // route that happened to be open look identical to the people on the call
                // and are completely different machines to debug.
                string mediaRoute = v.Route;
                if (mediaRoute == "none") mediaRoute = everRoute;
                // The address that sent real media, not merely a datagram: a keep-alive
                // needs no key, so on the old reading this line could name a source that
                // had never carried a frame of the call.
                string mediaFrom = v.Media.LastRxAuthRemote == null ? "-" : v.Media.LastRxAuthRemote.ToString();
                // And whether our half ever arrived at all, proved by a receipt the peer
                // signed with the call key. Reported separately from the route because they
                // are different claims: the route names where their audio came from, this
                // says the peer decrypted ours.
                string mediaPair = v.RouteProved;
                if (mediaPair == "none") mediaPair = everPair;
                string routeLine = "";
                foreach (string row in v.Routes.Describe()) routeLine += "[" + row + "] ";
                Console.WriteLine("ROUTES " + routeLine.Trim());
                // verified= is the one that matters: encrypted= says a key exists,
                // verified= says the far end proved whose key it is.
                Console.WriteLine("CALL state incall=" + incallNow + " video=" + v.VideoCall +
                    " encrypted=" + enc + " verified=" + verified +
                    " path=" + (v.Media.RelayActive ? "relayed" : "direct") +
                    " route=" + mediaRoute + " pair=" + mediaPair + " from=" + mediaFrom +
                    " tx_frames=" + v.Media.TxFrames + " rx_frames=" + v.Media.RxFrames +
                    " rx_bytes=" + v.Media.RxBytes +
                    " peer=" + (peerNum.Length > 0 ? peerNum : "?") +
                    " safety=" + (string.IsNullOrEmpty(sn) ? "none" : sn));
                bool ok = incallNow && enc && verified == "yes" &&
                    v.Media.TxFrames > 0 && v.Media.RxFrames > 0;
                Console.WriteLine("CALL RESULT=" + (ok ? "connected-encrypted-verified" : "incomplete") +
                    " (frames left and arrived through the AES-CTR path, and the far end" +
                    " proved its identity key; audio quality is not asserted by this -" +
                    " that needs two people and two speakers)");
                v.DisableRelay();
                return ok ? 0 : 1;
            }

            int secs = Cli.WatchSeconds > 0 ? Cli.WatchSeconds : Cli.LingerSeconds;
            DateTime until = DateTime.Now.AddSeconds(secs);
            while (DateTime.Now < until)
            {
                Thread.Sleep(250);
                if (Cli.WatchSeconds > 0 && gotText != null) break;
                // Only leave immediately when nobody asked to keep listening.
                // "--send --watch=60" used to fall straight out of here the moment
                // the send was accepted, so the reply could never arrive - the
                // one thing a command-line conversation would expect to do.
                if (Cli.WatchSeconds == 0 && Cli.SendSpec != null && sent && locked) break;
            }

            string via = "";
            foreach (string row in v.Routes.Describe()) via += "[" + row + "] ";
            Console.WriteLine("ROUTES " + via.Trim());
            Console.WriteLine("RESULT sent=" + sent + " sealedSession=" + (locked ? "locked" : "not established") +
                              " inbound=" + (gotText == null ? "none" : "from #" + gotFrom + ": " + gotText));
            v.DisableRelay();
            return (Cli.SendSpec == null || Cli.SendSpec.Length == 0) || sent ? 0 : 1;
        }

        // ---- C1: the always-awake listener ----
        //
        // Runs with no window at all: the GUI spends tens of seconds building
        // its visual tree before it can register, and holding a WPF tree alive
        // for days is the wrong shape for a background endpoint. The agent owns
        // the relay slot and the identity key and does only what is possible
        // headless: decrypt, store, wake the real app. It then gives the slot
        // up, so the window re-registers with the same number token and the
        // relay replaces one session with the other - never two half-sessions.
        // Every line the listener prints also lands in wake_agent.log in the
        // profile. When the window starts it there is no console attached at all,
        // so without this file neither a person nor a test can tell whether the
        // listener ever took the slot or why it gave it back. It stays bounded by
        // rewriting the tail, because an always-on process must not grow a log
        // until the disk is full.
        private static readonly object SayLock = new object();
        private static void Say(string s)
        {
            Console.WriteLine(s);
            try
            {
                string p = Path.Combine(Home.Dir, "wake_agent.log");
                lock (SayLock)
                {
                    try
                    {
                        if (File.Exists(p) && new FileInfo(p).Length > 200000)
                        {
                            string[] all = File.ReadAllLines(p);
                            if (all.Length > 400)
                            {
                                string[] tail = new string[400];
                                Array.Copy(all, all.Length - 400, tail, 0, 400);
                                File.WriteAllLines(p, tail);
                            }
                        }
                        File.AppendAllText(p, DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss") + " " + s + Environment.NewLine);
                    }
                    catch { }
                }
            }
            catch { }
        }

        // ---- A relay node with no window ----
        //
        // The node everybody registers with should not need a logged-in desktop
        // and a live WPF visual tree. This starts the same CallServer the GUI
        // starts, with the same federation policy from the profile (overridable
        // on the command line), prints a status line so a person or a test can
        // watch links and directories converge, and stays up until killed or
        // until --serve-timeout expires.
        public static int RunRelay()
        {
            AppConfig c = AppConfig.Load();
            c.EnsureIdentity();
            try { c.Save(); } catch { }
            int port = Cli.PortOverride > 0 ? Cli.PortOverride : CallServer.DEFAULT_PORT;

            CallServer s = new CallServer();
            s.RelayName = string.IsNullOrEmpty(c.display_name) ? Environment.MachineName : c.display_name.Trim();
            string pol = Cli.PolicyOverride != null && Cli.PolicyOverride.Length > 0
                ? Cli.PolicyOverride : (c.relay_policy ?? "allowed");
            if (pol != "nobody" && pol != "everyone") pol = "allowed";
            s.RelayPolicy = pol;
            s.RelayAllow = Cli.AllowOverride != null ? Cli.AllowOverride : (c.relay_allow ?? "");
            s.RelayLinks = Cli.PeersOverride != null && Cli.PeersOverride.Length > 0
                ? Cli.PeersOverride : (c.relay_peers ?? "");
            s.RelayAdvertise = c.relay_advertise ?? "";
            s.RelayStoreKb = c.relay_store_kb > 0 ? c.relay_store_kb : 2048;
            s.RelayBandwidthKbps = c.relay_bandwidth_kbps > 0 ? c.relay_bandwidth_kbps : 0;
            s.RelayAutoMesh = c.relay_automesh;
            s.RelayOnion = CallServer.NormalizeOnion(
                Cli.OnionOverride != null && Cli.OnionOverride.Length > 0 ? Cli.OnionOverride : c.relay_onion);
            s.RelayCarryMail = Cli.CarryMailOverride || c.relay_carry_mail;
            s.RelayPortMap = Cli.PortMapOverride || c.relay_port_map;
            s.Log += delegate(string m) { Say("srv: " + m); };

            // The one escape from a lease that has to exist, because a lockout would
            // be worse than the hole the lease closes: an install that legitimately
            // lost its number_token needs a way back that is not "find and edit a file
            // you were never told about". Then carry on serving, so this does not need
            // a second command and a port dance.
            if (!string.IsNullOrEmpty(Cli.ReleaseNumberOverride))
                Say("RELAY RELEASING " + Cli.ReleaseNumberOverride +
                    (s.ReleaseLease(Cli.ReleaseNumberOverride) ? " (lease removed)" : " (no lease on file)"));

            bool useTls = Cli.RelayTls || c.relay_tls;
            if (!s.Start(port, useTls))
            {
                Say("RELAY FAIL: could not start on port " + port +
                    (useTls ? " with TLS (check relay_tls.pfx, its password, and the port)" :
                     " (in use, or not permitted)"));
                return 3;
            }
            Say("RELAY UP port=" + port + " id=" + s.RelayId + " policy=" + pol +
                " transport=" + (s.UseTls ? "tls12" : "tcp") +
                " links=" + (s.RelayLinks.Length > 0 ? s.RelayLinks : "none") +
                " automesh=" + (s.RelayAutoMesh ? "on" : "off") + " store_kb=" + s.RelayStoreKb +
                " onion=" + s.RelayOnion + " carry_mail=" + (s.RelayCarryMail ? "on" : "off"));

            // The line somebody pastes into their relays.seed. It comes from the relay
            // because the fingerprint cannot be copied from anywhere else, and it is
            // printed with the catch attached: a relay behind a router advertising a
            // LAN address is a seed entry that only works for people already on that
            // network, which is the one thing a shared list gets wrong silently.
            //
            // Asking the router is the only way to fix that without buying a server, so
            // it happens here - on request only - and its outcome is printed as a fact
            // about the network rather than as a success message. A relay that could not
            // open a port is still a relay for anyone who can reach it.
            if (s.RelayPortMap)
            {
                string pip, why;
                string local = VoipService.GetLocalIp() == null ? "127.0.0.1" : VoipService.GetLocalIp().ToString();
                bool opened = PortMap.TryApply(port, local, out pip, out why);
                Say("PORT MAP " + (opened ? "UP: " : "no: ") + why);
                if (opened && pip.Length > 0) s.PublicAddress = pip + ":" + port;
            }

            if (s.MayLink())
            {
                Identity rk = s.RelayKey;
                Say("SEED LINE " + s.AdvertiseAddress() + "|" +
                    (rk == null ? "-" : rk.Fingerprint) + "|added " +
                    DateTime.Now.ToString("yyyy-MM-dd", System.Globalization.CultureInfo.InvariantCulture));
                Say("SEED NOTE paste it into <profile>\\relays.seed on the other machine. It" +
                    (s.PublicAddress.Length > 0
                        ? " carries the address the router reports, so it should be reachable from"
                          + " outside this network already. "
                        : " only helps them reach you if " + s.AdvertiseAddress() + " is reachable"
                          + " from outside this network (forward TCP " + port + ", or start this"
                          + " relay with --relay-port-map on a network whose router answers UPnP). ") +
                    "They should compare the fingerprint against this screen before trusting it.");
            }

            // A status line every 10 s. Without it a node looks identical whether
            // it has one link or none, and "is the mesh actually forming" stops
            // being a question anyone can answer from the outside.
            DateTime until = Cli.ServeTimeoutSeconds > 0
                ? DateTime.Now.AddSeconds(Cli.ServeTimeoutSeconds) : DateTime.MaxValue;
            int tick = 0;
            while (DateTime.Now < until)
            {
                Thread.Sleep(1000);
                if (++tick % 10 != 0) continue;
                Say("RELAY STATUS links=" + s.LinkCount + " remote_peers=" + s.RemotePeerCount +
                    " carried_kb=" + (s.QueuedBytesForPeers / 1024) +
                    " onion=" + s.OnionBuilt + "/" + s.OnionCarried + "/" + s.OnionRefused +
                    " mail=" + s.QueuedMailCount + " held_for_me=" + s.MailReceived +
                    // Room joins waiting on a route, and joins that were held and
                    // then landed: a mesh that is merely slow looks exactly like one
                    // that is broken unless somebody can count them.
                    " joins_waiting=" + s.PendingJoinCount + " joins_held=" + s.JoinsParked +
                    "/" + s.JoinsReplayed +
                    // Calls carried between relays are invisible to the two endpoints,
                    // which is precisely why a mesh claim needs a number on it.
                    " media_fwd=" + s.MediaForwarded + " media_del=" + s.MediaDelivered +
                    // Same reason: whether callers were dialling off a cold cache is a
                    // fact about timing, and a fact about timing needs counting.
                    " who_asked=" + s.WhoAsked +
                    // Asked and answered are counted apart, so "the caller timed out" can
                    // be told apart from "the relay never replied" - the two look
                    // identical from the caller's log and point at different machines.
                    " who_answered=" + s.WhoAnswered +
                    // Directory pushes sent, so "the notifier coalesces bursts" can be
                    // read off a line instead of taken on faith.
                    " peers_pushed=" + s.PeerBroadcasts);
            }
            Say("RELAY STOPPING (" + (Cli.ServeTimeoutSeconds > 0 ? "timeout reached" : "signalled") + ")");
            try { s.Stop(); } catch { }
            return 0;
        }

        private static bool ExecuteTrackerActions(string defaultDevice)
        {
            if (!Cli.TrackerRequested) return true;
            if (!TrackerBridge.IsSafeServerUrl(Cli.TrackerUrl))
            {
                Console.WriteLine("TRACKER FAIL: pass --tracker-url=https://host[:port]");
                return false;
            }
            AppConfig trackerConfig = AppConfig.Load();
            string device = !string.IsNullOrEmpty(Cli.TrackerDeviceId) ? Cli.TrackerDeviceId :
                (!string.IsNullOrEmpty(trackerConfig.tracker_device_id) ? trackerConfig.tracker_device_id : defaultDevice);
            string src = !string.IsNullOrEmpty(Cli.TrackerSource) ? Cli.TrackerSource : "ussd-app";
            string trackerToken = "";
            bool needsTrackerCredential = Cli.TrackerInfo || Cli.TrackerHeartbeat || Cli.TrackerLostMode.HasValue;
            if (needsTrackerCredential)
            {
                try { trackerToken = TrackerBridge.UnprotectDeviceToken(trackerConfig.tracker_token_protected); }
                catch (Exception ex)
                {
                    Console.WriteLine("TRACKER FAIL: could not unlock saved device credential: " + ex.Message);
                    return false;
                }
            }
            TrackerBridge tr = new TrackerBridge(Cli.TrackerUrl, trackerToken);
            bool ok = true;

            if (Cli.TrackerGenerate)
            {
                TrackerBridge.Reply r = tr.GeneratePair();
                Console.WriteLine("TRACKER generate: " + (r.Ok ? "ok" : "fail") + " status=" + r.StatusCode);
                if (!string.IsNullOrEmpty(r.Body)) Console.WriteLine("TRACKER body: " + TrackerBridge.RedactDeviceToken(r.Body));
                if (r.Ok)
                {
                    try { SaveTrackerCredentials(trackerConfig, r); }
                    catch (Exception ex) { Console.WriteLine("TRACKER credential save failed: " + ex.Message); ok = false; }
                    if (ok && needsTrackerCredential)
                    {
                        try
                        {
                            trackerToken = TrackerBridge.UnprotectDeviceToken(trackerConfig.tracker_token_protected);
                            tr = new TrackerBridge(Cli.TrackerUrl, trackerToken);
                        }
                        catch (Exception ex) { Console.WriteLine("TRACKER credential unlock failed: " + ex.Message); ok = false; }
                    }
                }
                if (!r.Ok) ok = false;
            }
            if (Cli.TrackerVerify)
            {
                if (string.IsNullOrEmpty(Cli.TrackerPairCode))
                {
                    Console.WriteLine("TRACKER FAIL: --tracker-verify needs --tracker-pair=<code>");
                    ok = false;
                }
                else
                {
                    TrackerBridge.Reply r = tr.VerifyPair(Cli.TrackerPairCode);
                    Console.WriteLine("TRACKER verify: " + (r.Ok ? "ok" : "fail") + " status=" + r.StatusCode);
                    if (!string.IsNullOrEmpty(r.Body)) Console.WriteLine("TRACKER body: " + TrackerBridge.RedactDeviceToken(r.Body));
                    if (r.Ok)
                    {
                        try { SaveTrackerCredentials(trackerConfig, r); }
                        catch (Exception ex) { Console.WriteLine("TRACKER credential save failed: " + ex.Message); ok = false; }
                        if (ok && needsTrackerCredential)
                        {
                            try
                            {
                                trackerToken = TrackerBridge.UnprotectDeviceToken(trackerConfig.tracker_token_protected);
                                tr = new TrackerBridge(Cli.TrackerUrl, trackerToken);
                            }
                            catch (Exception ex) { Console.WriteLine("TRACKER credential unlock failed: " + ex.Message); ok = false; }
                        }
                    }
                    if (!r.Ok) ok = false;
                }
            }
            if (Cli.TrackerInfo)
            {
                if (string.IsNullOrEmpty(device) || string.IsNullOrEmpty(trackerToken))
                {
                    Console.WriteLine("TRACKER FAIL: --tracker-info needs a paired device credential");
                    ok = false;
                }
                else
                {
                    TrackerBridge.Reply r = tr.PairInfo(device);
                    Console.WriteLine("TRACKER info: " + (r.Ok ? "ok" : "fail") + " status=" + r.StatusCode);
                    if (!string.IsNullOrEmpty(r.Body)) Console.WriteLine("TRACKER body: " + TrackerBridge.RedactDeviceToken(r.Body));
                    if (!r.Ok) ok = false;
                }
            }
            if (Cli.TrackerHeartbeat)
            {
                TrackerBridge.Reply r = tr.Heartbeat(device, Cli.TrackerLat, Cli.TrackerLng, src);
                Console.WriteLine("TRACKER heartbeat: " + (r.Ok ? "ok" : "fail") + " status=" + r.StatusCode);
                if (!string.IsNullOrEmpty(r.Body)) Console.WriteLine("TRACKER body: " + TrackerBridge.RedactDeviceToken(r.Body));
                if (!r.Ok) ok = false;
            }
            if (Cli.TrackerLostMode.HasValue)
            {
                TrackerBridge.Reply r = tr.LostMode(device, Cli.TrackerLostMode.Value);
                Console.WriteLine("TRACKER lost-mode " + (Cli.TrackerLostMode.Value ? "on" : "off") +
                                  ": " + (r.Ok ? "ok" : "fail") + " status=" + r.StatusCode);
                if (!string.IsNullOrEmpty(r.Body)) Console.WriteLine("TRACKER body: " + TrackerBridge.RedactDeviceToken(r.Body));
                if (!r.Ok) ok = false;
            }
            return ok;
        }

        private static void SaveTrackerCredentials(AppConfig config, TrackerBridge.Reply reply)
        {
            string device = TrackerBridge.ReadJsonString(reply.Body, "deviceId");
            string token = TrackerBridge.ReadJsonString(reply.Body, "deviceToken");
            if (device.Length == 0 || token.Length == 0)
                throw new InvalidDataException("Tracker pairing response did not contain device credentials.");
            config.tracker_device_id = device;
            config.tracker_token_protected = TrackerBridge.ProtectDeviceToken(token);
            config.tracker_pair_code = "";
            config.tracker_server = Cli.TrackerUrl;
            config.Save();
        }

        public static int RunAgent()
        {
            AppConfig c = AppConfig.Load();
            c.EnsureIdentity();
            try { c.Save(); } catch { }
            string mine = (Cli.NumberOverride != null && Cli.NumberOverride.Length > 0)
                ? Cli.NumberOverride : c.virtual_number;
            string addr = Cli.RelayOverride != null ? Cli.RelayOverride : c.relay_server;
            if (string.IsNullOrEmpty(mine)) { Say("AGENT FAIL: no virtual number (--number=)"); return 2; }
            if (string.IsNullOrEmpty(addr)) { Say("AGENT FAIL: no relay (--relay=host:port)"); return 2; }
            string gui = FindGui();
            if (gui == null)
            { Say("AGENT FAIL: no window exe to wake (use --gui=<path>)"); return 4; }

            VoipService v = new VoipService();
            v.MyNumber = mine;
            v.NumberToken = (c.number_token != null) ? c.number_token : "";
            string dn = (c.display_name != null) ? c.display_name.Trim() : "";
            v.LocalName = dn.Length > 0 ? dn : Environment.MachineName;
            v.Log += delegate(string s) { Say("log: " + s); };

            bool woken = false;
            string reason = "";
            // The relay closes this socket when the same number token registers
            // elsewhere - which is exactly what happens when the user opens the
            // window. RelayClient would reconnect after 5 s and register again,
            // kicking the window in turn, so the agent treats that close as its
            // own dismissal instead of starting a fight over one slot.
            bool displaced = false;
            v.Log += delegate(string s)
            {
                if (s != null && s.IndexOf("server closed connection", StringComparison.Ordinal) >= 0)
                    displaced = true;
            };
            v.ChatReceived += delegate(string from, string text)
            {
                // Store first, then wake: a window that crashes on the way up
                // must still find the message on disk next time.
                WakeInbox.Save(Home.Dir, from, text);
                PendingNotice.Record(Home.Dir, "chat", from, v.ChatSecurityState(from));
                Say("AGENT stored a chat from #" + from + " ("
                                  + WakeInbox.Count(Home.Dir) + " pending), waking the window");
                reason = "chat from #" + from;
                woken = true;
            };
            v.IncomingCall += delegate(string name, bool video)
            {
                // A ringing call cannot be rendered headlessly, and audio has no
                // meaning without the UI, so the honest move is only to wake.
                PendingNotice.Record(Home.Dir, "call", name, video ? "video" : "audio");
                Say("AGENT saw an incoming " + (video ? "video" : "audio") +
                                  " call from " + name + "; waking the window to answer it");
                reason = "call from " + name;
                woken = true;
            };

            v.EnableRelay(addr);
            DateTime ready = DateTime.Now.AddSeconds(20);
            while (DateTime.Now < ready && !v.RelayReady) Thread.Sleep(200);
            Say("AGENT number=" + mine + " identity=" +
                              (v.SecIdentity != null ? v.SecIdentity.Fingerprint : "none") +
                              " relay=" + addr + " connected=" + v.RelayReady +
                              " home=" + Home.Dir.TrimEnd('\\') +
                              " pending=" + WakeInbox.Count(Home.Dir) +
                              " wake=" + Path.GetFileName(gui));
            if (!v.RelayReady) { Say("AGENT stop: the relay refused or dropped the registration"); v.DisableRelay(); return 3; }

            string stopReason = null;
            DateTime until = Cli.AgentTimeoutSeconds > 0
                ? DateTime.Now.AddSeconds(Cli.AgentTimeoutSeconds) : DateTime.MaxValue;
            int beats = 0;
            // A dropped relay is not a reason to quit: RelayClient retries every
            // 5 s and an offline interval must not cost the user their messages.
            // Only being handed over the slot (displaced) or storing something
            // ends the wait.
            while (stopReason == null && DateTime.Now < until)
            {
                if (woken) stopReason = "stored " + reason;
                else if (displaced) stopReason = "the relay gave this number to the window - standing down instead of taking the slot back";
                else
                {
                    Thread.Sleep(500);
                    if (++beats % 24 == 0)
                        Say("AGENT alive: listening, pending=" + WakeInbox.Count(Home.Dir) +
                                          " connected=" + v.RelayReady);
                }
            }
            if (stopReason == null) stopReason = "timed out after " + Cli.AgentTimeoutSeconds + " s with nothing stored";
            Say("AGENT stop: " + stopReason);
            if (!woken)
            {
                v.DisableRelay();
                return displaced ? 0 : 6;
            }

            // Release before starting, so the window's REG is the one the relay
            // keeps, and so no two processes can append the peer book at once.
            v.DisableRelay();
            Thread.Sleep(300);
            try
            {
                ProcessStartInfo psi = new ProcessStartInfo(gui);
                psi.Arguments = "--home=\"" + Home.Dir.TrimEnd('\\', '/') +
                                "\" --number=" + mine + " --relay=" + addr;
                psi.WorkingDirectory = Path.GetDirectoryName(gui);
                psi.UseShellExecute = false;
                Process.Start(psi);
                Say("AGENT woke the window (" + reason + "), exiting");
            }
            catch (Exception ex)
            {
                Say("AGENT could not start the window: " + ex.Message +
                                  " - the message stays in wake_inbox");
                return 5;
            }
            return 0;
        }

        // Where the window lives: an explicit --gui= wins, then the folder the
        // agent exe sits in, then the data home, then the module path. A build
        // that renames the agent still wakes the app it shipped beside.
        private static string FindGui()
        {
            if (!string.IsNullOrEmpty(Cli.GuiOverride))
            {
                try
                {
                    string g = Path.GetFullPath(Cli.GuiOverride);
                    return File.Exists(g) ? g : null;
                }
                catch { return null; }
            }
            string self = null;
            try { self = Process.GetCurrentProcess().MainModule.FileName; } catch { }
            List<string> dirs = new List<string>();
            dirs.Add(AppDomain.CurrentDomain.BaseDirectory);
            dirs.Add(Home.Dir);
            if (self != null) { try { dirs.Add(Path.GetDirectoryName(self)); } catch { } }
            foreach (string d in dirs)
            {
                if (string.IsNullOrEmpty(d)) continue;
                string p = Path.Combine(d, "UssdApp.exe");
                if (File.Exists(p)) { try { return Path.GetFullPath(p); } catch { return p; } }
            }
            return null;
        }
    }

    // ======================= Main window =======================
    public class MainWindow : Window
    {
        // Theme aliases: every one of these IS a shared Theme token instance, so a
        // theme switch mutates the color and all referencing elements repaint live.
        public static readonly Brush BrushBg = Theme.Bg;
        public static readonly Brush BrushPanel = Theme.Panel;
        public static readonly Brush BrushFg = Theme.Text;
        public static readonly Brush BrushAccent = Theme.Accent;
        public static readonly Brush BrushSuccess = Theme.Success;
        public static readonly Brush BrushError = Theme.Error;
        public static readonly Brush BrushWarn = Theme.Warn;
        public static readonly Brush BrushGray = Theme.Gray;
        public static readonly Brush BrushBorder = Theme.CardBorder;
        public static readonly Brush BrushGreen = Theme.Green;
        public static readonly Brush BrushRed = Theme.Red;

        private enum CallState { Idle, Dialing, Ringing, Active }

        private readonly ModemService _modem = new ModemService();
        private readonly List<Contact> _contacts = new List<Contact>();
        private readonly List<SmsMessage> _inbox = new List<SmsMessage>();
        private readonly List<SmsCode> _codes = new List<SmsCode>();

        private CallState _call = CallState.Idle;
        private string _peer = "";
        private DateTime _callStart;
        private string _prevIccid;
        private bool _opsRunning;
        private int _opsCount;
        private bool _clccRunning;
        private bool _busy;

        // call history (Recents) + transition bookkeeping for recording
        private readonly List<CallRec> _callHistory = new List<CallRec>();
        private CallState _callPrev = CallState.Idle;
        private string _callDir = "out";        // "out" | "in" (SIM call direction)
        private bool _callAnswered;             // incoming call was picked up
        private bool _voipRecActive;            // a VoIP call record is in flight
        private string _voipRecNumber = "";
        private string _voipRecDir = "out";
        private string _voipRecKind = "voip";
        private DateTime _voipRecStart;
        // dialer Keypad/Recents panes
        private StackPanel _keypadPane, _recentsPane;
        private Button _tabKeypad, _tabRecents;
        private StackPanel _recentsPanel;
        private TextBlock _recentsEmpty;

        // connection bar
        private ComboBox _comboPort, _comboBaud;
        private Button _btnConnect;
        private CheckBox _chkAuto;
        private TextBlock _status, _sigText, _simSummary, _simPillText;
        private TextBlock _sbPort, _sbCarrier, _sbMethod;
        private CheckBox _chkAutoScroll;

        // dialer
        private TextBox _txtNumber;
        private TextBlock _callStateText, _callTimerText, _clipText, _dtmfEcho;
        private Button _btnAnswer, _btnDecline;

        // in-call audio overlay (covers the dialer while a call is live)
        private Grid _callOverlay;
        private Border _avatarBorder;
        private System.Windows.Shapes.Ellipse _avatarRing;
        private TextBlock _ovPeer, _ovState, _ovTimer;
        private Button _ovBtnMute, _ovBtnKeypad, _ovBtnEnd, _ovBtnAnswer, _ovBtnDecline;
        private bool _ovKeypadOpen;
        private bool _voipRinging;              // an incoming VoIP call is pending
        private DateTime _voipStart = DateTime.MinValue;   // VoIP call connected at
        private bool _voipE2E;                             // one-shot: E2E setup (reset/record) done
        private readonly AudioFilter _audioFilter = new AudioFilter();
        private CallRecorder _recorder;
        private Transcriber _transcriber;
        private TextBlock _subsText;              // live subtitles on the video stage
        private readonly List<string> _subsLines = new List<string>();
        private CheckBox _chkNoiseFilter, _chkRecordCalls, _chkAlwaysAwake;
        private ListView _lvRoutes;
        private CheckBox _chkCarryPeers;
        private bool _suppressCarryToggle;
        private static readonly byte[] Silence640 = new byte[640];

        // voip
        private VoipService _voip;
        private CallServer _callServer;      // embedded internet call server (host mode)
        private TextBox _txtRelay;           // relay server address host:port
        private CheckBox _chkHostCalls;      // host the call server on this PC
        private CheckBox _chkRelayMedia;     // force a call's media onto the relay
        private CheckBox _chkPortMap;        // ask the router to forward the relay port
        private TextBlock _relayTrustText;   // which key the relay in front of us showed
        private TextBox _txtMyNumber;        // this device's virtual number
        private VoipAudio _voipAudio;
        private ListView _lvPeers;
        private TextBox _txtVoipIp;
        private Button _btnVoipVoice, _btnVoipVideo, _btnVoipHangup;
        private TextBlock _voipStateText;
        private Window _videoWin;
        // Zoom-style video stage extras
        private ColumnDefinition _sideCol;
        private Grid _sideHost;
        private int[] _sideHostTag;
        private int _sideTab;
        private StackPanel _vidIdle;
        private Button _vidIdleButton, _btnSideChat, _btnSideNotes, _btnSideToggle;
        private System.Windows.Shapes.Ellipse _vidIdleAvatar;
        private UIElement _stageTag;
        private bool _shareRun, _camWasOn;
        private Thread _shareThread;
        private Image _imgRemote, _imgLocal;
        private Border _tileRemote, _tileLocal;
        private TextBlock _tileRemoteName, _tileLocalName;
        // Group call: one tile per member in a UniformGrid over the stage.
        private Border _confHost, _pipHost;
        private UniformGrid _confTiles;
        private TextBlock _confTag;
        private Button _btnAddParticipant;
        private readonly Dictionary<string, TextBlock> _confTileNames = new Dictionary<string, TextBlock>();
        private readonly Dictionary<string, Image> _confTileImgs = new Dictionary<string, Image>();
        private readonly Dictionary<string, Border> _confTileBorders = new Dictionary<string, Border>();
        private int _confVideoTick;      // rate limit for room thumbnails
        private string _confRoomHost;    // who opened the room we joined
        private Button _btnMuteMic;
        private bool _micMuted;
        private string _voipPeerName;
        private System.Diagnostics.Process _camProc;
        private volatile bool _camRun;
        private int _camFrameId;

        // animations
        private System.Windows.Shapes.Ellipse _liveDot;
        private DispatcherTimer _ussdTypeTimer;
        private string _ussdTypeTarget = "";
        private int _ussdTypeIdx;

        // contacts
        private ListView _lvContacts;
        // split-view detail panel + favorites filter for the Contacts page
        private string _contactFilter = "All";
        private TextBlock _ctDetailTitle, _ctDetailNum, _ctDetailSrc, _ctDetailFav;
        private Button _ctBtnFav, _ctBtnCall, _ctBtnSms, _ctBtnDel, _ctBtnVideo;
        private TextBox _txtCName, _txtCNum;

        // sms
        private TextBox _txtSmsTo, _txtSmsBody;
        private ListView _lvInbox, _lvCodes;
        // chat (relay peer chat with SMS fallback)
        private TextBox _txtChatTo, _txtChatInput;
        private TextBlock _chatPartner;
        private ListBox _lvChatRecent;                 // recent conversations
        private string _chatOpenNum = "";              // number of the open conversation
        private string _lastBubbleDate = "";           // day-separator dedupe
        private System.Windows.Threading.DispatcherTimer _chatTypTimer;   // outbound typing pulses
        private System.Windows.Threading.DispatcherTimer _peerTypTimer;   // inbound typing label expiry
        private bool _peerTyping;
        private TextBox _txtChatSearch;                                   // filter the open conversation
        private string _chatFilter = "";
        private readonly Dictionary<string, int> _chatUnread = new Dictionary<string, int>();
        // voice notes: mic frames accumulate here while recording
        private bool _vnRecording;
        private readonly List<byte[]> _vnBuf = new List<byte[]>();
        private readonly object _vnLock = new object();
        private System.Windows.Threading.DispatcherTimer _vnTimer;
        private Button _btnVoiceNote;
        // Header chip that reports the end-to-end state of the open chat.
        private Button _secChip;
        // A3: the details live inside the chat pane. A modal dialog was the wrong
        // tool three times over - it froze the chat behind it, no UI test could
        // reach it, and on a replaced peer key it was the only place the warning
        // ever appeared, so dismissing it silently lost the MITM signal.
        private Grid _secSheet;
        private TextBlock _secSheetHead, _secSheetState, _secSheetMine, _secSheetPeer, _secSheetSn, _secSheetNote;
        private TextBlock _hubSecDigest;
        private Button _secSheetTrust;
        private string _secSheetNum = "";
        private string _secSheetSnValue = "";
        private int _vnSecs;
        private const int VN_MAX_SECS = 30;
        private ScrollViewer _chatScroll;
        private StackPanel _chatPanel;
        private bool _chatStickBottom = true;   // auto-scroll while user is at the bottom
        private DateTime _voipMediaRetryAt = DateTime.MinValue;
        private int _voipMediaOpening;           // 0/1 interlocked guard for OpenVoipMedia
        private readonly List<ChatMsg> _chatMsgs = new List<ChatMsg>();   // open conversation

        // ── 3-Pane Chat Hub ──────────────────────────────────────────────────
        // Pane 1 category, Pane 2 list, Pane 3 active workspace.
        // Workspace transitions: "chat" | "voice" | "video" | "otp"
        private string _chatHubCategory = "peers";  // "peers" | "sms" | "codes"
        private string _chatWorkspace   = "chat";   // "chat" | "voice" | "video" | "otp"
        private Button _hubBtnPeers, _hubBtnSms, _hubBtnCodes;
        private StackPanel _hubPane2;
        private ColumnDefinition _hubPane2Col;
        private ColumnDefinition _hubPane2DivCol;
        private bool _hubPane2Visible = true;
        private Button _hubPane2Toggle;
        private Grid _hubPane3Chat, _hubPane3Voice, _hubPane3Video, _hubPane3Otp;
        private TextBlock _hubPane3ContactName, _hubPane3ContactMeta;
        private TextBlock _hubCallTimer, _hubCallState;
        private TextBlock _hubUnreadPeers, _hubUnreadSms, _hubUnreadCodes;
        private TextBlock _hubCharCount;            // live char count near input
        private StackPanel _hubEmojiPicker;
        private bool _hubEmojiOpen = false;
        private TextBlock _hubOtpCode, _hubOtpFrom, _hubOtpExpiry;
        private int _hubOtpSecsLeft;
        private DispatcherTimer _hubOtpTimer;
        // chat background customisation
        private SolidColorBrush _chatBgBrush;
        private string _chatBgImagePath = "";
        // AI assistant
        private string _aiApiKey = "";
        private string _aiModel = "gpt-4o-mini";
        private string _aiEndpoint = "https://api.openai.com/v1/chat/completions";
        private bool _aiEnabled = false;

        // sim
        private TextBlock _valPin, _valIccid, _valImsi, _valImei, _valOp, _valSig,
        _valReg, _valBatt, _valPhonebook, _valSimType, _valCarrier, _valSlot;

        // ussd
        private RadioButton _radioMifi, _radioSerial;
        private GroupBox _panelMifi;
        private string _mifiProbe = null;          // cached MifiApi.Probe() result
        private DateTime _mifiProbeTime = DateTime.MinValue;
        private TextBox _txtMifiIp, _txtCode;
        private ComboBox _comboCarrier;
        private TextBox _txtUssdResp, _txtUssdReply;
        private WrapPanel _ussdChips;
        private ListView _lvUssdHistory;
        private readonly List<UssdSession> _ussdSessions = new List<UssdSession>();
        private string _lastUssdCode = null;
        private bool _ussdSessionActive = false;
        private string _simCarrierKey = null;   // "MTN" / "Telecel" / "AirtelTigo" / "Glo"

        // log
        private RichTextBox _logBox;

        // navigation (sidebar + pages)
        private Border _sidebar;
        private ColumnDefinition _sidebarCol;
        private Grid _contentHost;
        private FrameworkElement _sidebarHeading;
        private FrameworkElement _sidebarFooter;
        private readonly System.Collections.Generic.List<FrameworkElement> _pages = new System.Collections.Generic.List<FrameworkElement>();
        private readonly System.Collections.Generic.List<string> _pageNames = new System.Collections.Generic.List<string>();
        private readonly System.Collections.Generic.List<string> _pageIcons = new System.Collections.Generic.List<string>();
        private readonly System.Collections.Generic.List<string> _pageLabels = new System.Collections.Generic.List<string>();
        private readonly System.Collections.Generic.List<string> _pageDescriptions = new System.Collections.Generic.List<string>();
        private readonly System.Collections.Generic.List<TextBlock> _navSectionLabels = new System.Collections.Generic.List<TextBlock>();
        private TextBlock _shellPageTitle;
        private TextBlock _shellPageDescription;
        private RowDefinition _logRow;
        private Grid _dialerGrid;
        private Grid _smsGrid;
        private Grid _videoGrid;
        private bool _stacked;
        private readonly System.Collections.Generic.List<Button> _navButtons = new System.Collections.Generic.List<Button>();
        private int _pageIndex;
        private bool _sidebarOpen = true;
        private bool _sidebarIconOnly = false;  // narrow: icons only (40px)
        private Button _btnMenu;
        private TextBlock _pillCom;        // header "COM6 | 115200"
        private Button _btnLogToggle;      // status bar: collapse/expand live log
        private bool _logCollapsed;
        private TextBlock _logBadge;       // unread-error counter on log toggle button
        private int _logUnread;            // count of log lines written while log is collapsed
        // transport mode for the dialer: "cellular" | "voip"
        private string _dialerTransport = "cellular";
        private Button _btnTransportCellular, _btnTransportVoip;
        private TextBox _agentPrompt, _agentResponse;
        private TextBlock _agentStatus;
        private Button _agentAskButton;
        private StackPanel _agentTranscript;
        private ScrollViewer _agentChatScroll;
        private TextBox _trackerServerBox, _trackerPairBox, _trackerDeviceBox, _trackerOutput;
        private TextBlock _trackerStatus;
        private StackPanel _trackerMapLinks;
        private Canvas _trackerMapCanvas;
        private TextBlock _trackerMapHint;
        private List<Tuple<string, double, double>> _trackerMapPoints;
        private readonly List<Button> _trackerActionButtons = new List<Button>();
        private bool _trackerBusy;
        private TextBlock _appsStatus;
        private string _laptopTrackerExe;
        private Process _laptopTrackerProcess;
        private TrackerWindowHost _laptopTrackerHost;
        private string _callsCompanionExe;
        private Process _callsCompanionProcess;
        private System.Speech.Synthesis.SpeechSynthesizer _agentSpeech;
        private CheckBox _agentSpeakReplies;
        private string _agentLastResponse = "";
        // modem setup popover (shown when user clicks COM pill)
        private System.Windows.Controls.Primitives.Popup _modemPopup;
        // video conference page (was: separate popup window)
        private TextBlock _videoStateText;
        private ListBox _lvMoments;        // Key Moments / agenda feed
        private ListBox _lvVideoChat;      // in-call group chat
        private TextBox _txtVideoChat;
        private Button _btnCamToggle;
        private Button _btnShare;

        // timers
        private DispatcherTimer _tickTimer;
        private DispatcherTimer _opsTimer;
        private DispatcherTimer _clccTimer;

        // ── System Tray ───────────────────────────────────────────────────
        private System.Windows.Forms.NotifyIcon _trayIcon;
        private bool _trayMinimized = false;

        // ── Network quality ───────────────────────────────────────────────
        private int _tickCount;
        private System.Windows.Shapes.Ellipse _netQualityDot;   // in header bar
        private TextBlock _netQualityText;

        // ── Nav badges ────────────────────────────────────────────────────
        // Overlaid on each nav button (unread counts, activity indicators)
        private readonly Dictionary<int, TextBlock> _navBadges = new Dictionary<int, TextBlock>();
        private int _totalUnread = 0;       // true = closed to tray not exiting

        // ── Offline message queue ─────────────────────────────────────────
        // Messages that failed to deliver are stored here and flushed when
        // the peer reconnects or the relay comes back online.
        private readonly List<OutboxMsg> _outbox = new List<OutboxMsg>();
        private DispatcherTimer _outboxFlushTimer;

        // ── Read receipts ─────────────────────────────────────────────────
        // msgId → bubble border for upgrading gray ticks to blue ticks
        private readonly Dictionary<string, Border> _pendingReadReceipt = new Dictionary<string, Border>();

        // ── Presence / status ─────────────────────────────────────────────
        private string _myPresence = "available";  // available|busy|dnd|away|incall
        private string _myStatusText = "";
        private readonly Dictionary<string, string> _peerPresence = new Dictionary<string, string>();
        private DispatcherTimer _presenceBroadcastTimer;
        private Button _btnPresence;               // status button in header

        // ── Message reply ─────────────────────────────────────────────────
        private ChatMsg _replyToMsg;               // message being replied to
        private Border _replyPreview;              // preview bar shown above input

        // ── AT retry queue ────────────────────────────────────────────────
        private readonly List<AtRetryItem> _atRetryQueue = new List<AtRetryItem>();
        private DispatcherTimer _atRetryTimer;

        private static Brush Hex(string s)
        {
            return new SolidColorBrush((Color)ColorConverter.ConvertFromString(s));
        }

        public MainWindow()
        {
            Title = "USSD Manager Pro";
            MinWidth = 920;
            MinHeight = 640;
            try
            {
                Rect wa = SystemParameters.WorkArea;
                Width = Math.Max(MinWidth, Math.Min(1180, wa.Width - 24));
                Height = Math.Max(MinHeight, Math.Min(840, wa.Height - 24));
                MaxWidth = Math.Max(MinWidth, wa.Width);
                MaxHeight = Math.Max(MinHeight, wa.Height);
            }
            catch
            {
                Width = 1180;
                Height = 840;
            }
            Background = BrushBg;
            FontFamily = new FontFamily("Segoe UI");
            FontSize = 12;
            WindowStartupLocation = WindowStartupLocation.CenterScreen;
            try
            {
                string icoPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "UssdApp.ico");
                if (!File.Exists(icoPath)) icoPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "..", "Python", "ussd.ico");
                if (File.Exists(icoPath)) Icon = new BitmapImage(new Uri(icoPath, UriKind.Absolute));
            }
            catch { }
            Boot.Mark("ctor: start");
            // Design system first: control styles + theme tokens must be in
            // Application.Resources before any UI is constructed.
            Theme.Init(Application.Current);

            BuildUi();
            _contentHost.SizeChanged += delegate { ApplyResponsiveLayout(); };
            SizeChanged += delegate { ApplyLogHeight(); VerifyDialerLayout(); };
            Boot.Mark("ctor: BuildUi done");
            LoadState();
            LoadContacts();
            RefreshContactsView();
            LoadCallHistory();
            RefreshRecentsView();
            Boot.Mark("ctor: LoadState done");
            RefreshPorts();
            Boot.Mark("ctor: RefreshPorts done");
            WireTimers();
            Boot.Mark("ctor: WireTimers done");
            _modem.LineReceived += OnModemLine;
            _modem.UrcReceived += OnModemUrc;
            _modem.ConnectionLost += OnModemLost;

            // Pre-generate the identity key on a background thread so the relay
            // connection path does not block on RSA-2048 keygen. A fresh install
            // used to stall for a few hundred ms on its first WHO lookup because
            // keygen ran on the connecting thread. Starting it here means the key
            // is ready by the time the relay connects.
            try
            {
                if (_voip != null) _voip.PreGenerateIdentity(Home.Dir);
                else
                {
                    // VoipService not created yet — pre-generate directly
                    string keyPath = Path.Combine(Home.Dir, "identity.key");
                    if (!File.Exists(keyPath))
                    {
                        Thread kt = new Thread((ThreadStart)delegate
                        {
                            try { Identity pre = new Identity(keyPath); }
                            catch { }
                        });
                        kt.IsBackground = true;
                        kt.Name = "UssdKeygen";
                        kt.Start();
                    }
                }
            }
            catch { }

            StartVoip();
            Boot.Mark("ctor: StartVoip done");

            // ── Advanced feature initialization ──────────────────────────
            InitTrayIcon();          // system tray agent
            LoadOutbox();            // offline message queue
            StartOutboxTimer();      // retry queued messages every 15 s
            StartPresenceBroadcast(); // broadcast presence every 60 s
            StartAtRetryTimer();     // AT command retry queue
            Boot.Mark("ctor: tray+outbox+timers done");
            // Add presence button to the header
            AddPresenceButtonToHeader();
            // Add network quality dot to the status bar
            AddNetworkQualityToStatusBar();
            Boot.Mark("ctor: end");
            // C1: anything the wake agent caught while this window was closed is
            // replayed once the UI can actually take it, not during construction.
            Dispatcher.BeginInvoke((Action)delegate { ReplayWakeInbox(); },
                System.Windows.Threading.DispatcherPriority.ContextIdle);
        }

        // The wake agent cannot render anything, so it stored what arrived and
        // started this exe. Replaying through ChatInbound keeps one single path
        // for inbound text: same log line, same chat store, same unread badge.
        // Take() consumes each file, so a restart cannot show it twice.
        private void ReplayWakeInbox()
        {
            try
            {
                List<string[]> rows = WakeInbox.Take(Home.Dir);
                List<string[]> notices = PendingNotice.ReadAll(Home.Dir);
                int missed = 0;
                foreach (string[] n in notices)
                {
                    if (n.Length < 3 || n[1] != "call") continue;
                    missed++;
                    Log("Wake agent: " + (n.Length >= 4 ? n[3] + " " : "") +
                        "call from " + n[2] + " arrived while the window was closed (" + n[0] + ")", BrushWarn);
                }
                if (rows.Count > 0)
                {
                    Log("Wake agent handed off " + rows.Count +
                        " message(s) received while the window was closed", BrushSuccess);
                    foreach (string[] r in rows)
                    {
                        if (string.IsNullOrEmpty(r[0])) continue;
                        Hang.Trace("chat: wake replay from #" + r[0]);
                        ChatInbound(r[0], r[1]);
                    }
                }
                if (missed > 0 || rows.Count > 0) PendingNotice.Clear(Home.Dir);
            }
            catch (Exception ex) { Log("Wake replay failed: " + ex.Message, BrushWarn); }
        }

        // ---------- First-run onboarding ----------
        // A non-blocking welcome overlay shown once on first run. Three things a
        // first-timer needs to know: their number, that a relay reaches people off
        // the network, and that a SIM is optional. Not a modal: a dismissable card
        // that floats over the log so the app is usable immediately.
        private void ShowFirstRunWelcome(string number)
        {
            try
            {
                Border card = new Border
                {
                    Background = new SolidColorBrush(Color.FromRgb(0x1a, 0x1d, 0x28)),
                    BorderBrush = BrushAccent,
                    BorderThickness = new Thickness(2),
                    CornerRadius = new CornerRadius(12),
                    Padding = new Thickness(24),
                    Margin = new Thickness(20),
                    MaxWidth = 460,
                    HorizontalAlignment = HorizontalAlignment.Center,
                    VerticalAlignment = VerticalAlignment.Center,
                    Effect = Application.Current.TryFindResource("PillShadow") as System.Windows.Media.Effects.Effect
                };
                StackPanel sp = new StackPanel();

                TextBlock title = new TextBlock
                {
                    Text = "\uD83D\uDCF1 Your number is ready",
                    FontSize = 18, FontWeight = FontWeights.SemiBold,
                    Foreground = new SolidColorBrush(Color.FromRgb(0xe2, 0xe8, 0xf0)),
                    Margin = new Thickness(0, 0, 0, 12),
                    TextWrapping = TextWrapping.Wrap
                };
                sp.Children.Add(title);

                TextBlock numLabel = new TextBlock
                {
                    Text = "This is YOUR app number, on this device:",
                    Foreground = new SolidColorBrush(Color.FromRgb(0x94, 0xa3, 0xb8)),
                    FontSize = 12,
                    Margin = new Thickness(0, 0, 0, 4),
                    TextWrapping = TextWrapping.Wrap
                };
                sp.Children.Add(numLabel);

                // The number, large and copyable
                Border numBox = new Border
                {
                    Background = new SolidColorBrush(Color.FromRgb(0x0f, 0x17, 0x2a)),
                    CornerRadius = new CornerRadius(8),
                    Padding = new Thickness(12, 8, 12, 8),
                    Margin = new Thickness(0, 0, 0, 12)
                };
                TextBlock numText = new TextBlock
                {
                    Text = number,
                    FontSize = 22, FontWeight = FontWeights.Bold,
                    Foreground = new SolidColorBrush(Color.FromRgb(0x4f, 0x8c, 0xff)),
                    HorizontalAlignment = HorizontalAlignment.Center
                };
                numBox.Child = numText;
                sp.Children.Add(numBox);

                Button copyBtn = MakeButton("Copy number");
                copyBtn.Margin = new Thickness(0, 0, 0, 12);
                copyBtn.Click += delegate
                {
                    try { Clipboard.SetText(number); Log("Number copied to clipboard.", BrushGray); } catch { }
                };
                sp.Children.Add(copyBtn);

                // "Host relay + share" — the zero-friction path for two mates
                Button hostBtn = MakeButton("\uD83D\uDD17  Host relay & copy invite for your mate");
                hostBtn.Margin = new Thickness(0, 0, 0, 8);
                hostBtn.Click += delegate
                {
                    try
                    {
                        // Enable host mode
                        if (_chkHostCalls != null) _chkHostCalls.IsChecked = true;
                        ApplyCallSettings();
                        SaveStateSafe();

                        // Wait a moment for the relay to start
                        System.Windows.Threading.DispatcherTimer t =
                            new System.Windows.Threading.DispatcherTimer { Interval = TimeSpan.FromSeconds(1.5) };
                        t.Tick += delegate
                        {
                            t.Stop();
                            // Generate and copy the connection card
                            string seedLine = (_callServer != null)
                                ? (_callServer.AdvertiseAddress() + "|" + (_voip != null ? (_voip.MyFingerprint ?? "-") : "-"))
                                : "";
                            string fp = _voip != null ? _voip.MyFingerprint : "";
                            string connCard = ConnectionHelper.MakeConnectCard(number, seedLine, fp);
                            try { Clipboard.SetText(connCard); } catch { }
                            Log("Connection card copied! Send it to your mate (paste in chat/email/WhatsApp).", BrushSuccess);
                            if (seedLine.Length > 0)
                                Log("SEED LINE for relays.seed:  " + seedLine, BrushAccent);
                            // Open firewall
                            try { ConnectionHelper.EnsureFirewallRule(CallServer.DEFAULT_PORT); } catch { }
                        };
                        t.Start();
                    }
                    catch (Exception ex) { Log("Host: " + ex.Message, BrushError); }
                };
                sp.Children.Add(hostBtn);

                TextBlock relayInfo = new TextBlock
                {
                    Text = "To reach anyone off this network, you need a relay. Paste a "
                         + "friend's SEED LINE (in Settings), or host one yourself.",
                    Foreground = new SolidColorBrush(Color.FromRgb(0x94, 0xa3, 0xb8)),
                    FontSize = 12,
                    Margin = new Thickness(0, 0, 0, 12),
                    TextWrapping = TextWrapping.Wrap
                };
                sp.Children.Add(relayInfo);

                TextBlock simInfo = new TextBlock
                {
                    Text = "A SIM is optional — all calling, chat and video work without one.",
                    Foreground = new SolidColorBrush(Color.FromRgb(0x94, 0xa3, 0xb8)),
                    FontSize = 12,
                    Margin = new Thickness(0, 0, 0, 16),
                    TextWrapping = TextWrapping.Wrap
                };
                sp.Children.Add(simInfo);

                // Paste seed line from mate
                TextBlock pasteLabel = new TextBlock
                {
                    Text = "Got a seed line from your mate? Paste it here:",
                    Foreground = new SolidColorBrush(Color.FromRgb(0x94, 0xa3, 0xb8)),
                    FontSize = 12,
                    Margin = new Thickness(0, 0, 0, 4),
                    TextWrapping = TextWrapping.Wrap
                };
                sp.Children.Add(pasteLabel);

                TextBox seedBox = new TextBox
                {
                    Background = new SolidColorBrush(Color.FromRgb(0x0f, 0x17, 0x2a)),
                    Foreground = new SolidColorBrush(Color.FromRgb(0xe2, 0xe8, 0xf0)),
                    BorderBrush = new SolidColorBrush(Color.FromRgb(0x4f, 0x8c, 0xff)),
                    BorderThickness = new Thickness(1),
                    Padding = new Thickness(8, 6, 8, 6),
                    FontSize = 11,
                    Margin = new Thickness(0, 0, 0, 8),
                    TextWrapping = TextWrapping.NoWrap
                };
                sp.Children.Add(seedBox);

                Button connectBtn = MakeButton("Connect via seed line");
                connectBtn.Margin = new Thickness(0, 0, 0, 16);
                connectBtn.Click += delegate
                {
                    string line = (seedBox.Text ?? "").Trim();
                    if (line.Length == 0) return;
                    try
                    {
                        // Write to relays.seed and trigger bootstrap
                        string seedPath = VoipService.SeedPath;
                        File.AppendAllText(seedPath, "\n" + line + "\n");
                        Log("Seed line saved. Connecting...", BrushGray);
                        ApplyCallSettings();
                        SaveStateSafe();
                    }
                    catch (Exception ex) { Log("Seed paste: " + ex.Message, BrushError); }
                };
                sp.Children.Add(connectBtn);

                Button gotIt = MakeButton("Got it");
                gotIt.Click += delegate
                {
                    try
                    {
                        if (_contentHost != null && _contentHost.Children.Contains(card))
                            _contentHost.Children.Remove(card);
                    }
                    catch { }
                };
                sp.Children.Add(gotIt);

                card.Child = sp;
                // Show over whatever page is currently visible
                if (_contentHost != null)
                {
                    Grid.SetRowSpan(card, 10);
                    Grid.SetColumnSpan(card, 10);
                    Panel.SetZIndex(card, 1000);
                    _contentHost.Children.Add(card);
                }
            }
            catch (Exception ex) { Log("Welcome overlay: " + ex.Message, BrushGray); }
        }

        // ---------- Identity key recovery ----------
        // When identity.key is lost or corrupt, the user is locked out of their
        // number until the operator runs --release-number. This provides an
        // in-app path: generate a new key, explain the consequences, and tell
        // the user what to ask the relay operator to do.
        private void ShowIdentityRecovery()
        {
            try
            {
                string num = AppNum.Format(_myNumber ?? "");
                string fp = _voip != null ? (_voip.MyFingerprint ?? "") : "";

                Window dlg = new Window
                {
                    Title = "Reset Identity Key",
                    Width = 460, Height = 380,
                    WindowStartupLocation = WindowStartupLocation.CenterOwner,
                    Owner = this,
                    ResizeMode = ResizeMode.NoResize,
                    Background = BrushBg
                };
                StackPanel sp = new StackPanel { Margin = new Thickness(20) };

                TextBlock head = new TextBlock
                {
                    Text = "Reset Identity Key",
                    FontSize = 16, FontWeight = FontWeights.SemiBold,
                    Foreground = BrushFg, Margin = new Thickness(0, 0, 0, 12),
                    TextWrapping = TextWrapping.Wrap
                };
                sp.Children.Add(head);

                TextBlock body = new TextBlock
                {
                    Text = "Your identity key is what proves your number belongs to you. "
                         + "If you lost it (new install, corrupt file), you cannot register "
                         + "as the owner of " + num + " until the old key is released.\n\n"
                         + "Generating a new key:\n"
                         + "  - Gives you a new fingerprint\n"
                         + "  - Does NOT change your number\n"
                         + "  - Means the relay operator must run "
                         + "--release-number=" + (_myNumber ?? "") + " first\n\n"
                         + "Current fingerprint: " + (fp.Length > 0 ? fp : "(none)"),
                    Foreground = BrushFg, FontSize = 12,
                    TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 0, 0, 16)
                };
                sp.Children.Add(body);

                Button genBtn = MakeButton("Generate new identity key");
                genBtn.Margin = new Thickness(0, 0, 0, 8);
                genBtn.Click += delegate
                {
                    try
                    {
                        string keyPath = Path.Combine(Home.Dir, "identity.key");
                        // Delete the old key
                        if (File.Exists(keyPath)) File.Delete(keyPath);
                        // Generate a new one (on a background thread to avoid UI stall)
                        Thread kt = new Thread((ThreadStart)delegate
                        {
                            try
                            {
                                Identity fresh = new Identity(keyPath);
                                Dispatcher.BeginInvoke((Action)delegate
                                {
                                    Log("Identity key reset. New fingerprint: " + fresh.Fingerprint, BrushSuccess);
                                    Log("Ask your relay operator to run --release-number="
                                        + (_myNumber ?? "") + " before you reconnect.", BrushWarn);
                                    Toast.Show("Identity reset",
                                        "New fingerprint: " + fresh.Fingerprint
                                        + "\nAsk the relay operator to release your number.", null);
                                    dlg.Close();
                                });
                            }
                            catch (Exception ex)
                            {
                                Dispatcher.BeginInvoke((Action)delegate
                                {
                                    Log("Identity reset failed: " + ex.Message, BrushError);
                                });
                            }
                        });
                        kt.IsBackground = true;
                        kt.Name = "UssdKeyReset";
                        kt.Start();
                    }
                    catch (Exception ex) { Log("Identity reset: " + ex.Message, BrushError); }
                };
                sp.Children.Add(genBtn);

                Button closeBtn = MakeButton("Cancel");
                closeBtn.Click += delegate { dlg.Close(); };
                sp.Children.Add(closeBtn);

                dlg.Content = sp;
                dlg.ShowDialog();
            }
            catch (Exception ex) { Log("Identity recovery: " + ex.Message, BrushGray); }
        }

        // ---------- VoIP wiring ----------
        private void StartVoip()
        {
            try
            {
                _voip = new VoipService();
                _voip.MyNumber = _myNumber ?? "";
                // Show our configured display name to peers (falls back to the
                // machine name); carried in INVITE/ACCEPT for the caller list,
                // history and incoming-call overlays.
                string dn = (_cfg != null && _cfg.display_name != null) ? _cfg.display_name.Trim() : "";
                _voip.LocalName = dn.Length > 0 ? dn : Environment.MachineName;
                _voip.NumberToken = (_cfg != null && _cfg.number_token != null) ? _cfg.number_token : "";
                _voipAudio = new VoipAudio();
                _voip.Log += delegate(string s) { Log("VoIP: " + s, BrushGray); };
                // The relay's identity verdict, kept on screen. Raised from the relay
                // client's thread, so it is marshalled like every other VoIP callback.
                _voip.RelayTrustChanged += delegate(string verdict)
                {
                    Dispatcher.BeginInvoke((Action)delegate { UpdateRelayTrustChip(); });
                };
                _voip.PeerListChanged += delegate(VoipPeer p) { Dispatcher.BeginInvoke((Action)delegate { RefreshPeerList(); }); };
                _voip.IncomingCall += delegate(string name, bool video) { Dispatcher.BeginInvoke((Action)delegate { OnVoipIncoming(name, video); }); };
                _voip.CallStateChanged += delegate(string s) { Dispatcher.BeginInvoke((Action)delegate
                {
                    // outgoing ring plays a ringback loop; every other state
                    // (accepted, rejected, failed, ended) silences the ring.
                    if (s != null && (s.IndexOf("Connecting to", StringComparison.Ordinal) >= 0
                        || s.IndexOf("Calling #", StringComparison.Ordinal) >= 0
                        || s.IndexOf("Ringing on remote", StringComparison.Ordinal) >= 0))
                        ToneSynth.StartRing();
                    else
                        ToneSynth.StopRing();
                    if (_voipStateText != null) _voipStateText.Text = s;
                    // start the call clock the moment the call is connected
                    if (s != null && s.IndexOf("E2E", StringComparison.Ordinal) >= 0 && !_voipE2E)
                    {
                        _voipE2E = true;
                        _voipStart = DateTime.Now;
                        _audioFilter.Reset();
                        StartRecordingIfNeeded();
                        StartTranscriberIfNeeded();
                        ClearSubtitles();
                    }
                    // Offline fallback: if the callee was unreachable send a
                    // chat notification so they see the missed call when they
                    // next open the app (or receive it as a relay push).
                    if (s != null && (s.IndexOf("unreachable", StringComparison.OrdinalIgnoreCase) >= 0
                                   || s.IndexOf("not found", StringComparison.OrdinalIgnoreCase) >= 0
                                   || s.IndexOf("rejected", StringComparison.OrdinalIgnoreCase) >= 0
                                   || s.IndexOf("timed out", StringComparison.OrdinalIgnoreCase) >= 0))
                    {
                        // Best-effort: send a peer chat notification as missed-call record
                        string peerNum = _voipPeerName ?? "";
                        if (peerNum.Length >= 3 && _voip != null)
                        {
                            string missedMsg = "\uD83D\uDCF5 Missed call from " + AppNum.Format(_myNumber) + " (" + DateTime.Now.ToString("HH:mm") + ") — tap to call back";
                            try { _voip.SendChat(peerNum, missedMsg); } catch { }
                            Log("Offline fallback: missed-call notice sent to #" + peerNum, BrushWarn);
                        }
                        // Show hub workspace back to chat after failed call
                        HubShowWorkspace("chat");
                    }
                    ApplyVoipBreath(s); UpdateVoipButtons(); UpdateCallOverlay();
                }); };
                _voip.CallEnded += delegate { Dispatcher.BeginInvoke((Action)delegate
                {
                    ToneSynth.StopRing();
                    _voipRinging = false;
                    _voipStart = DateTime.MinValue;
                    _voipE2E = false;
                    if (_ovTimer != null) _ovTimer.Text = "00:00";
                    StopRecording();
                    StopTranscriber();
                    ClearSubtitles();
                    RecordVoipCallEnd(); StopVoipMedia(); UpdateVoipButtons(); UpdateCallOverlay();
                }); };
                _voip.RemoteVideoFrame += delegate(byte[] jpeg) { Dispatcher.BeginInvoke((Action)delegate { ShowRemoteFrame(jpeg); }); };
                // ── Group call signals ────────────────────────────────────
                _voip.ConferenceRosterChanged += delegate(string rid, List<string> mem) { OnConferenceRoster(mem); };
                _voip.ConferenceTalkLevels += delegate(string rid, Dictionary<string, int> lv) { OnConferenceTalk(lv); };
                _voip.ConferenceVideo += delegate(string rid, string from, byte[] jpeg) { OnConferenceVideo(from, jpeg); };
                _voip.ConferenceInviteReceived += delegate(string rid, string hn, string hname) { OnConferenceInvite(rid, hn, hname); };
                // A join the relay could not complete even after waiting. Said out
                // loud because the alternative is a silent empty room: the member
                // sees "in call", the others never see them, and nobody knows.
                _voip.ConferenceRefused += delegate(string rid)
                {
                    Dispatcher.BeginInvoke((Action)delegate
                    {
                        Log("Group call: " + rid + " was not reachable - your relay never found a route to whoever opened it. Both sides need a relay that is linked, or the same relay.", BrushWarn);
                        Toast.Show("Could not join the call", "That group call is not reachable from your relay", null);
                    });
                };
                _voip.StickerLine += delegate(string f, string l) { HandleStickerLine(f, l); };
                _voip.RelayDiscovered += delegate(string addr)
                {
                    Dispatcher.BeginInvoke((Action)delegate { NoteFoundRelay(addr, "heard on the local network"); });
                };
                _voip.RelayReferral += delegate(string list)
                {
                    Dispatcher.BeginInvoke((Action)delegate
                    {
                        foreach (string e in (list ?? "").Split(new char[] { ',', ';' }, StringSplitOptions.RemoveEmptyEntries))
                            NoteFoundRelay(e, "referred by the relay I use");
                    });
                };
                // A named serial port is the opt-in; nothing here opens one that
                // the user did not ask for.
                TryAttachRadio();
                _voip.DtmfReceived += delegate(string d) { Dispatcher.BeginInvoke((Action)delegate { ToneSynth.PlayDtmf(d); }); };
                _voip.ChatReceived += delegate(string f, string t) { Dispatcher.BeginInvoke((Action)delegate { Hang.Trace("chat: relay in from #" + f); ChatInbound(f, t); }); };
                // ── Advanced signal handlers ──────────────────────────────
                _voip.ChatReadReceived += delegate(string f, long ts) { Dispatcher.BeginInvoke((Action)delegate { ChatMarkDelivered(f); }); };
                _voip.ReactionReceived += delegate(string f, string mid, string em) { Dispatcher.BeginInvoke((Action)delegate { HandleReactionReceived(f, mid, em); }); };
                _voip.FileOfferReceived += delegate(string f, string tid, string nm, long sz, string key, string hash) { Dispatcher.BeginInvoke((Action)delegate { HandleFileOffer(f, tid, nm, sz, key, hash); }); };
                _voip.FileAcceptReceived += delegate(string f, string tid, int port) { Dispatcher.BeginInvoke((Action)delegate { HandleFileAccept(f, tid, port); }); };
                _voip.FileRejectReceived += delegate(string f, string tid) { Dispatcher.BeginInvoke((Action)delegate { HandleFileReject(f, tid); }); };
                _voip.ChatAckReceived += delegate(string f) { Dispatcher.BeginInvoke((Action)delegate { ChatMarkDelivered(f); }); };
                _voip.ChatTypingReceived += delegate(string f, bool on) { Dispatcher.BeginInvoke((Action)delegate { ChatShowPeerTyping(f, on); }); };
                _voip.ChatQueued += delegate(string f) { Dispatcher.BeginInvoke((Action)delegate { ChatQueuedNotice(f); }); };
                _voip.PeerOffline += delegate(string f) { Dispatcher.BeginInvoke((Action)delegate { ChatOfflineNotice(f); }); };
                // Key exchange results: refresh the chip, and shout loudly when a
                // peer key is replaced - that is the only MITM signal TOFU can give.
                _voip.ChatSecurity += delegate(string n, string st, string det)
                {
                    Dispatcher.BeginInvoke((Action)delegate
                    {
                        bool open = _chatOpenNum != null && _chatOpenNum == n;
                        if (open) ChatSecurityChip(n);
                        if (st == "changed")
                        {
                            Log("SECURITY WARNING: #" + n + " now presents a different identity key (" + det + "). Nothing is being sent to them until you decide.", BrushWarn);
                            // The warning has to be impossible to miss and impossible
                            // to acknowledge by accident, so it opens in front of the
                            // conversation and stays until the user chooses.
                            if (open && _secSheet != null) OpenChatSecuritySheet(n);
                            else if (open && _secChip != null) _secChip.ToolTip = "Their identity key CHANGED - tap to review";
                        }
                        else if (st == "failed")
                            Log("Security: session with #" + n + " failed: " + det, BrushWarn);
                        else if (st == "locked" && open)
                            Log("Security: encrypted session with #" + n + " (" + det + ").", BrushGray);
                    });
                };
                // D1b: the route table is a live view, not a snapshot. Anything that
                // changes a link's state raises this, so the table cannot drift into
                // promising a route the router has already dropped.
                _voip.RoutesChanged += delegate { Dispatcher.BeginInvoke((Action)delegate { RefreshRouteTable(); }); };
                // The saved consent has to reach the router, not only the checkbox:
                // a tick that nothing obeys would be a lie about carrying peers.
                try { if (_cfg != null) _voip.SetCarryForPeers(_cfg.carry_for_peers); } catch (Exception ex) { Log("Routes: " + ex.Message, BrushGray); }
                _voip.ChatVoiceReceived += delegate(string f, byte[] wav)
                {
                    Dispatcher.BeginInvoke((Action)delegate
                    {
                        if (wav == null || wav.Length == 0) return;
                        try
                        {
                            string num = SanitizeNumber(f);
                            int secs = (wav.Length - 44) / (VoipAudio.SAMPLE_RATE * 2);   // 16 kHz mono 16-bit
                            string path = Path.Combine(AppConfig.ChatsDir, "vn_" + DateTime.Now.Ticks + ".wav");
                            Directory.CreateDirectory(AppConfig.ChatsDir);
                            File.WriteAllBytes(path, wav);
                            ChatPersist("vin", num, secs + "|" + path);
                            if (num == _chatOpenNum || num == ChatNumber()) ChatScrollEnd();
                            else ChatBumpUnread(num);
                            string vn = ChatLookupName(num);
                            Toast.Show("Voice note from " + (vn != null ? vn : ("#" + f)), "[" + secs + " s]", delegate
                            {
                                GetTabByHeader("SMS");
                                if (_txtChatTo != null) _txtChatTo.Text = num;
                                ChatOpen();
                            });
                        }
                        catch (Exception ex) { Log("Voice note save error: " + ex.Message, BrushWarn); }
                    });
                };
                _voip.Media.AudioFrame += delegate(byte[] pcm, System.Net.IPEndPoint ep)
                {
                    _audioFilter.ReferenceSpeaker(pcm);   // AEC echo reference
                    if (_recorder != null) _recorder.WriteRx(pcm);
                    TranscribeFrame(pcm);
                    if (_voipAudio != null) _voipAudio.EnqueuePlay(pcm);
                };
                _voipAudio.FrameCaptured += OnMicFrame;
                _voipAudio.LogLine += delegate(string s) { Log("Audio: " + s, BrushGray); };
                _voip.DirectoryChanged += delegate { Dispatcher.BeginInvoke((Action)delegate { RefreshPeerList(); }); };
                _voip.Start();
                ApplyCallSettings();
                UpdateVoipButtons();
            }
            catch (Exception ex) { Log("VoIP init failed: " + ex.Message, BrushRed); }

            // ── Background keep-alive service ───────────────────────────────
            // Runs for the lifetime of the app. Checks relay connectivity every
            // 30 s and re-applies settings if the relay dropped (network change,
            // WiFi ↔ LTE switch, etc.). Works on any network type.
            StartBackgroundReconnectService();
        }

        private Thread _bgReconnectThread;
        private volatile bool _bgRunning = true;

        private void StartBackgroundReconnectService()
        {
            _bgReconnectThread = new Thread(delegate()
            {
                Hang.Trace("bgSvc: started");
                while (_bgRunning)
                {
                    try
                    {
                        System.Threading.Thread.Sleep(30000);
                        if (!_bgRunning) break;
                        // Re-apply relay settings if the VoIP service is not connected
                        bool relayOk = _voip != null && _voip.RelayReady;
                        if (!relayOk && _voip != null && _cfg != null && !string.IsNullOrEmpty(_cfg.relay_server))
                        {
                            Hang.Trace("bgSvc: relay down, reconnecting...");
                            Dispatcher.BeginInvoke((Action)delegate
                            {
                                try { ApplyCallSettings(); Log("Background service: reconnected to relay.", BrushGray); }
                                catch { }
                            });
                        }
                    }
                    catch (System.Threading.ThreadInterruptedException) { break; }
                    catch { }
                }
                Hang.Trace("bgSvc: stopped");
            });
            _bgReconnectThread.IsBackground = true;  // does NOT prevent app from exiting
            _bgReconnectThread.Name = "UssdAppBgReconnect";
            _bgReconnectThread.Start();
        }

        private void SaveStateSafe()
        {
            try { SaveState(); } catch { }
        }

        // Start the embedded call server if the host checkbox says so.
        private void EnsureCallServer()
        {
            if (_callServer != null && _callServer.Running) return;
            try
            {
                _callServer = new CallServer();
                _callServer.Log += delegate(string s) { Log("CallSrv: " + s, BrushGray); };
                // Must happen before Start(): the server dials its listed peers as
                // it comes up, so a policy applied afterwards would be too late.
                ApplyFederationConfig(_callServer);
                bool useTls = _cfg != null && _cfg.relay_tls;
                if (_callServer.Start(CallServer.DEFAULT_PORT, useTls))
                {
                    Log("Hosting internet call server on port " + CallServer.DEFAULT_PORT +
                        (useTls ? " with authenticated TLS" : " with cleartext TCP") +
                        " (other devices: set Relay to this PC's address:" + CallServer.DEFAULT_PORT + ")",
                        BrushSuccess);
                    // The router question is asked once, here, and only after the port is
                    // actually bound - mapping a port nothing is listening on would open a
                    // hole and advertise it as a relay.
                    if (_cfg != null && _cfg.relay_port_map) TryOpenRouterPort(_callServer, CallServer.DEFAULT_PORT);
                    string pol = (_cfg != null ? _cfg.relay_policy : "allowed") ?? "allowed";
                    int peers = _cfg != null && !string.IsNullOrEmpty(_cfg.relay_peers)
                        ? _cfg.relay_peers.Split(',').Length : 0;
                    if (pol != "nobody" && peers > 0)
                        Log("Federation: linking to " + peers + " relay(s), carrying for " + pol + ".", BrushAccent);
                    SyncHostingAdvertise();
                }
                else
                {
                    string startError = _callServer.StartError ?? "";
                    Log(useTls && startError.StartsWith("TLS:", StringComparison.Ordinal)
                        ? "Could not host TLS relay: " + startError + " Install the certificate and restart the app."
                        : "Could not host call server on port " + CallServer.DEFAULT_PORT +
                          " (" + (startError.Length > 0 ? startError : "busy") + ") - will retry in 20 s",
                        BrushWarn);
                    _callServer = null;
                    if (!(useTls && startError.StartsWith("TLS:", StringComparison.Ordinal)))
                        ScheduleCallServerRetry();   // transient bind failures are retried; TLS setup errors need operator action
                }
            }
            catch (Exception ex)
            {
                Log("Call server error: " + ex.Message, BrushError);
                _callServer = null;
            }
        }

        // Ask the router to forward the relay port, and say what it answered in the
        // router's own terms rather than as success or failure. The result is worth a
        // permanent log line: if the mapping lands, the advertised address becomes one a
        // friend can actually dial; if it does not, the reason is the thing that has to
        // be readable instead of a spinner.
        //
        // The same opt-in also asks for the UDP media forward, because a person who has
        // agreed to let the router be touched has agreed to the thing that makes a direct
        // call possible - and if only the TCP relay port opens, every call still has to
        // pass through a relay.
        private void TryOpenRouterPort(CallServer s, int port)
        {
            if (s == null) return;
            Thread t = new Thread((ThreadStart)delegate
            {
                string pip, why;
                string local = VoipService.GetLocalIp() == null ? "127.0.0.1" : VoipService.GetLocalIp().ToString();
                bool opened;
                try { opened = PortMap.TryApply(port, local, out pip, out why); }
                catch (Exception ex) { pip = ""; why = "the UPnP attempt itself failed: " + ex.Message; opened = false; }
                if (opened && pip.Length > 0) s.PublicAddress = pip + ":" + port;
                string show = why;
                bool mm = false;
                try { if (_voip != null) mm = _voip.MapMediaPort(); } catch { mm = false; }
                Dispatcher.BeginInvoke((Action)delegate
                {
                    Log("Router port (UPnP): " + (opened ? "" : "not opened - ") + show, opened ? BrushSuccess : BrushWarn);
                    Log("Media port (UPnP/UDP): " + (mm
                        ? "forwarded, and announced to peers as " + (_voip.MyMappedMediaEp == null ? "?" : _voip.MyMappedMediaEp.ToString())
                        : "not forwarded - a direct call will not reach this machine, so calls are carried by the relay"),
                        mm ? BrushSuccess : BrushWarn);
                    SyncHostingAdvertise();
                });
            });
            t.IsBackground = true;
            t.Start();
        }

        private System.Windows.Threading.DispatcherTimer _callSrvRetry;

        // Push the "am I a hop for other people's traffic" policy onto a server.
        // Defaults are the safe ones: a relay serves the clients that register
        // with it, but does not carry for other relays until told to.
        private void ApplyFederationConfig(CallServer s)
        {
            if (s == null || _cfg == null) return;
            s.RelayName = _voip != null && !string.IsNullOrEmpty(_voip.LocalName)
                ? _voip.LocalName : Environment.MachineName;
            string pol = (_cfg.relay_policy ?? "allowed").Trim().ToLowerInvariant();
            if (pol != "nobody" && pol != "everyone" && pol != "allowed") pol = "allowed";
            s.RelayPolicy = pol;
            s.RelayAllow = _cfg.relay_allow ?? "";
            s.RelayLinks = _cfg.relay_peers ?? "";
            s.RelayAdvertise = _cfg.relay_advertise ?? "";
            s.RelayStoreKb = _cfg.relay_store_kb > 0 ? _cfg.relay_store_kb : 2048;
            s.RelayBandwidthKbps = _cfg.relay_bandwidth_kbps > 0 ? _cfg.relay_bandwidth_kbps : 0;
            s.RelayAutoMesh = _cfg.relay_automesh;
            s.RelayOnion = CallServer.NormalizeOnion(_cfg.relay_onion);
            s.RelayCarryMail = _cfg.relay_carry_mail;
            s.RelayPortMap = _cfg.relay_port_map;
        }

        // Re-apply after the user edits Settings, including new peer relays.
        private void ApplyFederationLive()
        {
            if (_callServer == null || !_callServer.Running) { SyncHostingAdvertise(); return; }
            if (_cfg != null && _callServer.UseTls != _cfg.relay_tls)
            {
                Log("Relay transport changed; restarting the hosted relay. Connected clients and links will reconnect.",
                    BrushWarn);
                _callServer.Stop();
                _callServer = null;
                SyncHostingAdvertise();
                EnsureCallServer();
                return;
            }
            ApplyFederationConfig(_callServer);
            _callServer.SyncLinks();
            // Enabling auto-mesh must act on what is already known, not wait for
            // the next gossip to happen to arrive.
            _callServer.ReconsiderMesh();
            SyncHostingAdvertise();
        }

        // The VoIP service answers LAN "is anyone hosting?" probes only when told
        // it is, and needs the address to hand back - otherwise discovery finds
        // nothing on a network where a relay plainly does exist.
        private void SyncHostingAdvertise()
        {
            if (_voip == null) return;
            bool hosting = _callServer != null && _callServer.Running;
            _voip.HostingRelay = hosting;
            _voip.RelayAdvertiseAddr = hosting ? _callServer.AdvertiseAddress() : "";
        }

        // Relays heard about but not yet trusted: LAN probes and referrals from
        // the relay we already use. Kept separate from RelayLinks on purpose -
        // nothing discovered is dialed without the user saying so.
        private readonly List<string> _foundRelays = new List<string>();

        // What the running relay actually holds in its ledger, so the Settings tab
        // shows a fact about the mesh instead of a promise about it.
        private TextBlock _relayLedgerList;

        private void RefreshLedgerView()
        {
            if (_relayLedgerList == null) return;
            try
            {
                if (_callServer == null || !_callServer.Running)
                { _relayLedgerList.Text = "this PC is not hosting a relay"; return; }
                List<string> l = _callServer.LedgerEndpoints;
                _relayLedgerList.Text = l.Count == 0 ? "none yet" : string.Join("\n", l.ToArray());
            }
            catch { _relayLedgerList.Text = "unavailable"; }
        }

        private void NoteFoundRelay(string endpoint, string source)
        {
            if (string.IsNullOrEmpty(endpoint)) return;
            endpoint = endpoint.Trim();
            if (_foundRelays.Contains(endpoint)) return;
            _foundRelays.Add(endpoint);
            Log("Relay " + source + ": " + endpoint +
                (_cfg != null && _cfg.relay_autolink ? " - auto-linking" : " - add it under Relays to link to"),
                BrushAccent);
            if (_cfg != null && _cfg.relay_autolink) AddRelayLink(endpoint);
            if (_relayFoundList != null) _relayFoundList.Text = string.Join("\n", _foundRelays.ToArray());
        }

        private void AddRelayLink(string endpoint)
        {
            if (_cfg == null || string.IsNullOrEmpty(endpoint)) return;
            foreach (string e in (cfgLinks()).Split(new char[] { ',', ';' }, StringSplitOptions.RemoveEmptyEntries))
                if (string.Equals(e.Trim(), endpoint, StringComparison.OrdinalIgnoreCase)) return;
            _cfg.relay_peers = string.IsNullOrEmpty(_cfg.relay_peers) ? endpoint : _cfg.relay_peers + "," + endpoint;
            try { _cfg.Save(); } catch { }
            ApplyFederationLive();
        }

        private string cfgLinks() { return _cfg != null && _cfg.relay_peers != null ? _cfg.relay_peers : ""; }

        private string FederationStatusLine()
        {
            if (_callServer == null || !_callServer.Running)
                return "Not hosting - tick Host server in the Dialer to become a relay.";
            return "Hosting. Links: " + _callServer.LinkCount + ", peers known through them: " +
                   _callServer.RemotePeerCount + ", carrying for others: " +
                   (_callServer.QueuedBytesForPeers / 1024) + " KB queued.";
        }

        private TextBlock _relayFoundList;

        // A KISS radio, if the user named a port. The number of things that can
        // go wrong with a serial device is why this is opt-in and why every
        // failure is logged with the port name in it: silence here is the one
        // outcome nobody can debug from across a room.
        private RadioTransport _radio;
        private SerialPort _radioPort;

        private void TryAttachRadio()
        {
            if (_voip == null || _cfg == null) return;
            string port = (_cfg.radio_port ?? "").Trim();
            if (port.Length == 0 || _radio != null) return;
            try
            {
                SerialPort sp = new SerialPort(port, 115200, Parity.None, 8, StopBits.One);
                sp.ReadTimeout = 250;
                sp.WriteTimeout = 2000;
                sp.Open();
                // The transport takes a Stream; a SerialPort is not one, it only
                // exposes one. Closing the stream does not close the handle, so
                // the port is kept and disposed alongside the transport.
                RadioTransport t = new RadioTransport("kiss", sp.BaseStream, 1200, 100, _cfg.radio_carries);
                string call = (_cfg.radio_callsign ?? "").Trim();
                t.Start(call.Length > 0 ? call : Axa25.CallsignForNumber(_myNumber));
                if (!_voip.AttachTransport(t, delegate(string from) { return t.NumberForCall(from); }))
                {
                    t.Dispose();
                    try { sp.Close(); } catch { }
                    return;
                }
                _radio = t;
                _radioPort = sp;
                Log("Radio link up on " + port + " as " + t.Name + ": text only, " +
                    t.BitRate + " bps, " + t.MaxFrameBytes + " B per message.", BrushSuccess);
            }
            catch (Exception ex)
            {
                Log("Radio on " + port + " did not come up: " + ex.Message +
                    " (wrong port, no KISS firmware, or the port is in use by another app)", BrushWarn);
            }
        }

        private void DetachRadio()
        {
            RadioTransport t = _radio;
            SerialPort p = _radioPort;
            _radio = null;
            _radioPort = null;
            try { if (t != null) t.Dispose(); } catch { }
            try { if (p != null) p.Close(); } catch { }
        }

        private void ScheduleCallServerRetry()
        {
            if (_callSrvRetry != null) return;
            _callSrvRetry = new System.Windows.Threading.DispatcherTimer
            {
                Interval = TimeSpan.FromSeconds(20)
            };
            _callSrvRetry.Tick += delegate
            {
                _callSrvRetry.Stop();
                _callSrvRetry = null;
                if (_chkHostCalls != null && _chkHostCalls.IsChecked == true)
                {
                    Hang.Trace("CallSrv retry attempt");
                    EnsureCallServer();
                }
            };
            _callSrvRetry.Start();
        }

        // Apply relay settings (host checkbox -> server, relay textbox -> client).
        // With no relay typed in, the app tries the relays.seed list - the one line a
        // friend can paste - before it gives up on reaching anyone off this network.
        private volatile bool _bootstrapping;
        private void ApplyCallSettings()
        {
            if (_voip == null) return;
            try
            {
                if (_chkHostCalls != null && _chkHostCalls.IsChecked == true)
                {
                    EnsureCallServer();
                    string relay = _txtRelay != null ? _txtRelay.Text.Trim() : "";
                    if (relay.Length == 0)
                    {
                        relay = "127.0.0.1:" + CallServer.DEFAULT_PORT;
                        if (_txtRelay != null) _txtRelay.Text = relay;
                    }
                }
                string addr = _txtRelay != null ? _txtRelay.Text.Trim() : "";
                // The STUN list the user can edit, handed to the thing that uses it.
                // This was a settings box that changed nothing: the query below had
                // Google's host written into it, so an ISP that blocks that one had no
                // way out and no way to know the box was a lie.
                try { _voip.StunServers = _cfg != null ? _cfg.stun_servers : ""; } catch { }
                // Same rule as the STUN list above: a setting has to reach the thing
                // that acts on it, or the tick box is a lie with a nicer shape.
                try { _voip.ForceRelayedMedia = Cli.RelayMedia || (_cfg != null && _cfg.relay_media); } catch { }
                UpdateRelayTrustChip();
                if (addr.Length == 0)
                {
                    // No relay is a real state with real consequences, and it used to
                    // be silent: peers outside this network cannot be reached at all,
                    // and a person who is not watching logs has no way to work that out.
                    int seeds = VoipService.SeedEntryCount;
                    if (seeds > 0 && !_bootstrapping)
                    {
                        // A seed entry is an address plus the fingerprint it should
                        // answer with, so trying one is a decision somebody already made
                        // on purpose. It still has to be checked before we register, and
                        // that check waits seconds by design - so it runs on a thread,
                        // never here, or the window freezes on a dead address.
                        _bootstrapping = true;
                        Log("No relay set - trying the " + seeds + " relay(s) listed in relays.seed."
                            + " Each one has to identify itself before anything is registered.", BrushGray);
                        Thread boot = new Thread((ThreadStart)delegate
                        {
                            string found = null;
                            string boom = null;
                            try { if (_voip != null && _voip.TryBootstrapRelay()) found = _voip.BootstrappedFrom; }
                            catch (Exception ex) { boom = ex.Message; }
                            _bootstrapping = false;
                            string f = found;
                            Dispatcher.BeginInvoke((Action)delegate
                            {
                                if (f != null && f.Length > 0)
                                {
                                    // The relay is live already (TryBootstrapRelay handed
                                    // it to EnableRelay); the box is filled so the state
                                    // is visible and can be kept or typed over.
                                    if (_txtRelay != null) _txtRelay.Text = f;
                                    Log("Connected through the seed list: " + f +
                                        ". Save Settings to keep it, or type your own relay over it.", BrushSuccess);
                                    FlushOutbox();
                                }
                                else
                                {
                                    Log("Nothing in relays.seed answered as itself" +
                                        (boom != null ? " (" + boom + ")" : "") +
                                        ", so nothing was registered anywhere. Reachable on this network"
                                        + " only until you set a relay - see the lines above for each try.", BrushWarn);
                                }
                            });
                        });
                        boot.IsBackground = true;
                        boot.Start();
                    }
                    else
                    {
                        _voip.DisableRelay();
                        Log("No relay set: reachable on this network only. Anyone on another "
                            + "network needs a relay - host one in Settings, or ask a friend for "
                            + (seeds > 0 ? "the seed line of theirs (it goes in relays.seed)."
                                         : "the address of theirs, and its fingerprint."), BrushWarn);
                    }
                }
                else
                {
                    _voip.EnableRelay(addr);
                    // Flush any queued messages now that relay is connected
                    Dispatcher.BeginInvoke((Action)delegate { FlushOutbox(); });
                }
            }
            catch (Exception ex) { Log("Relay setup error: " + ex.Message, BrushError); }
        }

        // The standing answer to "is this server the one I chose", kept on the screen
        // rather than in the log. The colours carry the weight because the line has to
        // stay readable at a glance: the pinned key is calm, first sight of one asks to
        // be checked, and a key that does not match the pin is the one case the whole
        // mechanism exists to catch - which must not depend on nobody having scrolled
        // past the line yet.
        private void UpdateRelayTrustChip()
        {
            if (_relayTrustText == null) return;
            try
            {
                string v = _voip == null ? "none" : _voip.RelayTrustVerdict;
                string t = _voip == null ? "no relay" : _voip.RelayTrustText;
                if (v == "verified-new")
                {
                    _relayTrustText.Text = "Relay identity: " + t + " - seen for the first time and pinned now. "
                                         + "Read these digits against the relay's own screen before trusting them.";
                    _relayTrustText.Foreground = BrushWarn;
                }
                else if (v == "verified-known")
                {
                    _relayTrustText.Text = "Relay identity: " + t + " - the key pinned for this address.";
                    _relayTrustText.Foreground = BrushSuccess;
                }
                else if (v == "mismatch" || v == "bad-signature")
                {
                    _relayTrustText.Text = "SECURITY: this relay's key is NOT the one pinned for it (" + t + "). "
                                         + "Nothing was registered and it will not be reconnected to.";
                    _relayTrustText.Foreground = BrushRed;
                }
                else if (_voip != null && _voip.Relay != null)
                {
                    _relayTrustText.Text = "Relay identity: " + t + " - unverified. Traffic stays sealed from it, "
                                         + "but it has not proven which server it is.";
                    _relayTrustText.Foreground = BrushWarn;
                }
                else
                {
                    _relayTrustText.Text = "Relay identity: none (no relay connected)";
                    _relayTrustText.Foreground = BrushGray;
                }
            }
            catch { }
        }

        // Friendly display name for a peer: saved contact name first.
        private string ChatLookupName(string number)
        {
            string n = SanitizeNumber(number);
            if (_contacts != null && n.Length > 0)
                foreach (Contact c in _contacts)
                    if (SanitizeNumber(c.Number) == n && !string.IsNullOrEmpty(c.Name))
                        return c.Name;
            return null;
        }

        private string _peerSig = null;

        private void RefreshPeerList()
        {
            if (_lvPeers == null || _voip == null) return;
            int relayCount = 0;
            // rebuild ONLY on membership changes: discovery fires every 2 s and
            // a full clear+rebuild every 2 s realized rows mid-click (UIA
            // Select() threw 'Unrecognized error' and users could not dial).
            // Status text ages with LastSeen, so include a coarse age bucket
            // in the signature: rebuild when someone crosses a 60 s boundary.
            string sig = "";
            foreach (VoipPeer p in _voip.Peers)
            {
                string age = ((DateTime.Now - p.LastSeen).TotalSeconds / 60).ToString("0");
                sig += p.Name + "|" + p.Ip + "|" + p.Number + "|" + age + ";";
            }
            foreach (RelayClient.PeerInfo pi in _voip.RelayDirectory())
            {
                relayCount++;
                sig += "#" + pi.Number + "|" + pi.Ip + "|" + pi.Machine + ";";
            }
            if (sig == _peerSig) { Hang.Trace("RefreshPeerList skip (unchanged)"); return; }
            _peerSig = sig;
            // remember the selected peer so refreshes (directory changes) do not
            // wipe the selection out from under the user before they press Call
            string selNumber = null, selIp = null;
            if (_lvPeers.SelectedItem is VoipPeer)
            {
                VoipPeer sp = (VoipPeer)_lvPeers.SelectedItem;
                selNumber = sp.Number;
                selIp = sp.Ip;
            }
            _lvPeers.Items.Clear();
            // hide duplicate entries: same virtual number from two sources
            Dictionary<string, bool> seen = new Dictionary<string, bool>();
            VoipPeer reselect = null;
            foreach (VoipPeer p in _voip.Peers)
            {
                if (p.Number == _myNumber) continue;               // never list ourselves
                string key = p.Number != null && p.Number.Length > 0 ? "#" + p.Number : (p.Name + "|" + p.Ip);
                if (seen.ContainsKey(key)) continue;
                seen[key] = true;
                string baseName = p.Name;
                string cn = (p.Number != null && p.Number.Length > 0) ? ChatLookupName(p.Number) : null;
                if (reselect == null && selNumber != null && selNumber.Length > 0 && p.Number == selNumber) reselect = p;
                // add a display copy so the underlying peer object's name is
                // never decorated in place (it would accumulate on refresh)
                if (cn != null)
                {
                    _lvPeers.Items.Add(new VoipPeer
                    {
                        Name = cn + "  (" + baseName + ")",
                        Ip = p.Ip,
                        Number = p.Number,
                        LastSeen = p.LastSeen
                    });
                }
                else _lvPeers.Items.Add(p);
            }
            foreach (RelayClient.PeerInfo pi in _voip.RelayDirectory())
            {
                relayCount++;
                if (pi.Number == _myNumber) continue;
                if (NumberShown(pi.Number)) continue;               // already listed from LAN discovery
                string baseName = pi.Machine;
                string cn = ChatLookupName(pi.Number);
                VoipPeer np = new VoipPeer
                {
                    Name = cn != null ? (cn + "  (" + baseName + ")") : baseName,
                    Ip = pi.Ip,
                    Number = pi.Number,
                    LastSeen = DateTime.Now
                };
                if (reselect == null && selNumber != null && selNumber.Length > 0 && pi.Number == selNumber) reselect = np;
                _lvPeers.Items.Add(np);
            }
            if (reselect != null) _lvPeers.SelectedItem = reselect;
            Hang.Trace("RefreshPeerList total=" + _lvPeers.Items.Count + " relay=" + relayCount);
        }

        // True when a peer with this number/ip is already shown (dedupe helper).
        private bool NumberShown(string num)
        {
            if (_lvPeers == null || string.IsNullOrEmpty(num)) return false;
            foreach (object o in _lvPeers.Items)
            {
                VoipPeer p = o as VoipPeer;
                if (p == null) continue;
                if (p.Number != null && p.Number == num) return true;
                if (p.Ip == num) return true;
            }
            return false;
        }

        private void ApplyVoipBreath(string state)
        {
            if (_voipStateText == null) return;
            bool live = state != null &&
                !state.StartsWith("Idle") && !state.StartsWith("Call ended") &&
                !state.StartsWith("Call rejected") && !state.StartsWith("Peer busy") &&
                !state.StartsWith("Call failed");
            if (live)
            {
                DoubleAnimation breath = new DoubleAnimation
                {
                    From = 1.0,
                    To = 0.55,
                    Duration = TimeSpan.FromMilliseconds(750),
                    AutoReverse = true,
                    RepeatBehavior = RepeatBehavior.Forever
                };
                _voipStateText.BeginAnimation(UIElement.OpacityProperty, breath);
            }
            else
            {
                _voipStateText.BeginAnimation(UIElement.OpacityProperty, null);
                _voipStateText.Opacity = 1.0;
            }
        }

        private void StartVoipCall(bool video)
        {
            if (_voip == null) return;
            Hang.Trace("StartVoipCall video=" + video + " enter");
            string ip = null;
            string number = null;
            string peerName = null;
            if (_lvPeers != null && _lvPeers.SelectedItem is VoipPeer)
            {
                VoipPeer p = (VoipPeer)_lvPeers.SelectedItem;
                ip = p.Ip;
                number = p.Number;
                peerName = p.Name;
            }
            if (string.IsNullOrEmpty(ip) && _txtVoipIp != null) ip = _txtVoipIp.Text.Trim();

            // a registered virtual number goes through the internet call path
            if (!string.IsNullOrEmpty(number) && _voip.IsRegisteredNumber(number))
            {
                StartVoipCallByNumber(number, video);
                return;
            }
            // Modem-free app caller IDs: typing a 700-XXXXXXX number (or a
            // contact whose number is one) always takes the relay path, even
            // when the peer is not in the relay directory yet.
            if (string.IsNullOrEmpty(ip) && _txtVoipIp != null)
            {
                string typed = AppNum.NormalizeForCall(_txtVoipIp.Text);
                if (AppNum.IsApp(typed))
                {
                    _voipPeerName = AppNum.Format(typed);
                    Log("App call \u279C " + AppNum.Format(typed) + " (no modem required)", BrushAccent);
                    StartVoipCallByNumber(typed, video);
                    return;
                }
            }
            if (string.IsNullOrEmpty(ip))
            {
                // typed a saved contact's name in the dial box? dial their number
                if (string.IsNullOrEmpty(number) && _txtVoipIp != null)
                {
                    string resolved = ResolveChatNumber(_txtVoipIp.Text);
                    if (resolved.Length >= 3 && _voip.IsRegisteredNumber(resolved))
                    {
                        _voipPeerName = _txtVoipIp.Text.Trim();
                        StartVoipCallByNumber(resolved, video);
                        return;
                    }
                }
                Hang.Trace("StartVoipCall no-target: selected=(" + ip + " num=" + number + ") typed=" + (_txtVoipIp != null ? _txtVoipIp.Text : ""));
                Log("VoIP: select a peer or enter an IP.", BrushWarn);
                return;
            }
            _voipPeerName = string.IsNullOrEmpty(peerName) ? ip : peerName;
            // Dial off the UI thread: direct connect blocks up to 2.5 s and any
            // stall there froze the window (observed on self-calls).
            Task.Run(delegate
            {
                bool started = false;
                try { started = _voip.StartCall(ip, video); }
                catch (Exception ex) { Log("VoIP dial error: " + ex.Message, BrushWarn); }
                Dispatcher.BeginInvoke(new Action(delegate
                {
                    if (started)
                    {
                        BeginVoipRec(_voipPeerName, "out", video);
                        OpenVoipMedia();
                        if (video) ShowVideoWindow();
                    }
                    UpdateVoipButtons();
                    UpdateCallOverlay();
                }));
            });
        }

        // Place an internet call by virtual number (direct if possible, else relay).
        private void StartVoipCallByNumber(string number, bool video)
        {
            HangTrace("StartVoipCallByNumber " + number + " video=" + video);
            if (_voip == null) return;
            if (!_voip.RelayReady)
            {
                Log("Internet calls need a relay server (set Relay, e.g. 127.0.0.1:" +
                    CallServer.DEFAULT_PORT + ", or tick Host server).", BrushWarn);
                return;
            }
            _voipPeerName = "#" + number;
            // A device cannot call itself (this produced busy loops + freezes
            // when the app dialed its own virtual number).
            string mine = SanitizeNumber(_myNumber ?? "");
            string theirs = SanitizeNumber(number);
            if (mine.Length > 0 && theirs == mine)
            {
                Log("That's this device's own number (" + mine + ").", BrushWarn);
                return;
            }
            // Dial off the UI thread - see StartVoipCall; a self-call used to
            // freeze the UI here (sync driver open + connect wait).
            Task.Run(delegate
            {
                bool started = false;
                try { started = _voip.StartCallByNumber(number, video); }
                catch (Exception ex) { Log("VoIP dial error: " + ex.Message, BrushWarn); }
                Dispatcher.BeginInvoke(new Action(delegate
                {
                    if (started)
                    {
                        BeginVoipRec(number, "out", video);
                        OpenVoipMedia();
                        if (video) ShowVideoWindow();
                    }
                    else if (AppNum.IsApp(AppNum.NormalizeForCall(number)))
                    {
                        // Peer offline / unreachable: leave a queued chat notice so
                        // they still see the missed call the moment they reconnect
                        // (the relay stores it and delivers on registration).
                        string when = DateTime.Now.ToString("HH:mm");
                        bool q = _voip != null && _voip.SendChat(number,
                            "Missed " + (video ? "video " : "voice ") + "call at " + when + " - I tried to reach you.");
                        Log(q ? "Peer is offline - missed-call notice queued (delivered when they reconnect)."
                              : "Peer is offline and the relay queue is unavailable.", BrushWarn);
                        Toast.Show("Call not connected", "Peer offline - a missed-call notice was queued for them.", null);
                    }
                    UpdateVoipButtons();
                    UpdateCallOverlay();
                }));
            });
        }

        // Enable/disable VoIP buttons from call state.
        private void UpdateVoipButtons()
        {
            if (_voip == null) return;
            bool inCall = _voip.InCall;
            if (_btnVoipVoice != null) _btnVoipVoice.IsEnabled = !inCall;
            if (_btnVoipVideo != null) _btnVoipVideo.IsEnabled = !inCall;
            if (_btnVoipHangup != null) _btnVoipHangup.IsEnabled = inCall;
        }

        private void HangupVoip()
        {
            if (_voip != null) _voip.EndCall();
            RecordVoipCallEnd();
            StopVoipMedia();
        }

        // Call history: arm a VoIP record when a call starts.
        private void BeginVoipRec(string number, string dir, bool video)
        {
            _voipRecActive = true;
            _voipRecNumber = number;
            _voipRecDir = dir;
            _voipRecKind = video ? "video" : "voip";
            _voipRecStart = DateTime.Now;
        }

        // Call history: close the in-flight VoIP record (idempotent).
        private void RecordVoipCallEnd()
        {
            if (!_voipRecActive) return;
            HangTrace("RecordVoipCallEnd " + _voipRecNumber + " " + _voipRecDir);
            _voipRecActive = false;
            int secs = (int)(DateTime.Now - _voipRecStart).TotalSeconds;
            AddCallHistory(_voipRecNumber, _voipRecDir, _voipRecKind, secs);
        }

        private void OnVoipIncoming(string name, bool video)
        {
            HangTrace("OnVoipIncoming " + name + " video=" + video);
            _voipPeerName = name;
            _voipRinging = true;
            if (_callStateText != null)
            {
                _callStateText.Text = "VoIP " + (video ? "video" : "voice") + " call: " + name;
                _callStateText.Foreground = BrushAccent;
            }
            // Non-blocking: show the overlay instead of a modal dialog.
            Toast.Show("Incoming " + (video ? "video" : "voice") + " call", name,
                delegate { GetTabByHeader("Dialer"); });
            ToneSynth.StartRing();
            UpdateCallOverlay();
        }

        private void AcceptVoipIncoming()
        {
            if (_voip == null) { _voipRinging = false; return; }
            ToneSynth.StopRing();
            bool video = _voip.VideoCall;
            _voipRinging = false;
            try
            {
                BeginVoipRec(_voipPeerName, "in", video);
                _voip.AcceptIncomingCall();
                OpenVoipMedia();
                if (video) ShowVideoWindow();
                UpdateVoipButtons();
            }
            catch (Exception ex) { Log("VoIP accept error: " + ex.Message, BrushWarn); }
            UpdateCallOverlay();
        }

        private void RejectVoipIncoming()
        {
            ToneSynth.StopRing();
            _voipRinging = false;
            if (_voip != null)
            {
                try { _voip.RejectIncomingCall(); } catch { }
            }
            AddCallHistory(_voipPeerName, "missed", _voip != null && _voip.VideoCall ? "video" : "voip", 0);
            UpdateCallOverlay();
        }

        private void OpenVoipMedia()
        {
            // NEVER open the audio devices on the UI thread: waveIn/waveOut open
            // can block on the driver and races the just-queued close of the
            // previous device - that deadlock froze the whole app on self-calls.
            if (_voipAudio == null) return;
            // Throttle: when the device is missing, blocked by Windows privacy
            // or held by another app, every caller used to spawn a retry thread.
            // One attempt every two seconds is plenty and keeps the log readable.
            if (DateTime.Now < _voipMediaRetryAt) return;
            if (Interlocked.CompareExchange(ref _voipMediaOpening, 1, 0) != 0) return;
            _voipMediaRetryAt = DateTime.Now.AddSeconds(2);
            Thread t = new Thread((ThreadStart)delegate
            {
                try
                {
                    // Retry against whatever instance is current: a media swap
                    // (StopVoipMedia) can happen while this thread is starting,
                    // and the old code then returned silently, leaving the mic
                    // closed - which broke voice-note recording and call audio.
                    VoipAudio cur = _voipAudio;
                    if (cur == null) return;
                    cur.OpenSpeaker();
                    cur.OpenMic();   // failures are logged (rate-limited) by VoipAudio
                }
                catch (Exception ex) { Log("Audio open error: " + ex.Message, BrushWarn); }
                finally { Interlocked.Exchange(ref _voipMediaOpening, 0); }
            });
            t.IsBackground = true;
            t.Start();
        }

        // Mic capture path: optional noise/echo filter, then send + record.
        // Muted: send nothing, but keep the recorder's local channel alive
        // with silence so the WAV stays time-aligned.
        private void OnMicFrame(byte[] pcm)
        {
            if (pcm == null) return;
            // voice-note recording taps the mic feed even outside a call
            if (_vnRecording)
            {
                lock (_vnLock) _vnBuf.Add((byte[])pcm.Clone());
            }
            // A group call has no 1:1 media channel, so InCall can be false
            // while the room is live - the room itself counts as a call here.
            if (_voip == null || (!_voip.InCall && !_voip.ConferenceMode)) return;
            if (_micMuted)
            {
                if (_recorder != null) _recorder.WriteTx(Silence640);
                return;
            }
            byte[] outp = _audioFilter.Enabled ? _audioFilter.Process(pcm) : pcm;
            if (_voip.ConferenceMode)
            {
                // Group audio is mixed on the relay: one sum for N listeners,
                // not N point-to-point sends from this mic.
                _voip.SendConferenceAudio(outp);
            }
            else _voip.Media.SendAudio(outp);
            if (_recorder != null) _recorder.WriteTx(outp);
        }

        // Call archive: one stereo WAV per connected call (L=remote, R=mic).
        private void StartRecordingIfNeeded()
        {
            if (_recorder != null) return;
            if (_cfg == null || !_cfg.record_calls) return;
            string peer = string.IsNullOrEmpty(_voipPeerName) ? "peer" : _voipPeerName;
            CallRecorder r = CallRecorder.StartNew(peer);
            if (r != null)
            {
                _recorder = r;
                Log("Recording call -> recordings\\" + System.IO.Path.GetFileName(r.FilePath), BrushAccent);
            }
        }

        private void StopRecording()
        {
            CallRecorder r = _recorder;
            _recorder = null;
            if (r == null) return;
            try { r.Dispose(); } catch { }
            if (r.FilePath != null) Log("Recording saved: " + r.FilePath, BrushSuccess);
        }

        // ── Call transcription ────────────────────────────────────────────
        // Only the remote voice is transcribed: subtitling both sides of a call
        // into one column of text is unreadable, and the local voice is already
        // heard directly. It taps the same frame stream the recorder uses, so it
        // works for 1:1 calls and for the group mix alike.
        private void TranscribeFrame(byte[] pcm)
        {
            Transcriber t = _transcriber;
            if (t == null) return;
            try { t.AddFrame(pcm); } catch { }
        }

        private void StartTranscriberIfNeeded()
        {
            if (_transcriber != null) return;
            if (_cfg == null || !_cfg.transcribe_calls) return;
            Transcriber t = new Transcriber(Transcriber.FindExe(_cfg.whisper_exe),
                                            Transcriber.FindModel(_cfg.whisper_model),
                                            _cfg.whisper_lang);
            if (!t.Available)
            {
                Log("Transcription is off: no whisper.cpp binary or ggml model found. " +
                    "Set them under Settings > Communication.", BrushWarn);
                t.Dispose();
                return;
            }
            t.Notice += delegate(string s)
            {
                Dispatcher.BeginInvoke((Action)delegate { Log("Transcript: " + s, BrushGray); });
            };
            t.Line += delegate(string line)
            {
                Dispatcher.BeginInvoke((Action)delegate { AddSubtitle(line); });
            };
            string peer = string.IsNullOrEmpty(_voipPeerName) ? "peer" : _voipPeerName;
            t.Start(peer, _recorder != null ? _recorder.FilePath : null);
            _transcriber = t;
        }

        private void StopTranscriber()
        {
            Transcriber t = _transcriber;
            _transcriber = null;
            if (t == null) return;
            // Stop() waits up to 3 s for the in-flight segment: never on the UI
            // thread, or hanging up would visibly freeze the window.
            Thread th = new Thread((ThreadStart)delegate { try { t.Stop(); t.Dispose(); } catch { } });
            th.IsBackground = true;
            th.Start();
        }

        // Three lines is enough to follow; a long call must not grow the stage.
        private void AddSubtitle(string line)
        {
            if (_subsText == null || string.IsNullOrEmpty(line)) return;
            _subsLines.Add(line);
            while (_subsLines.Count > 3) _subsLines.RemoveAt(0);
            _subsText.Text = string.Join("\n", _subsLines.ToArray());
            _subsText.Visibility = Visibility.Visible;
        }

        private void ClearSubtitles()
        {
            _subsLines.Clear();
            if (_subsText != null) { _subsText.Text = ""; _subsText.Visibility = Visibility.Collapsed; }
        }

        private void StopVoipMedia()
        {
            // Dispose audio on a background thread: waveIn/waveOut close can
            // block on the driver and must never freeze the UI thread.
            VoipAudio old = _voipAudio;
            if (old != null)
            {
                _voipAudio = new VoipAudio();
                _voipAudio.FrameCaptured += OnMicFrame;
                _voipAudio.LogLine += delegate(string s) { Log("Audio: " + s, BrushGray); };
                Thread t = new Thread((ThreadStart)delegate { try { old.Dispose(); } catch { } });
                t.IsBackground = true;
                t.Start();
            }
            StopCamera();
            // Reset in-call UI state (video page + mic toggle).
            _micMuted = false;
            SyncOverlayMute();   // UI thread: clear any stale "Unmute" label
            if (_btnMuteMic != null)
            {
                _btnMuteMic.Content = "Mute Mic";
                _btnMuteMic.ClearValue(Button.StyleProperty);
            }
            if (_tileLocalName != null) _tileLocalName.Text = "You";
            if (_imgRemote != null) _imgRemote.Source = null;
            if (_imgLocal != null) _imgLocal.Source = null;
            // Drop the group grid with the call: EndCallInternal has already left
            // the room, so this collapses the stage back to the idle card.
            RefreshConferenceTiles();
            UpdateVideoStage();
            if (_callStateText != null) { _callStateText.Text = "Idle"; _callStateText.Foreground = BrushFg; }
        }

        // ---------- video window + camera capture ----------
        // One tile per face: remote + you in a UniformGrid (2 columns when
        // wide, stacked when narrow), plus a control bar (mute / hang up).
        // Video calls render in the in-app Video Call page (conference layout:
        // thumbnail strip, main stage, Key Moments + Chat sidebar, control pill).
        private void ShowVideoWindow()
        {
            ShowPage(2); // Video Call page
            UpdateVideoStage();
            if (!_camRun) StartCamera();
        }

        // Stage label + idle/active visuals reflect the current peer / state.
        private void UpdateVideoStage()
        {
            bool live = _voip != null && (_voip.InCall || _voip.ConferenceMode);
            if (_vidIdle != null) _vidIdle.Visibility = live ? Visibility.Collapsed : Visibility.Visible;
            if (_vidIdleButton != null) _vidIdleButton.Visibility = Visibility.Visible;
            if (_stageTag != null) _stageTag.Visibility = live ? Visibility.Visible : Visibility.Collapsed;
            if (_tileRemoteName != null)
                _tileRemoteName.Text = _voipPeerName ?? "Remote";
            if (_videoStateText != null)
            {
                _videoStateText.Text = live ? "  \u00b7  Live \u00b7 end-to-end encrypted"
                    : "  \u00b7  no active call";
            }
            if (_tileLocalName != null)
                _tileLocalName.Text = _micMuted ? "You (muted)" : "You";
        }

        // A single participant tile: video area + name bar underneath.
        private static Border MakeVideoTile(string name, Image img, Brush accent, out TextBlock nameText)
        {
            Border tile = new Border
            {
                Background = Brushes.Black,
                BorderBrush = accent,
                BorderThickness = new Thickness(1.5),
                CornerRadius = new CornerRadius(10),
                Margin = new Thickness(4),
                MinHeight = 150
            };
            Grid g = new Grid();
            g.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) });
            g.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            Grid.SetRow(img, 0);
            g.Children.Add(img);
            Border nameBar = new Border { Background = Hex("#232334"), Padding = new Thickness(8, 4, 8, 4) };
            nameText = new TextBlock
            {
                Text = name,
                Foreground = accent,
                FontWeight = FontWeights.SemiBold,
                HorizontalAlignment = HorizontalAlignment.Center
            };
            nameBar.Child = nameText;
            Grid.SetRow(nameBar, 1);
            g.Children.Add(nameBar);
            tile.Child = g;
            return tile;
        }

        // ── Group calls ───────────────────────────────────────────────────
        // A room lives on the relay and anyone can open one; the id carries the
        // opener's number, so two hosts cannot collide. Inviting a peer is one
        // control line (room id + our name). They decide whether to join,
        // because joining is what turns their microphone into a broadcast.
        private void EnsureConferenceRoom()
        {
            if (_voip == null || _voip.ConferenceMode) return;
            if (!_voip.RelayReady)
            {
                Log("Group calls need the relay — set the relay address in Settings.", BrushWarn);
                return;
            }
            _confRoomHost = _myNumber;
            _voip.JoinConference(_voip.NewConferenceRoomId());
            // Generate an E2E room key so conference audio is encrypted end-to-end.
            // The relay forwards without mixing; each member decrypts and mixes locally.
            byte[] roomKey = _voip.GenerateConferenceRoomKey();
            _voip.SetConferenceRoomKey(roomKey);
            Log("Group call: E2E encryption enabled — the relay cannot hear the audio.", BrushSuccess);
            RefreshConferenceTiles();
        }

        private void AddParticipantClick()
        {
            if (_voip == null) return;
            if (!_voip.RelayReady) { Log("Add participant: relay not connected.", BrushWarn); return; }
            EnsureConferenceRoom();
            if (!_voip.ConferenceMode) return;

            List<VoipPeer> invite = new List<VoipPeer>();
            foreach (VoipPeer p in _voip.Peers)
            {
                if (p == null || string.IsNullOrEmpty(p.Number)) continue;   // LAN peer, no app id
                if (p.Number == _myNumber) continue;
                if (_voip.ConferenceMembers.Contains(p.Number)) continue;    // already in the room
                if (!p.Status.StartsWith("\u25CF")) continue;                // must be online now
                invite.Add(p);
            }
            if (invite.Count == 0)
            {
                Toast.Show("No peers to invite",
                    "A group call needs other online devices on the same relay.", null);
                return;
            }
            ShowInvitePicker(invite);
        }

        private void ShowInvitePicker(List<VoipPeer> invite)
        {
            Window pw = new Window
            {
                Title = "Add participant",
                Width = 400,
                SizeToContent = SizeToContent.Height,
                ResizeMode = ResizeMode.NoResize,
                WindowStartupLocation = WindowStartupLocation.CenterOwner,
                Owner = this,
                Background = Theme.Bg
            };
            Border pc = new Border { Background = Theme.Card, BorderBrush = Theme.CardBorder, BorderThickness = new Thickness(1), CornerRadius = new CornerRadius(12), Padding = new Thickness(18, 14, 18, 14), Margin = new Thickness(10) };
            StackPanel pp = new StackPanel();
            pp.Children.Add(new TextBlock { Text = "Add participant", FontSize = 14, FontWeight = FontWeights.Bold, Foreground = BrushFg, Margin = new Thickness(0, 0, 0, 4) });
            pp.Children.Add(new TextBlock
            {
                Text = "Everyone in the room hears the same mixed audio. The people you invite choose whether to join.",
                FontSize = 11, Foreground = BrushGray, TextWrapping = TextWrapping.Wrap,
                Margin = new Thickness(0, 0, 0, 10)
            });
            List<CheckBox> boxes = new List<CheckBox>();
            foreach (VoipPeer p in invite)
            {
                CheckBox cb = new CheckBox
                {
                    Content = p.Name + "  \u00b7  #" + p.Number,
                    Foreground = BrushFg,
                    FontSize = 12,
                    Margin = new Thickness(0, 4, 0, 4)
                };
                boxes.Add(cb);
                pp.Children.Add(cb);
            }
            StackPanel prow = new StackPanel { Orientation = Orientation.Horizontal, HorizontalAlignment = HorizontalAlignment.Right, Margin = new Thickness(0, 12, 0, 0) };
            Button btnCancelInv = MakeButton("Cancel");
            btnCancelInv.Click += delegate { pw.Close(); };
            prow.Children.Add(btnCancelInv);
            Button btnInvite = MakeButton("Invite");
            Style ipr = TryStyle("PrimaryButton"); if (ipr != null) btnInvite.Style = ipr;
            btnInvite.Margin = new Thickness(8, 0, 0, 0);
            btnInvite.Click += delegate
            {
                string room = _voip.ActiveConferenceRoom;
                int sent = 0;
                for (int i = 0; i < boxes.Count; i++)
                {
                    if (boxes[i].IsChecked != true) continue;
                    VoipPeer p = invite[i];
                    try
                    {
                        _voip.InviteToConference(p.Number, room, _voip.LocalName);
                        // Distribute the E2E room key to the invited member via sealed chat
                        _voip.ShareConferenceRoomKey(p.Number);
                        sent++;
                    }
                    catch (Exception ex) { Log("Invite failed for #" + p.Number + ": " + ex.Message, BrushError); }
                }
                if (sent > 0) Log("Invited " + sent + " peer(s) into the group call.", BrushSuccess);
                else Log("Nothing selected — nobody invited.", BrushGray);
                pw.Close();
            };
            prow.Children.Add(btnInvite);
            pp.Children.Add(prow);
            pc.Child = pp; pw.Content = pc; pw.ShowDialog();
        }

        // Rebuild the tile grid from the roster. Only runs when members change;
        // talk levels and thumbnails update the existing tiles in place.
        private void RefreshConferenceTiles()
        {
            if (_confTiles == null) return;
            bool inRoom = _voip != null && _voip.ConferenceMode;
            _confHost.Visibility = inRoom ? Visibility.Visible : Visibility.Collapsed;
            _confTag.Visibility = inRoom ? Visibility.Visible : Visibility.Collapsed;
            // Self is a real tile in a group, so the floating PiP would double it.
            if (_pipHost != null) _pipHost.Visibility = inRoom ? Visibility.Collapsed : Visibility.Visible;
            _confTiles.Children.Clear();
            _confTileImgs.Clear();
            _confTileNames.Clear();
            _confTileBorders.Clear();
            if (!inRoom) return;

            List<string> members = new List<string>(_voip.ConferenceMembers);
            if (!members.Contains(_myNumber)) members.Insert(0, _myNumber ?? "");
            int n = members.Count;
            // 2x2 up to four, 3x3 beyond: the roadmap grid, no scrolling needed.
            _confTiles.Columns = n <= 1 ? 1 : (n <= 4 ? 2 : 3);
            _confTiles.Rows = (int)Math.Ceiling(n / (double)_confTiles.Columns);
            _confTag.Text = "\uD83D\uDC65 Group call \u00b7 " + n +
                            (n <= 1 ? " (waiting for peers)" : " in room");

            foreach (string num in members)
            {
                bool self = num == _myNumber;
                Image im;
                TextBlock nm;
                Border tile = MakeConfTile(self ? "You" : PeerLabel(num), out im, out nm, self);
                _confTiles.Children.Add(tile);
                if (self)
                {
                    _confTileImgs["__self"] = im;
                    _confTileNames["__self"] = nm;
                    _confTileBorders[num] = tile;
                }
                else
                {
                    if (im != null) _confTileImgs[num] = im;
                    if (nm != null) _confTileNames[num] = nm;
                    _confTileBorders[num] = tile;
                }
            }
        }

        private Border MakeConfTile(string label, out Image img, out TextBlock nameText, bool self)
        {
            Image im = new Image
            {
                Stretch = Stretch.UniformToFill,
                VerticalAlignment = VerticalAlignment.Center,
                HorizontalAlignment = HorizontalAlignment.Center
            };
            TextBlock tb;
            Border b = MakeVideoTile(label, im, self ? BrushAccent : Brushes.White, out tb);
            img = im;
            nameText = tb;
            return b;
        }

        private string PeerLabel(string number)
        {
            if (_voip != null)
            {
                foreach (VoipPeer p in _voip.Peers)
                    if (p != null && p.Number == number && !string.IsNullOrEmpty(p.Name)) return p.Name;
            }
            if (_contacts != null)
            {
                foreach (Contact c in _contacts)
                    if (c != null && c.Number == number && !string.IsNullOrEmpty(c.Name)) return c.Name;
            }
            return AppNum.Format(number);
        }

        // Room mix arrives already summed; the playout path handles it in
        // VoipService. Here we only need the speaker highlight, on the UI thread.
        private void OnConferenceRoster(List<string> members)
        {
            Dispatcher.BeginInvoke((Action)delegate
            {
                RefreshConferenceTiles();
                if (_voip == null || !_voip.ConferenceMode) return;
                if (members != null && members.Count >= 2)
                {
                    if (_vidIdle != null) _vidIdle.Visibility = Visibility.Collapsed;
                    // A group that has people in it is worth looking at.
                    ShowPage(2);
                }
            });
        }

        private void OnConferenceTalk(Dictionary<string, int> levels)
        {
            Dispatcher.BeginInvoke((Action)delegate
            {
                foreach (KeyValuePair<string, Border> kv in _confTileBorders)
                {
                    int lvl;
                    bool speaking = levels != null && levels.TryGetValue(kv.Key, out lvl) && lvl > 0;
                    kv.Value.BorderBrush = speaking
                        ? new SolidColorBrush(Color.FromRgb(0x22, 0xc5, 0x5e))
                        : (kv.Key == _myNumber ? BrushAccent : Brushes.White);
                    kv.Value.BorderThickness = new Thickness(speaking ? 3 : 1.5);
                    TextBlock nm;
                    if (_confTileNames.TryGetValue(kv.Key, out nm) && nm != null)
                        nm.Text = (kv.Key == _myNumber ? "You" : PeerLabel(kv.Key)) +
                                  (speaking ? "  \uD83D\uDD0A" : "");
                }
            });
        }

        private void OnConferenceVideo(string fromNumber, byte[] jpeg)
        {
            Dispatcher.BeginInvoke((Action)delegate
            {
                Image im;
                if (fromNumber == _myNumber || !_confTileImgs.TryGetValue(fromNumber, out im) || im == null) return;
                try
                {
                    using (MemoryStream ms = new MemoryStream(jpeg))
                    {
                        BitmapImage bmp = new BitmapImage();
                        bmp.BeginInit();
                        bmp.CacheOption = BitmapCacheOption.OnLoad;
                        bmp.StreamSource = ms;
                        bmp.EndInit();
                        bmp.Freeze();
                        im.Source = bmp;
                    }
                }
                catch { }
            });
        }

        private void OnConferenceInvite(string roomId, string hostNumber, string hostName)
        {
            Dispatcher.BeginInvoke((Action)delegate
            {
                if (_voip == null || string.IsNullOrEmpty(roomId)) return;
                if (_voip.ActiveConferenceRoom == roomId)
                {
                    RefreshConferenceTiles();
                    return;   // we already opened or joined this one
                }
                _confRoomHost = hostNumber;
                Log("Group call invite from " + hostName + " (#" + hostNumber + ")", BrushAccent);
                Toast.Show("Group call invite",
                    hostName + " is inviting you into a group call \u2014 tap to join",
                    delegate { JoinConferenceFromInvite(roomId, hostNumber, hostName); });
            });
        }

        private void JoinConferenceFromInvite(string roomId, string hostNumber, string hostName)
        {
            if (_voip == null) return;
            _voip.JoinConference(roomId);
            RefreshConferenceTiles();
            ShowPage(2);
            Log("Joined " + hostName + "'s group call.", BrushSuccess);
        }

        private void ToggleMicMute()
        {
            _micMuted = !_micMuted;
            if (_btnMuteMic != null)
            {
                _btnMuteMic.Content = _micMuted ? "Unmute Mic" : "Mute Mic";
                if (_micMuted)
                {
                    Style danger = TryStyle("DangerButton");
                    if (danger != null) _btnMuteMic.Style = danger;
                }
                else
                {
                    _btnMuteMic.ClearValue(Button.StyleProperty);
                }
            }
            if (_tileLocalName != null) _tileLocalName.Text = _micMuted ? "You (muted)" : "You";
            // The room mixer needs to know too: muting locally while the relay
            // still forwards our frames would leave everyone hearing us.
            if (_voip != null && _voip.ConferenceMode) _voip.SetConferenceMuted(_micMuted);
            Log(_micMuted ? "VoIP: microphone muted" : "VoIP: microphone unmuted", BrushGray);
            SyncOverlayMute();
        }

        private void ShowRemoteFrame(byte[] jpeg)
        {
            if (_imgRemote == null) return;
            try
            {
                using (MemoryStream ms = new MemoryStream(jpeg))
                {
                    var bmp = new System.Windows.Media.Imaging.BitmapImage();
                    bmp.BeginInit();
                    bmp.CacheOption = System.Windows.Media.Imaging.BitmapCacheOption.OnLoad;
                    bmp.StreamSource = ms;
                    bmp.EndInit();
                    bmp.Freeze();
                    _imgRemote.Source = bmp;
                }
            }
            catch { }
        }

        private void StartCamera()
        {
            StopCamera();
            string script = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "..", "Python", "voip_camera.py");
            if (!File.Exists(script)) script = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "voip_camera.py");
            if (!File.Exists(script)) { Log("Camera helper not found: voip_camera.py", BrushWarn); return; }
            string[] pythons = new string[] { "python", "py" };
            Process proc = null;
            Exception lastErr = null;
            foreach (string py in pythons)
            {
                try
                {
                    ProcessStartInfo psi = new ProcessStartInfo
                    {
                        FileName = py,
                        Arguments = "-u \"" + script + "\" 320 240 12 55",
                        UseShellExecute = false,
                        RedirectStandardOutput = true,
                        RedirectStandardError = true,
                        CreateNoWindow = true
                    };
                    proc = Process.Start(psi);
                    break;
                }
                catch (Exception ex) { lastErr = ex; proc = null; }
            }
            if (proc == null)
            {
                Log("Camera start failed (python not found): " + (lastErr != null ? lastErr.Message : "unknown"), BrushRed);
                return;
            }
            _camProc = proc;
            _camRun = true;
            // Drain stderr on its own thread: otherwise the helper can block on
            // a full pipe, and its errors (no opencv, no camera) are invisible.
            string camErr = null;
            Thread errT = new Thread((ThreadStart)delegate
            {
                try
                {
                    string line;
                    while ((line = proc.StandardError.ReadLine()) != null)
                    {
                        if (string.IsNullOrEmpty(line)) continue;
                        camErr = line;
                        Log("Camera: " + line, BrushWarn);
                    }
                }
                catch { }
            });
            errT.IsBackground = true;
            errT.Start();
            Thread t = new Thread((ThreadStart)delegate { CamReadLoop(delegate { return camErr; }); });
            t.IsBackground = true;
            t.Start();
            Log("Camera started for video call.", BrushSuccess);
        }

        private void CamReadLoop(Func<string> lastErr)
        {
            bool eof = false;
            try
            {
                Stream s = _camProc.StandardOutput.BaseStream;
                byte[] lenBuf = new byte[4];
                // A group call keeps the camera running even with no 1:1 media
                // channel, because the room is what carries the picture.
                while (_camRun && _voip != null &&
                       ((_voip.InCall && _voip.VideoCall) || _voip.ConferenceMode))
                {
                    if (!ReadFull(s, lenBuf, 4)) { eof = true; break; }
                    int len = lenBuf[0] | (lenBuf[1] << 8) | (lenBuf[2] << 16) | (lenBuf[3] << 24);
                    if (len <= 0 || len > 200000) { eof = true; break; }
                    byte[] jpeg = new byte[len];
                    if (!ReadFull(s, jpeg, len)) { eof = true; break; }
                    if (_voip.ConferenceMode)
                    {
                        // Group video is one thumbnail per member into the room,
                        // throttled to ~2 fps: the helper renders 12 fps, and
                        // pushing that to N peers multiplies the uplink by N for
                        // tiles that are far too small to show the difference.
                        int tick = Environment.TickCount;
                        if (tick - _confVideoTick >= 450)
                        {
                            _confVideoTick = tick;
                            try { _voip.SendConferenceVideo(jpeg); } catch { }
                        }
                    }
                    else
                    {
                        int fid = _camFrameId = (_camFrameId + 1) & 0x7FFF;
                        const int chunk = 1200;
                        int count = (jpeg.Length + chunk - 1) / chunk;
                        if (count > 128)
                        {
                            // Receiver rejects frames needing >128 chunks; skipping
                            // keeps the stream alive instead of sending undecodable junk.
                            Log("Camera frame too large (" + jpeg.Length + " B) - skipped.", BrushWarn);
                        }
                        else
                        {
                            for (int i = 0; i < count; i++)
                            {
                                int off = i * chunk;
                                int n = Math.Min(chunk, jpeg.Length - off);
                                byte[] part = new byte[n];
                                Buffer.BlockCopy(jpeg, off, part, 0, n);
                                _voip.Media.SendVideo(part, fid, i, count);
                            }
                        }
                    }
                    // local preview
                    Dispatcher.BeginInvoke((Action)delegate
                    {
                        BitmapImage bmp = null;
                        try
                        {
                            using (MemoryStream ms = new MemoryStream(jpeg))
                            {
                                bmp = new System.Windows.Media.Imaging.BitmapImage();
                                bmp.BeginInit();
                                bmp.CacheOption = System.Windows.Media.Imaging.BitmapCacheOption.OnLoad;
                                bmp.StreamSource = ms;
                                bmp.EndInit();
                                bmp.Freeze();
                            }
                        }
                        catch { return; }
                        if (_imgLocal != null) _imgLocal.Source = bmp;
                        // In a group call our face lives in the grid, not the PiP.
                        Image self;
                        if (_confTileImgs.TryGetValue("__self", out self) && self != null)
                            self.Source = bmp;
                    });
                }
            }
            catch (Exception ex) { Log("Camera read error: " + ex.Message, BrushWarn); }
            finally
            {
                // Helper died while a video call was still live: say why,
                // otherwise remote video just silently never appears.
                _camRun = false;
                if (eof && _voip != null && ((_voip.InCall && _voip.VideoCall) || _voip.ConferenceMode))
                {
                    string why = lastErr != null ? lastErr() : null;
                    Log("Camera stopped - no video will be sent."
                        + (string.IsNullOrEmpty(why) ? " (helper exited)" : " " + why), BrushWarn);
                }
            }
        }

        private static bool ReadFull(Stream s, byte[] buf, int count)
        {
            int got = 0;
            while (got < count)
            {
                int n = s.Read(buf, got, count - got);
                if (n <= 0) return false;
                got += n;
            }
            return true;
        }

        private void StopCamera()
        {
            _camRun = false;
            if (_camProc != null)
            {
                try { if (!_camProc.HasExited) _camProc.Kill(); } catch { }
                try { _camProc.Dispose(); } catch { }
                _camProc = null;
            }
        }

        // ---------- animations / animated logo ----------
        // Mini animated logo: blue tile + white chat bubble + pulsing signal waves
        // (mirrors the .ico; waves ripple in sequence like a broadcast).
        private FrameworkElement CreateAnimatedLogo()
        {
            Grid g = new Grid { Width = 34, Height = 34, Margin = new Thickness(0, 0, 8, 0) };

            // rounded blue tile with gradient
            Border tile = new Border
            {
                CornerRadius = new CornerRadius(9),
                Background = new LinearGradientBrush(
                    (Color)ColorConverter.ConvertFromString("#2563EB"),
                    (Color)ColorConverter.ConvertFromString("#1D4ED8"), 90)
            };
            g.Children.Add(tile);

            // three signal wave arcs (stroked ellipses, bottom-left origin)
            for (int i = 0; i < 3; i++)
            {
                double sz = 16 + i * 9;
                System.Windows.Shapes.Ellipse wave = new System.Windows.Shapes.Ellipse
                {
                    Width = sz,
                    Height = sz,
                    Stroke = Brushes.White,
                    StrokeThickness = 1.8,
                    Opacity = 0.25,
                    HorizontalAlignment = HorizontalAlignment.Left,
                    VerticalAlignment = VerticalAlignment.Bottom,
                    Margin = new Thickness(-3 - i * 3, 0, 0, -3 - i * 3)
                };
                g.Children.Add(wave);

                DoubleAnimation fade = new DoubleAnimation
                {
                    From = 0.1,
                    To = 0.9 - i * 0.15,
                    Duration = TimeSpan.FromMilliseconds(520),
                    AutoReverse = true,
                    RepeatBehavior = RepeatBehavior.Forever,
                    BeginTime = TimeSpan.FromMilliseconds(i * 170)
                };
                wave.BeginAnimation(UIElement.OpacityProperty, fade);
            }

            // white chat bubble
            Border bubble = new Border
            {
                Width = 17,
                Height = 13,
                Background = Brushes.White,
                CornerRadius = new CornerRadius(4),
                HorizontalAlignment = HorizontalAlignment.Center,
                VerticalAlignment = VerticalAlignment.Center,
                Margin = new Thickness(3, -3, -3, 3)
            };
            // tail triangle for bubble
            System.Windows.Shapes.Polygon tail = new System.Windows.Shapes.Polygon
            {
                Points = new PointCollection
                {
                    new Point(0, 0), new Point(0, 6), new Point(5, 0)
                },
                Fill = Brushes.White,
                HorizontalAlignment = HorizontalAlignment.Left,
                VerticalAlignment = VerticalAlignment.Top,
                Margin = new Thickness(-1, 8, 0, 0)
            };
            Grid bg = new Grid();
            bg.Children.Add(bubble);
            bg.Children.Add(tail);
            // three menu lines inside bubble
            StackPanel lines = new StackPanel { Margin = new Thickness(3, 2.5, 3, 2.5) };
            lines.Children.Add(new Border { Height = 2, Background = Hex("#1D4ED8"), CornerRadius = new CornerRadius(1), Margin = new Thickness(0, 0.8, 0, 0.8) });
            lines.Children.Add(new Border { Height = 2, Background = Hex("#1D4ED8"), CornerRadius = new CornerRadius(1), Margin = new Thickness(0, 0.8, 0, 0.8) });
            lines.Children.Add(new Border { Height = 2, Background = Hex("#1D4ED8"), CornerRadius = new CornerRadius(1), Margin = new Thickness(0, 0.8, 4, 0.8) });
            bubble.Child = lines;
            // bubble glow pulse
            DoubleAnimation glow = new DoubleAnimation
            {
                From = 1.0,
                To = 0.82,
                Duration = TimeSpan.FromMilliseconds(900),
                AutoReverse = true,
                RepeatBehavior = RepeatBehavior.Forever
            };
            bubble.BeginAnimation(UIElement.OpacityProperty, glow);

            g.Children.Add(bg);
            return g;
        }

        // Small pulsing "live" dot next to the status pill.
        private void StartLiveDot(bool connected)
        {
            if (_liveDot == null) return;
            _liveDot.Fill = connected ? BrushGreen : BrushRed;
            DoubleAnimation pulse = new DoubleAnimation
            {
                From = 1.0,
                To = connected ? 0.35 : 0.75,
                Duration = TimeSpan.FromMilliseconds(700),
                AutoReverse = true,
                RepeatBehavior = RepeatBehavior.Forever
            };
            _liveDot.BeginAnimation(UIElement.OpacityProperty, pulse);
        }

        // Typewriter effect for USSD responses (reveals text progressively).
        private void ShowUssdResponseTyped(string text)
        {
            if (_txtUssdResp == null) return;
            if (_ussdTypeTimer != null) { _ussdTypeTimer.Stop(); _ussdTypeTimer = null; }
            _ussdTypeTarget = text ?? "";
            _ussdTypeIdx = 0;
            _txtUssdResp.Text = "";
            if (_ussdTypeTarget.Length == 0) return;
            _ussdTypeTimer = new DispatcherTimer();
            _ussdTypeTimer.Interval = TimeSpan.FromMilliseconds(18);
            _ussdTypeTimer.Tick += UssdTypeTick;
            _ussdTypeTimer.Start();
        }

        private void UssdTypeTick(object sender, EventArgs e)
        {
            if (_ussdTypeTarget == null || _txtUssdResp == null) { if (_ussdTypeTimer != null) _ussdTypeTimer.Stop(); return; }
            int step = 3;
            _ussdTypeIdx = Math.Min(_ussdTypeTarget.Length, _ussdTypeIdx + step);
            _txtUssdResp.Text = _ussdTypeTarget.Substring(0, _ussdTypeIdx);
            if (_ussdTypeIdx >= _ussdTypeTarget.Length && _ussdTypeTimer != null)
            {
                _ussdTypeTimer.Stop();
                _ussdTypeTimer = null;
            }
        }

        // Breathing highlight for the call-state text while a call is active.
        private void StartCallBreath()
        {
            if (_callStateText == null) return;
            DoubleAnimation breath = new DoubleAnimation
            {
                From = 1.0,
                To = 0.55,
                Duration = TimeSpan.FromMilliseconds(750),
                AutoReverse = true,
                RepeatBehavior = RepeatBehavior.Forever
            };
            _callStateText.BeginAnimation(UIElement.OpacityProperty, breath);
        }

        private void StopCallBreath()
        {
            if (_callStateText == null) return;
            _callStateText.BeginAnimation(UIElement.OpacityProperty, null);
            _callStateText.Opacity = 1.0;
        }

        // ---------- in-call audio overlay ----------
        // Full-card overlay that hides the dialer while a call is live. Shows a
        // pulsing avatar, the peer, state, running timer and mute/keypad/end.
        // Answer/Decline appear only for incoming calls.
        private void BuildCallOverlay(Grid host)
        {
            _callOverlay = new Grid { Visibility = Visibility.Collapsed };

            LinearGradientBrush bg = new LinearGradientBrush();
            bg.StartPoint = new Point(0, 0);
            bg.EndPoint = new Point(1, 1);
            bg.GradientStops.Add(new GradientStop((Color)ColorConverter.ConvertFromString("#141428"), 0.0));
            bg.GradientStops.Add(new GradientStop((Color)ColorConverter.ConvertFromString("#1E1A3A"), 0.55));
            bg.GradientStops.Add(new GradientStop((Color)ColorConverter.ConvertFromString("#241633"), 1.0));
            _callOverlay.Background = bg;

            StackPanel center = new StackPanel { HorizontalAlignment = HorizontalAlignment.Center, VerticalAlignment = VerticalAlignment.Center };

            // pulsing avatar: a ring Ellipse behind a solid disk with initials
            Grid avatar = new Grid { Width = 132, Height = 132, HorizontalAlignment = HorizontalAlignment.Center };
            _avatarRing = new System.Windows.Shapes.Ellipse
            {
                Stroke = BrushAccent,
                StrokeThickness = 2.5,
                Opacity = 0.5,
                HorizontalAlignment = HorizontalAlignment.Center,
                VerticalAlignment = VerticalAlignment.Center
            };
            avatar.Children.Add(_avatarRing);
            _avatarBorder = new Border
            {
                Width = 104,
                Height = 104,
                CornerRadius = new CornerRadius(52),
                Background = BrushAccent,
                HorizontalAlignment = HorizontalAlignment.Center,
                VerticalAlignment = VerticalAlignment.Center
            };
            _avatarBorder.Child = new TextBlock
            {
                Text = "?",
                Foreground = Brushes.White,
                FontSize = 40,
                FontWeight = FontWeights.Bold,
                HorizontalAlignment = HorizontalAlignment.Center,
                VerticalAlignment = VerticalAlignment.Center
            };
            avatar.Children.Add(_avatarBorder);
            center.Children.Add(avatar);

            _ovPeer = new TextBlock
            {
                Text = "",
                // fixed light colors: the overlay has a dark gradient in both
                // themes, so theme brushes (dark text) would be unreadable
                Foreground = Brushes.White,
                FontSize = 24,
                FontWeight = FontWeights.Bold,
                HorizontalAlignment = HorizontalAlignment.Center,
                Margin = new Thickness(0, 22, 0, 0)
            };
            center.Children.Add(_ovPeer);

            _ovState = new TextBlock
            {
                Text = "",
                Foreground = Brushes.Gainsboro,
                FontSize = 14,
                HorizontalAlignment = HorizontalAlignment.Center,
                Margin = new Thickness(0, 6, 0, 0)
            };
            center.Children.Add(_ovState);

            _ovTimer = new TextBlock
            {
                Text = "00:00",
                Foreground = BrushAccent,
                FontSize = 34,
                FontWeight = FontWeights.Bold,
                FontFamily = new FontFamily("Consolas"),
                HorizontalAlignment = HorizontalAlignment.Center,
                Margin = new Thickness(0, 10, 0, 0)
            };
            center.Children.Add(_ovTimer);

            // action buttons row (mute / keypad / end, plus answer/decline)
            StackPanel btns = new StackPanel { Orientation = Orientation.Horizontal, HorizontalAlignment = HorizontalAlignment.Center, Margin = new Thickness(0, 30, 0, 0) };
            _ovBtnAnswer = MakeOverlayButton("Answer", Theme.Success, Brushes.White);
            _ovBtnAnswer.Click += delegate { AcceptVoipIncoming(); UpdateCallOverlay(); };
            _ovBtnDecline = MakeOverlayButton("Decline", Theme.Danger, Brushes.White);
            _ovBtnDecline.Click += delegate { RejectVoipIncoming(); UpdateCallOverlay(); };
            _ovBtnMute = MakeOverlayButton("Mute", Theme.Panel, BrushFg);
            _ovBtnMute.Click += delegate { ToggleMicMute(); SyncOverlayMute(); };
            _ovBtnKeypad = MakeOverlayButton("Keypad", Theme.Panel, BrushFg);
            _ovBtnKeypad.Click += delegate { ToggleOverlayKeypad(); };
            _ovBtnEnd = MakeOverlayButton("End", Theme.Danger, Brushes.White);
            _ovBtnEnd.Click += delegate { EndOverlayCall(); };

            btns.Children.Add(_ovBtnAnswer);
            btns.Children.Add(_ovBtnDecline);
            btns.Children.Add(_ovBtnMute);
            btns.Children.Add(_ovBtnKeypad);
            btns.Children.Add(_ovBtnEnd);
            center.Children.Add(btns);

            _callOverlay.Children.Add(center);
            Grid.SetRow(_callOverlay, 0);
            Grid.SetColumn(_callOverlay, 0);
            Grid.SetRowSpan(_callOverlay, 2);
            Grid.SetColumnSpan(_callOverlay, 2);
            host.Children.Add(_callOverlay);
        }

        private static Button MakeOverlayButton(string text, Brush bg, Brush fg)
        {
            Button b = new Button
            {
                Content = text,
                Background = bg,
                Foreground = fg,
                FontWeight = FontWeights.SemiBold,
                Padding = new Thickness(18, 10, 18, 10),
                Margin = new Thickness(5),
                Cursor = Cursors.Hand
            };
            WireButtonEffects(b);
            return b;
        }

        // Single entry point: reflect current SIM + VoIP state onto the overlay.
        // Shows the overlay whenever a call is live (dialing/ringing/active) and
        // hides it when both the modem and VoIP are idle.
        private void UpdateCallOverlay()
        {
            if (_callOverlay == null) return;
            bool simLive = _call != CallState.Idle;
            bool voipLive = _voip != null && _voip.InCall;
            bool voipRinging = _voipRinging;

            if (!simLive && !voipLive && !voipRinging)
            {
                _callOverlay.Visibility = Visibility.Collapsed;
                StopAvatarPulse();
                return;
            }

            _callOverlay.Visibility = Visibility.Visible;

            string peer, state;
            bool incoming;
            if (simLive)
            {
                peer = string.IsNullOrEmpty(_peer) ? "Unknown" : _peer;
                state = _call == CallState.Active ? "On call" : (_call == CallState.Ringing ? "Incoming call" : "Calling...");
                incoming = _call == CallState.Ringing;
            }
            else
            {
                peer = string.IsNullOrEmpty(_voipPeerName) ? "Unknown" : _voipPeerName;
                if (voipRinging) state = "Incoming call";
                else
                {
                    // use the service's own state when it has one
                    // ("Calling...", "Ringing on remote side...", "VoIP call (E2E encrypted)")
                    string svc = _voipStateText != null ? _voipStateText.Text : null;
                    if (!string.IsNullOrEmpty(svc) && svc != "Idle") state = svc;
                    else state = voipLive ? "On call" : "Calling...";
                }
                incoming = voipRinging;
            }

            _ovPeer.Text = peer;
            _ovState.Text = state;
            SetAvatarInitials(peer);

            bool answerMode = incoming;
            _ovBtnAnswer.Visibility = answerMode ? Visibility.Visible : Visibility.Collapsed;
            _ovBtnDecline.Visibility = answerMode ? Visibility.Visible : Visibility.Collapsed;
            _ovBtnMute.Visibility = answerMode ? Visibility.Collapsed : Visibility.Visible;
            _ovBtnKeypad.Visibility = answerMode ? Visibility.Collapsed : Visibility.Visible;
            // incoming: Decline is the way out - a second End would be ambiguous
            _ovBtnEnd.Visibility = answerMode ? Visibility.Collapsed : Visibility.Visible;

            StartAvatarPulse();
        }

        private void SetAvatarInitials(string name)
        {
            if (_avatarBorder == null) return;
            string initials = "?";
            if (!string.IsNullOrEmpty(name))
            {
                string clean = name.Trim();
                if (clean.Length > 0 && char.IsDigit(clean[0])) initials = clean.Substring(0, Math.Min(2, clean.Length));
                else
                {
                    string[] parts = clean.Split(new char[] { ' ', '.', '-', '_' }, StringSplitOptions.RemoveEmptyEntries);
                    if (parts.Length >= 2) initials = ("" + parts[0][0] + parts[1][0]).ToUpperInvariant();
                    else if (parts.Length == 1 && parts[0].Length > 0) initials = parts[0].Substring(0, Math.Min(2, parts[0].Length)).ToUpperInvariant();
                }
            }
            TextBlock tb = _avatarBorder.Child as TextBlock;
            if (tb != null) tb.Text = initials;
        }

        private void StartAvatarPulse()
        {
            if (_avatarRing == null) return;
            if (_avatarRing.RenderTransform is ScaleTransform && _avatarRing.Tag as string == "pulsing") return;
            ScaleTransform st = new ScaleTransform(1, 1);
            _avatarRing.RenderTransform = st;
            _avatarRing.RenderTransformOrigin = new Point(0.5, 0.5);
            _avatarRing.Tag = "pulsing";
            DoubleAnimation grow = new DoubleAnimation(1.0, 1.22, TimeSpan.FromMilliseconds(900));
            grow.AutoReverse = true;
            grow.RepeatBehavior = RepeatBehavior.Forever;
            grow.EasingFunction = new SineEase { EasingMode = EasingMode.EaseInOut };
            _avatarRing.BeginAnimation(UIElement.RenderTransformProperty, null);
            st.BeginAnimation(ScaleTransform.ScaleXProperty, grow);
            st.BeginAnimation(ScaleTransform.ScaleYProperty, grow.Clone());
        }

        private void StopAvatarPulse()
        {
            if (_avatarRing == null) return;
            _avatarRing.Tag = null;
            ScaleTransform st = _avatarRing.RenderTransform as ScaleTransform;
            if (st != null)
            {
                st.BeginAnimation(ScaleTransform.ScaleXProperty, null);
                st.BeginAnimation(ScaleTransform.ScaleYProperty, null);
                st.ScaleX = 1.0; st.ScaleY = 1.0;
            }
        }

        // Mirror mic-mute onto the overlay button label + colour.
        private void SyncOverlayMute()
        {
            if (_ovBtnMute == null) return;
            _ovBtnMute.Content = _micMuted ? "Unmute" : "Mute";
            _ovBtnMute.Background = _micMuted ? Theme.Danger : Theme.Panel;
            _ovBtnMute.Foreground = _micMuted ? Brushes.White : BrushFg;
        }

        // A compact 3x4 DTMF pad that drops over the overlay while in a call.
        private void ToggleOverlayKeypad()
        {
            if (_callOverlay == null) return;
            if (_ovKeypadOpen)
            {
                for (int i = _callOverlay.Children.Count - 1; i >= 0; i--)
                    if (_callOverlay.Children[i] is Grid && ((Grid)_callOverlay.Children[i]).Tag as string == "ovpad")
                        _callOverlay.Children.RemoveAt(i);
                _ovKeypadOpen = false;
                return;
            }
            Grid pad = new Grid { Tag = "ovpad" };
            for (int i = 0; i < 4; i++) pad.RowDefinitions.Add(new RowDefinition { Height = new GridLength(62) });
            for (int i = 0; i < 3; i++) pad.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            pad.Width = 210;
            pad.HorizontalAlignment = HorizontalAlignment.Center;
            pad.VerticalAlignment = VerticalAlignment.Bottom;
            pad.Margin = new Thickness(0, 0, 0, 18);
            string[] keys = new string[] { "1", "2", "3", "4", "5", "6", "7", "8", "9", "*", "0", "#" };
            for (int i = 0; i < keys.Length; i++)
            {
                Button k = new Button
                {
                    Content = keys[i],
                    Background = Theme.Panel,
                    Foreground = BrushFg,
                    FontSize = 20,
                    Margin = new Thickness(3),
                    Cursor = Cursors.Hand
                };
                WireButtonEffects(k);
                string digit = keys[i];
                k.Click += delegate { KeyPress(digit); };
                Grid.SetRow(k, i / 3);
                Grid.SetColumn(k, i % 3);
                pad.Children.Add(k);
            }
            _callOverlay.Children.Add(pad);
            _ovKeypadOpen = true;
        }

        // Route End to whichever call is live (SIM first, then VoIP).
        private void EndOverlayCall()
        {
            if (_call != CallState.Idle) { var t = EndCallAsync(); return; }
            if (_voip != null && _voip.InCall) { HangupVoip(); return; }
            if (_voipRinging) { RejectVoipIncoming(); }
        }

        // Slide-in / fade for a UI element (page transitions, chips).
        private static void AnimateSlideIn(UIElement el)
        {
            if (el == null) return;
            TranslateTransform tt = new TranslateTransform(-24, 0);
            el.RenderTransform = tt;
            DoubleAnimation slide = new DoubleAnimation(0, TimeSpan.FromMilliseconds(240));
            slide.EasingFunction = new QuadraticEase { EasingMode = EasingMode.EaseOut };
            DoubleAnimation fade = new DoubleAnimation(0, 1, TimeSpan.FromMilliseconds(260));
            Storyboard sb = new Storyboard();
            sb.Children.Add(slide);
            sb.Children.Add(fade);
            Storyboard.SetTarget(slide, el);
            Storyboard.SetTarget(fade, el);
            Storyboard.SetTargetProperty(slide, new PropertyPath("(UIElement.RenderTransform).(TranslateTransform.X)"));
            Storyboard.SetTargetProperty(fade, new PropertyPath(UIElement.OpacityProperty));
            sb.Begin();
        }

        // ---------- UI helpers ----------
        private static GroupBox MakeGroup(string header)
        {
            GroupBox gb = new GroupBox
            {
                Foreground = BrushAccent,
                FontWeight = FontWeights.SemiBold,
                FontSize = 12.5,
                BorderBrush = BrushBorder,
                BorderThickness = new Thickness(1),
                Background = Theme.Chrome,
                Margin = new Thickness(8, 5, 8, 5),
                Padding = new Thickness(8, 6, 8, 7)
            };
            gb.Header = header;
            return gb;
        }

        private static Label MakeLabel(string text)
        {
            return new Label { Content = text, Foreground = BrushFg, Padding = new Thickness(4, 2, 4, 2) };
        }

        // Rounded status pill used in the header.
        private static Border MakePill(TextBlock inner, Brush bg)
        {
            inner.Margin = new Thickness(0, 0, 0, 0);
            Border b = new Border
            {
                Background = bg,
                CornerRadius = new CornerRadius(11),
                Padding = new Thickness(11, 4, 11, 4),
                Margin = new Thickness(6, 0, 0, 0),
                Child = inner,
                VerticalAlignment = VerticalAlignment.Center
            };
            return b;
        }

        private static FrameworkElement MakeTelemetrySep()
        {
            return new Border
            {
                Width = 1,
                Height = 14,
                Background = Theme.CardBorder,
                Margin = new Thickness(8, 0, 8, 0),
                VerticalAlignment = VerticalAlignment.Center
            };
        }

        private static FrameworkElement MakeTelemetryItem(string icon, TextBlock value)
        {
            StackPanel row = new StackPanel
            {
                Orientation = Orientation.Horizontal,
                VerticalAlignment = VerticalAlignment.Center
            };
            row.Children.Add(new TextBlock
            {
                Text = icon,
                FontSize = 12,
                Foreground = Theme.Subtle,
                VerticalAlignment = VerticalAlignment.Center,
                Margin = new Thickness(0, 0, 6, 0)
            });
            value.VerticalAlignment = VerticalAlignment.Center;
            row.Children.Add(value);
            return row;
        }

        private static TextBox MakeTextBox(double width)
        {
            // Surface colors come from the implicit TextBox style (theme tokens).
            TextBox t = new TextBox
            {
                VerticalContentAlignment = VerticalAlignment.Center
            };
            if (width > 0) t.Width = width;
            return t;
        }

        private static TextBox MakeMultiBox()
        {
            return new TextBox
            {
                AcceptsReturn = true,
                TextWrapping = TextWrapping.Wrap,
                VerticalScrollBarVisibility = ScrollBarVisibility.Auto
            };
        }

        private static Button MakeButton(string text)
        {
            // Look (rounded card, hover/press) comes from the implicit Button style.
            Button b = new Button
            {
                Content = text,
                Padding = new Thickness(10, 5, 10, 5),
                Cursor = Cursors.Hand,
                FontFamily = new FontFamily("Segoe UI")
            };
            WireButtonEffects(b);
            return b;
        }

        private static Button MakeStyledButton(string text, string styleKey)
        {
            Button b = MakeButton(text);
            Style s = TryStyle(styleKey);
            if (s != null) b.Style = s;
            return b;
        }

        // Press feedback (scale down while held) + dim when disabled.
        // For buttons built without MakeButton (keypad, etc).
        private static void WireButtonEffects(Button b)
        {
            ScaleTransform st = new ScaleTransform(1, 1);
            b.RenderTransform = st;
            b.RenderTransformOrigin = new Point(0.5, 0.5);
            b.MouseLeftButtonDown += delegate { AnimateButtonScale(b, 0.96); };
            b.MouseLeftButtonUp += delegate { AnimateButtonScale(b, 1.0); };
            b.MouseLeave += delegate { AnimateButtonScale(b, 1.0); };
            b.IsEnabledChanged += delegate { b.Opacity = b.IsEnabled ? 1.0 : 0.45; };
        }

        private static void AnimateButtonScale(FrameworkElement el, double to)
        {
            ScaleTransform st = el.RenderTransform as ScaleTransform;
            if (st == null) return;
            DoubleAnimation a = new DoubleAnimation(to, TimeSpan.FromMilliseconds(80));
            st.BeginAnimation(ScaleTransform.ScaleXProperty, a);
            st.BeginAnimation(ScaleTransform.ScaleYProperty, a);
        }

        private static TextBlock MakeVal()
        {
            return new TextBlock { Foreground = BrushFg, TextWrapping = TextWrapping.Wrap, Margin = new Thickness(4, 2, 12, 2) };
        }

        private static TextBlock MakeKey(string text)
        {
            return new TextBlock { Text = text, Foreground = BrushGray, FontWeight = FontWeights.Bold, Margin = new Thickness(4, 2, 4, 2) };
        }

        private static ListView MakeListView()
        {
            // Surface colors come from the implicit ListView style (theme tokens).
            ListView lv = new ListView();
            // Let wide GridView columns scroll horizontally instead of clipping.
            ScrollViewer.SetHorizontalScrollBarVisibility(lv, ScrollBarVisibility.Auto);
            return lv;
        }

        // One rounded card per page: Border -> ScrollViewer -> page grid.
        // Keeps every page inside the window (vertical scroll, never clipped).
        private static Border MakePageCard(Grid content, bool visible)
        {
            return MakePageCard(content, visible, true);
        }

        // The chat hub fills the viewport and scrolls its own panes; it must not
        // sit inside the page scroller (that made focus scroll the whole page).
        private static Border MakePageCard(Grid content, bool visible, bool pageScroll)
        {
            ScrollViewer sv = new ScrollViewer
            {
                VerticalScrollBarVisibility = pageScroll ? ScrollBarVisibility.Auto : ScrollBarVisibility.Disabled,
                HorizontalScrollBarVisibility = ScrollBarVisibility.Disabled,
                Background = Brushes.Transparent,
                Focusable = false
            };
            sv.Content = content;
            Border card = new Border
            {
                Background = Theme.Card,
                BorderBrush = Theme.CardBorder,
                BorderThickness = new Thickness(1),
                CornerRadius = new CornerRadius(18),
                Padding = new Thickness(10),
                Margin = new Thickness(8),
                // Never let overflow (e.g. a very short window) draw outside the
                // card - the chat composer must stay inside the pane.
                ClipToBounds = true,
                Visibility = visible ? Visibility.Visible : Visibility.Collapsed,
                Child = sv
            };
            try
            {
                card.Effect = System.Windows.Application.Current != null
                    ? System.Windows.Application.Current.TryFindResource("CardShadow") as System.Windows.Media.Effects.Effect
                    : null;
            }
            catch { }
            return card;
        }

        // ---------- UI construction ----------
        private void BuildUi()
        {
            Grid root = new Grid { Background = BrushBg };
            root.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });   // row 0: header
            root.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) }); // row 1: body
            root.RowDefinitions.Add(new RowDefinition { Height = new GridLength(0) });  // row 2: log (collapsed by default)
            root.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });   // row 3: status bar
            Content = root;

            // ---------- Header bar: [hamburger][logo][title] ... [SIM][COM][gear] ----------
            Border header = new Border
            {
                Background = Theme.Panel,
                BorderBrush = Theme.CardBorder,
                BorderThickness = new Thickness(0, 0, 0, 1),
                Padding = new Thickness(16, 10, 16, 10),
                MinHeight = 76
            };
            DockPanel hd = new DockPanel { LastChildFill = false };
            _btnMenu = MakeButton("\u2261");
            _btnMenu.FontSize = 16;
            _btnMenu.Padding = new Thickness(10, 2, 10, 2);
            _btnMenu.ToolTip = "Open / close navigation sidebar";
            DockPanel.SetDock(_btnMenu, Dock.Left);
            _btnMenu.Click += delegate { ToggleSidebar(); };
            hd.Children.Add(_btnMenu);

            // animated logo (blue tile + pulsing signal waves + chat bubble)
            FrameworkElement logo = CreateAnimatedLogo();
            DockPanel.SetDock(logo, Dock.Left);
            hd.Children.Add(logo);

            StackPanel titleBlock = new StackPanel
            {
                Orientation = Orientation.Vertical,
                VerticalAlignment = VerticalAlignment.Center,
                Margin = new Thickness(4, 0, 0, 0)
            };
            titleBlock.Children.Add(new TextBlock
            {
                Text = "USSD MANAGER PRO",
                FontSize = 10,
                FontWeight = FontWeights.Bold,
                Foreground = BrushAccent,
                Margin = new Thickness(0, 0, 0, 1)
            });
            _shellPageTitle = new TextBlock
            {
                Text = "Dialer",
                FontSize = 18,
                FontWeight = FontWeights.SemiBold,
                Foreground = BrushFg
            };
            titleBlock.Children.Add(_shellPageTitle);
            _shellPageDescription = new TextBlock
            {
                Text = "Cellular and internet calling",
                FontSize = 11,
                Foreground = BrushGray
            };
            titleBlock.Children.Add(_shellPageDescription);
            DockPanel.SetDock(titleBlock, Dock.Left);
            _liveDot = new System.Windows.Shapes.Ellipse
            {
                Width = 8,
                Height = 8,
                Fill = BrushRed,
                VerticalAlignment = VerticalAlignment.Center,
                Margin = new Thickness(8, 0, 0, 0)
            };
            DockPanel.SetDock(_liveDot, Dock.Left);

            // Right side is docked first-to-rightmost: gear ends up at the far edge.
            Button btnGear = MakeButton("\u2699");
            btnGear.FontSize = 15;
            btnGear.Padding = new Thickness(10, 2, 10, 2);
            btnGear.ToolTip = "Open Settings";
            DockPanel.SetDock(btnGear, Dock.Right);
            btnGear.Click += delegate { ShowSettingsDialog(); };
            hd.Children.Add(btnGear);

            _pillCom = new TextBlock
            {
                Text = "COM: -",
                Foreground = BrushGray,
                VerticalAlignment = VerticalAlignment.Center
            };
            Button pillComBtn = new Button
            {
                Content = MakeTelemetryItem("\uD83D\uDD0C", _pillCom),
                Background = Brushes.Transparent,
                BorderThickness = new Thickness(0),
                Cursor = Cursors.Hand,
                ToolTip = "Click to open Modem Setup (port, baud, connect)",
                Padding = new Thickness(4, 0, 4, 0)
            };
            Style ghostCom = TryStyle("GhostButton");
            if (ghostCom != null) pillComBtn.Style = ghostCom;
            pillComBtn.BorderThickness = new Thickness(0);
            pillComBtn.Click += delegate { ShowModemSetupPopover(pillComBtn); };

            _sigText = new TextBlock
            {
                Text = "signal --",
                Foreground = BrushGray,
                VerticalAlignment = VerticalAlignment.Center
            };
            _status = new TextBlock
            {
                Text = "Disconnected",
                FontWeight = FontWeights.Bold,
                Foreground = BrushError,
                VerticalAlignment = VerticalAlignment.Center
            };
            TextBlock simPillText = new TextBlock
            {
                Text = "no SIM",
                Foreground = BrushGray,
                VerticalAlignment = VerticalAlignment.Center
            };
            _simPillText = simPillText;

            StackPanel telemetryRow = new StackPanel
            {
                Orientation = Orientation.Horizontal,
                VerticalAlignment = VerticalAlignment.Center
            };
            telemetryRow.Children.Add(MakeTelemetryItem("\uD83D\uDCF1", simPillText));
            telemetryRow.Children.Add(MakeTelemetrySep());
            telemetryRow.Children.Add(MakeTelemetryItem("\uD83D\uDCF6", _sigText));
            telemetryRow.Children.Add(MakeTelemetrySep());
            telemetryRow.Children.Add(MakeTelemetryItem("\u25CF", _status));
            telemetryRow.Children.Add(MakeTelemetrySep());
            telemetryRow.Children.Add(pillComBtn);
            Border telemetryCluster = new Border
            {
                Background = Theme.Pill,
                BorderBrush = Theme.CardBorder,
                BorderThickness = new Thickness(1),
                CornerRadius = new CornerRadius(16),
                Padding = new Thickness(10, 4, 8, 4),
                Margin = new Thickness(6, 0, 8, 0),
                VerticalAlignment = VerticalAlignment.Center,
                Child = telemetryRow
            };
            DockPanel.SetDock(telemetryCluster, Dock.Right);

            hd.Children.Add(titleBlock);
            hd.Children.Add(_liveDot);
            hd.Children.Add(telemetryCluster);
            header.Child = hd;
            Grid.SetRow(header, 0);
            root.Children.Add(header);

            // ---- Modem Setup controls (hidden; surfaced via COM-pill popover) ----
            // These are NOT added to the visual tree here; they are placed inside
            // the ModemSetupPopover that opens when the user clicks the COM pill.
            _comboBaud = new ComboBox { Width = 86 };
            foreach (string b in new[] { "9600", "19200", "38400", "57600", "115200", "230400" }) _comboBaud.Items.Add(b);
            _comboBaud.SelectedItem = "115200";
            _comboBaud.SelectionChanged += delegate { UpdateComPill(); };

            _comboPort = new ComboBox { Width = 220 };
            _comboPort.SelectionChanged += delegate { UpdateComPill(); };

            _chkAuto = new CheckBox { Content = "Auto-connect", IsChecked = false, VerticalAlignment = VerticalAlignment.Center };

            _simSummary = new TextBlock { Text = "no SIM", Foreground = BrushGray, VerticalAlignment = VerticalAlignment.Center };

            _btnConnect = MakeButton("Connect");
            Style successStyle = TryStyle("SuccessButton");
            if (successStyle != null) _btnConnect.Style = successStyle;
            _btnConnect.Click += async delegate { await ToggleConnectAsync(); };

            Button btnRefresh = MakeButton("Refresh");
            btnRefresh.Click += delegate { RefreshPorts(); };

            UpdateComPill();

            // ---------- Sidebar + content pages ----------
            Grid body = new Grid();
            body.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(252) });
            body.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            _sidebarCol = body.ColumnDefinitions[0];

            _sidebar = new Border
            {
                Background = Theme.Panel,
                BorderBrush = Theme.CardBorder,
                BorderThickness = new Thickness(0, 0, 1, 0),
                Padding = new Thickness(10, 12, 10, 10)
            };
            Grid sidebarLayout = new Grid();
            sidebarLayout.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            sidebarLayout.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) });
            sidebarLayout.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            StackPanel sidebarHeading = new StackPanel { Margin = new Thickness(8, 2, 8, 18) };
            sidebarHeading.Children.Add(new TextBlock
            {
                Text = "YOUR WORKSPACE",
                Foreground = BrushAccent,
                FontWeight = FontWeights.Bold,
                FontSize = 10,
                Margin = new Thickness(0, 0, 0, 4)
            });
            sidebarHeading.Children.Add(new TextBlock
            {
                Text = "Communication, made simple.",
                Foreground = BrushGray,
                FontSize = 11,
                TextWrapping = TextWrapping.Wrap
            });
            Grid.SetRow(sidebarHeading, 0);
            sidebarLayout.Children.Add(sidebarHeading);
            _sidebarHeading = sidebarHeading;

            StackPanel nav = new StackPanel();
            Grid.SetRow(nav, 1);
            sidebarLayout.Children.Add(nav);

            Border modemCard = new Border
            {
                Background = Theme.Chrome,
                BorderBrush = Theme.CardBorder,
                BorderThickness = new Thickness(1),
                CornerRadius = new CornerRadius(14),
                Padding = new Thickness(12),
                Margin = new Thickness(2, 12, 2, 2)
            };
            StackPanel modemInfo = new StackPanel();
            modemInfo.Children.Add(new TextBlock
            {
                Text = "MODEM CONNECTION",
                FontSize = 10,
                FontWeight = FontWeights.Bold,
                Foreground = BrushGray,
                Margin = new Thickness(0, 0, 0, 5)
            });
            modemInfo.Children.Add(new TextBlock
            {
                Text = "Connect only when you're ready.",
                FontSize = 11,
                Foreground = BrushFg,
                TextWrapping = TextWrapping.Wrap,
                Margin = new Thickness(0, 0, 0, 8)
            });
            Button configureModem = MakeButton("Configure modem");
            configureModem.HorizontalContentAlignment = HorizontalAlignment.Center;
            configureModem.Click += delegate { ShowModemSetupPopover(pillComBtn); };
            modemInfo.Children.Add(configureModem);
            modemCard.Child = modemInfo;
            Grid.SetRow(modemCard, 2);
            sidebarLayout.Children.Add(modemCard);
            _sidebarFooter = modemCard;
            _sidebar.Child = sidebarLayout;
            Grid.SetColumn(_sidebar, 0);
            body.Children.Add(_sidebar);

            _contentHost = new Grid { Margin = new Thickness(4) };
            Grid.SetColumn(_contentHost, 1);
            body.Children.Add(_contentHost);

            // Page keys follow the spec nav (emoji via \uXXXX to keep source ASCII).
            string[] pageNames = new string[]
            {
                "\uD83D\uDCDE  Dialer",        // phone handset
                "\uD83D\uDC64  Contacts",      // bust silhouette
                "\uD83D\uDCF9  Video Call",    // video camera
                "\uD83D\uDCAC  SMS",           // speech balloon
                "\uD83D\uDCF1  SIM Manager",   // mobile phone (was ⚙, now distinct from Settings gear)
                "\u2708  USSD",                // airplane / send
                "\uD83D\uDCE6  Apps",            // application package
                "\uD83E\uDD16  Agent"          // assistant panel
            };
            Grid[] pageGrids = new Grid[]
            {
                BuildDialerTab(), BuildContactsTab(), BuildVideoTab(), BuildSmsTab(), BuildSimTab(), BuildUssdTab(), BuildAppsTab(), BuildAgentTab()
            };
            string[] pageIcons = new string[]
            {
                "\uD83D\uDCDE", "\uD83D\uDC64", "\uD83D\uDCF9", "\uD83D\uDCAC",
                "\uD83D\uDCF1", "\u2708", "\uD83D\uDCE6", "\uD83E\uDD16"
            };
            string[] pageDescriptions = new string[]
            {
                "Cellular and internet calling", "Manage saved contacts", "Voice and video rooms",
                "Messages and secure chat", "SIM information and tools", "Run carrier USSD codes",
                "Open your companion apps", "Your local and AI assistant"
            };
            string[] pageLabels = new string[]
            {
                "Dialer", "Contacts", "Video Call", "SMS",
                "SIM Manager", "USSD", "Apps", "Agent"
            };
            for (int i = 0; i < pageGrids.Length; i++)
            {
                if (i == 0 || i == 4 || i == 7)
                {
                    string sectionName = i == 0 ? "COMMUNICATION" : (i == 4 ? "DEVICE TOOLS" : "ASSISTANT");
                    TextBlock sectionLabel = new TextBlock
                    {
                        Text = sectionName,
                        Foreground = BrushGray,
                        FontWeight = FontWeights.Bold,
                        FontSize = 10,
                        Margin = new Thickness(8, i == 0 ? 2 : 14, 4, 5)
                    };
                    nav.Children.Add(sectionLabel);
                    _navSectionLabels.Add(sectionLabel);
                }
                Border card = MakePageCard(pageGrids[i], i == 0, i != 3 && i != 6 && i != 7);
                _pages.Add(card);
                _pageNames.Add(pageNames[i]);
                _pageIcons.Add(pageIcons[i]);
                _pageLabels.Add(pageLabels[i]);
                _pageDescriptions.Add(pageDescriptions[i]);
                _contentHost.Children.Add(card);

                Button navBtn = MakeButton(pageNames[i]);
                Style navStyle = TryStyle("NavItem");
                if (navStyle != null) navBtn.Style = navStyle;
                navBtn.Margin = new Thickness(0, 2, 0, 2);
                navBtn.MinHeight = 44;
                navBtn.ToolTip = pageLabels[i];
                System.Windows.Automation.AutomationProperties.SetName(navBtn, pageLabels[i]);
                System.Windows.Automation.AutomationProperties.SetHelpText(navBtn, "Open " + pageLabels[i]);
                int idx = i;
                navBtn.Click += delegate { ShowPage(idx); };
                nav.Children.Add(navBtn);
                _navButtons.Add(navBtn);
            }
            _pageIndex = 0;
            UpdateShellPageHeading();
            HighlightNav();

            Grid.SetRow(body, 1);
            root.Children.Add(body);

            // Log drawer (collapsed by default; toggle is in status bar)
            // Use a plain Border instead of GroupBox to avoid the double-border artefact.
            Border logGroup = new Border
            {
                Background = Theme.Panel,
                BorderBrush = Theme.CardBorder,
                BorderThickness = new Thickness(0, 1, 0, 0)
            };
            DockPanel logOuter = new DockPanel();
            DockPanel logHead = new DockPanel
            {
                Background = Theme.Chrome,
                LastChildFill = false
            };
            logHead.SetValue(DockPanel.DockProperty, Dock.Top);
            TextBlock logTitle = new TextBlock
            {
                Text = "Live Log  \u2014  AT traffic · events · USSD · SMS · VoIP",
                Foreground = BrushAccent,
                FontWeight = FontWeights.SemiBold,
                VerticalAlignment = VerticalAlignment.Center,
                Padding = new Thickness(12, 5, 0, 5)
            };
            DockPanel.SetDock(logTitle, Dock.Left);
            CheckBox chkScroll = new CheckBox
            {
                Content = "auto-scroll",
                Foreground = BrushGray,
                IsChecked = true,
                VerticalAlignment = VerticalAlignment.Center,
                Margin = new Thickness(0, 0, 12, 0)
            };
            DockPanel.SetDock(chkScroll, Dock.Right);
            logHead.Children.Add(logTitle);
            logHead.Children.Add(chkScroll);
            _chkAutoScroll = chkScroll;
            _logBox = new RichTextBox
            {
                Background = BrushPanel,
                Foreground = BrushFg,
                BorderBrush = BrushBorder,
                FontFamily = new FontFamily("Consolas"),
                FontSize = 11,
                IsReadOnly = true,
                VerticalScrollBarVisibility = ScrollBarVisibility.Auto,
                Padding = new Thickness(4)
            };
            logOuter.Children.Add(logHead);
            logOuter.Children.Add(_logBox);
            logGroup.Child = logOuter;
            Grid.SetRow(logGroup, 2);
            root.Children.Add(logGroup);
            _logRow = root.RowDefinitions[2];

            // Status bar (port/country + log drawer toggle, right side)
            Border statusBar = new Border
            {
                Background = Theme.Panel,
                BorderBrush = Theme.CardBorder,
                BorderThickness = new Thickness(0, 1, 0, 0),
                Padding = new Thickness(12, 4, 12, 6)
            };
            DockPanel sd = new DockPanel { LastChildFill = false };
            StackPanel sp = new StackPanel { Orientation = Orientation.Horizontal };
            _sbPort = new TextBlock { Text = "port: -", Foreground = BrushGray, VerticalAlignment = VerticalAlignment.Center };
            _sbCarrier = new TextBlock { Text = "carrier: -", Foreground = BrushGray, VerticalAlignment = VerticalAlignment.Center, Margin = new Thickness(14, 0, 0, 0) };
            _sbMethod = new TextBlock { Text = "USSD via MiFi", Foreground = BrushGray, VerticalAlignment = VerticalAlignment.Center, Margin = new Thickness(14, 0, 0, 0) };
            sp.Children.Add(_sbPort);
            sp.Children.Add(_sbCarrier);
            sp.Children.Add(_sbMethod);
            DockPanel.SetDock(sp, Dock.Left);

            // Log starts collapsed; user can expand via the status-bar toggle.
            _logCollapsed = true;
            _btnLogToggle = MakeButton("Log \u25BC");
            _btnLogToggle.Padding = new Thickness(10, 2, 10, 2);
            _btnLogToggle.Margin = new Thickness(6, 0, 0, 0);
            _btnLogToggle.ToolTip = "Expand / collapse the live log drawer  [Ctrl+`]";
            _logBadge = new TextBlock
            {
                Text = "",
                Foreground = Brushes.White,
                FontSize = 9,
                FontWeight = FontWeights.Bold,
                VerticalAlignment = VerticalAlignment.Top,
                HorizontalAlignment = HorizontalAlignment.Right,
                Margin = new Thickness(0, -4, -6, 0),
                Visibility = Visibility.Collapsed
            };
            Grid logToggleGrid = new Grid();
            logToggleGrid.Children.Add(new TextBlock { Text = _logCollapsed ? "Log \u25BC" : "Log \u25B2", VerticalAlignment = VerticalAlignment.Center });
            logToggleGrid.Children.Add(_logBadge);
            _btnLogToggle.Content = logToggleGrid;
            _btnLogToggle.Click += delegate
            {
                _logCollapsed = !_logCollapsed;
                // update the arrow in the button content
                TextBlock tb2 = (logToggleGrid.Children.Count > 0) ? (logToggleGrid.Children[0] as TextBlock) : null;
                if (tb2 != null)
                    tb2.Text = _logCollapsed ? "Log \u25BC" : "Log \u25B2";
                if (_logBadge != null) _logBadge.Visibility = Visibility.Collapsed;
                _logUnread = 0;
                ApplyLogHeight();
            };
            DockPanel.SetDock(_btnLogToggle, Dock.Right);

            TextBlock version = new TextBlock
            {
                Text = "v4.0",
                Foreground = BrushGray,
                VerticalAlignment = VerticalAlignment.Center
            };
            Border verPill = MakePill(version, Theme.Pill);
            DockPanel.SetDock(verPill, Dock.Right);

            sd.Children.Add(sp);
            sd.Children.Add(verPill);
            sd.Children.Add(_btnLogToggle);
            statusBar.Child = sd;
            Grid.SetRow(statusBar, 3);
            root.Children.Add(statusBar);
        }

        // Style lookup helper (Application resources, null-safe before init).
        private static Style TryStyle(string key)
        {
            if (Application.Current == null) return null;
            return Application.Current.TryFindResource(key) as Style;
        }

        private static string TryRes(string key)
        {
            if (Application.Current == null) return "no-app";
            object o = Application.Current.TryFindResource(key);
            return o == null ? "MISSING" : o.ToString();
        }

        // Header "COM6 | 115200" pill, refreshed on port/baud changes.
        private void UpdateComPill()
        {
            if (_pillCom == null || _comboPort == null) return;
            string port = _comboPort.SelectedItem != null ? _comboPort.SelectedItem.ToString() : (_comboPort.Text ?? "");
            string baud = _comboBaud != null && _comboBaud.SelectedItem != null ? _comboBaud.SelectedItem.ToString() : "";
            if (string.IsNullOrEmpty(port)) _pillCom.Text = "COM: -";
            else _pillCom.Text = port + " | " + baud;
        }

        private Grid BuildAgentTab()
        {
            Grid g = new Grid { Margin = new Thickness(14, 10, 14, 10) };
            g.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            g.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) });

            StackPanel heading = new StackPanel { Margin = new Thickness(4, 0, 4, 10) };
            heading.Children.Add(new TextBlock
            {
                Text = "Agent panel",
                FontSize = 22,
                FontWeight = FontWeights.Bold,
                Foreground = BrushFg
            });
            heading.Children.Add(new TextBlock
            {
                Text = "Ask the configured AI assistant, use safe local navigation commands, or read a response aloud. Prompts are sent only when you click Send. Device tracking and permissions stay in Laptop Tracker.",
                TextWrapping = TextWrapping.Wrap,
                Foreground = BrushGray,
                Margin = new Thickness(0, 4, 0, 0)
            });
            CheckBox readReplies = new CheckBox
            {
                Content = "Read AI responses aloud",
                Foreground = BrushGray,
                IsChecked = false,
                Margin = new Thickness(4, 8, 4, 0),
                ToolTip = "Speech is local and starts only after you enable this option."
            };
            _agentSpeakReplies = readReplies;
            heading.Children.Add(readReplies);
            Grid.SetRow(heading, 0);
            g.Children.Add(heading);

            Grid chat = new Grid();
            chat.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) });
            chat.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });

            _agentTranscript = new StackPanel { Margin = new Thickness(4, 4, 4, 8) };
            _agentChatScroll = new ScrollViewer
            {
                VerticalScrollBarVisibility = ScrollBarVisibility.Auto,
                HorizontalScrollBarVisibility = ScrollBarVisibility.Disabled,
                Focusable = false
            };
            _agentChatScroll.Content = _agentTranscript;
            _agentStatus = new TextBlock
            {
                Text = "Ready. Configure the assistant in Settings > AI.",
                TextWrapping = TextWrapping.Wrap,
                Foreground = BrushGray,
                Margin = new Thickness(8, 8, 8, 8)
            };
            _agentTranscript.Children.Add(_agentStatus);

            _agentResponse = MakeMultiBox();
            _agentResponse.IsReadOnly = true;
            _agentResponse.Visibility = Visibility.Collapsed;
            _agentTranscript.Children.Add(_agentResponse);

            Border transcriptCard = MakeServiceCard(_agentChatScroll);
            transcriptCard.Margin = new Thickness(0, 0, 0, 8);
            transcriptCard.VerticalAlignment = VerticalAlignment.Stretch;
            Grid.SetRow(transcriptCard, 0);
            chat.Children.Add(transcriptCard);

            Grid composer = new Grid();
            composer.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            composer.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
            composer.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
            _agentPrompt = MakeMultiBox();
            _agentPrompt.Height = 72;
            _agentPrompt.MaxLength = 4000;
            _agentPrompt.AcceptsReturn = true;
            _agentPrompt.HorizontalAlignment = HorizontalAlignment.Stretch;
            _agentPrompt.VerticalAlignment = VerticalAlignment.Stretch;
            _agentPrompt.Margin = new Thickness(0, 0, 8, 0);
            _agentPrompt.PreviewKeyDown += AgentPromptKeyDown;
            Grid.SetColumn(_agentPrompt, 0);
            composer.Children.Add(_agentPrompt);

            Button speak = MakeButton("Read aloud");
            speak.Height = 40;
            speak.Margin = new Thickness(0, 0, 8, 0);
            speak.VerticalAlignment = VerticalAlignment.Bottom;
            speak.ToolTip = "Speak the latest assistant response using the local Windows voice.";
            speak.Click += delegate { SpeakAgentText(_agentLastResponse); };
            Grid.SetColumn(speak, 1);
            composer.Children.Add(speak);

            _agentAskButton = MakeStyledButton("Send  \u2191", "PrimaryButton");
            _agentAskButton.MinWidth = 96;
            _agentAskButton.Height = 40;
            _agentAskButton.VerticalAlignment = VerticalAlignment.Bottom;
            _agentAskButton.Click += async delegate { await RunAgentPromptAsync(); };
            Grid.SetColumn(_agentAskButton, 2);
            composer.Children.Add(_agentAskButton);

            Border composerCard = MakeServiceCard(composer);
            composerCard.Margin = new Thickness(0);
            Grid.SetRow(composerCard, 1);
            chat.Children.Add(composerCard);

            Grid.SetRow(chat, 1);
            g.Children.Add(chat);
            return g;
        }

        private void AgentPromptKeyDown(object sender, KeyEventArgs e)
        {
            if (e.Key != Key.Enter) return;
            if (Keyboard.Modifiers == ModifierKeys.Shift) return;
            e.Handled = true;
            if (_agentAskButton != null && _agentAskButton.IsEnabled)
                _agentAskButton.RaiseEvent(new RoutedEventArgs(ButtonBase.ClickEvent));
        }

        private void AppendAgentBubble(string text, bool fromUser)
        {
            if (_agentTranscript == null) return;
            Border bubble = new Border
            {
                Background = fromUser ? Theme.Accent : Theme.Chrome,
                BorderBrush = fromUser ? Theme.AccentHover : Theme.CardBorder,
                BorderThickness = new Thickness(1),
                CornerRadius = fromUser ? new CornerRadius(14, 14, 4, 14) : new CornerRadius(14, 14, 14, 4),
                Padding = new Thickness(12, 9, 12, 9),
                Margin = fromUser ? new Thickness(72, 4, 8, 4) : new Thickness(8, 4, 72, 4),
                HorizontalAlignment = fromUser ? HorizontalAlignment.Right : HorizontalAlignment.Left,
                MaxWidth = 760
            };
            bubble.Child = new TextBlock
            {
                Text = text ?? "",
                TextWrapping = TextWrapping.Wrap,
                Foreground = fromUser ? Brushes.White : BrushFg
            };
            _agentTranscript.Children.Add(bubble);
            if (_agentChatScroll != null) _agentChatScroll.ScrollToEnd();
        }

        private async Task RunAgentPromptAsync()
        {
            if (_agentPrompt == null || _agentAskButton == null) return;
            string prompt = (_agentPrompt.Text ?? "").Trim();
            if (prompt.Length == 0)
            {
                _agentStatus.Text = "Enter a question first.";
                return;
            }
            if (prompt.StartsWith("/agent", StringComparison.OrdinalIgnoreCase) &&
                (prompt.Length == 6 || char.IsWhiteSpace(prompt[6])))
            {
                string localResponse = RunLocalAgentCommand(prompt);
                _agentPrompt.Text = "";
                AppendAgentBubble(prompt, true);
                AppendAgentBubble(localResponse, false);
                _agentLastResponse = localResponse;
                _agentStatus.Text = "Local command completed. No prompt was sent to an AI provider.";
                if (_agentSpeakReplies.IsChecked == true) SpeakAgentText(localResponse);
                return;
            }
            if (!_aiEnabled || string.IsNullOrEmpty(_aiApiKey))
            {
                _agentStatus.Text = "Configure and enable the AI assistant in Settings > AI first.";
                ShowSettingsDialog();
                return;
            }

            _agentPrompt.Text = "";
            AppendAgentBubble(prompt, true);
            _agentAskButton.IsEnabled = false;
            _agentStatus.Text = "Sending your prompt to the configured AI provider...";
            try
            {
                string response = await Task.Run(delegate { return CallAiApi(prompt); });
                _agentResponse.Text = response;
                AppendAgentBubble(response, false);
                _agentLastResponse = response;
                _agentStatus.Text = "Response received. No device action was executed.";
                if (_agentSpeakReplies.IsChecked == true) SpeakAgentText(response);
            }
            catch (Exception ex)
            {
                _agentStatus.Text = "Assistant request failed: " + ex.Message;
                AppendAgentBubble("Assistant request failed: " + ex.Message, false);
                Log("Agent: " + ex.Message, BrushError);
            }
            finally
            {
                _agentAskButton.IsEnabled = true;
            }
        }

        private string RunLocalAgentCommand(string prompt)
        {
            string command = prompt.Length > 6 ? prompt.Substring(6).Trim() : "";
            int split = command.IndexOfAny(new char[] { ' ', '\t', '\r', '\n' });
            string verb = split < 0 ? command : command.Substring(0, split);
            string argument = split < 0 ? "" : command.Substring(split).Trim();
            if (string.Equals(verb, "help", StringComparison.OrdinalIgnoreCase) || verb.Length == 0)
                return "Local commands: /agent help, /agent status, /agent open apps, /agent open dialer, /agent open contacts, /agent open video, /agent open messages, /agent open sim, /agent open ussd, and /agent say <text>. Device operations require the Laptop Tracker app.";
            if (string.Equals(verb, "status", StringComparison.OrdinalIgnoreCase))
                return "USSD Manager is open. Modem status: " + (_status != null ? _status.Text : "unknown") +
                    ". Device controls remain in Laptop Tracker and were not triggered.";
            if (string.Equals(verb, "say", StringComparison.OrdinalIgnoreCase))
            {
                if (argument.Length == 0) return "Add text after /agent say. No speech was played.";
                if (argument.Length > 500) return "Speech is limited to 500 characters.";
                SpeakAgentText(argument);
                return "Spoke the text locally. No network request was made.";
            }
            if (string.Equals(verb, "open", StringComparison.OrdinalIgnoreCase))
            {
                int page = -1;
                if (string.Equals(argument, "apps", StringComparison.OrdinalIgnoreCase) ||
                    string.Equals(argument, "tracking", StringComparison.OrdinalIgnoreCase)) page = 6;
                else if (string.Equals(argument, "dialer", StringComparison.OrdinalIgnoreCase)) page = 0;
                else if (string.Equals(argument, "contacts", StringComparison.OrdinalIgnoreCase)) page = 1;
                else if (string.Equals(argument, "video", StringComparison.OrdinalIgnoreCase)) page = 2;
                else if (string.Equals(argument, "messages", StringComparison.OrdinalIgnoreCase) ||
                    string.Equals(argument, "sms", StringComparison.OrdinalIgnoreCase)) page = 3;
                else if (string.Equals(argument, "sim", StringComparison.OrdinalIgnoreCase)) page = 4;
                else if (string.Equals(argument, "ussd", StringComparison.OrdinalIgnoreCase)) page = 5;
                if (page >= 0)
                {
                    ShowPage(page);
                    return page == 6
                        ? "Opened Apps. " + (_appsStatus != null ? _appsStatus.Text : "Laptop Tracker was not launched.")
                        : "Opened " + _pageLabels[page] + ".";
                }
            }
            return "That command is not available. Use /agent help. No device action was run.";
        }

        private void SpeakAgentText(string text)
        {
            string value = (text ?? "").Trim();
            if (value.Length == 0)
            {
                if (_agentStatus != null) _agentStatus.Text = "There is no response to read aloud yet.";
                return;
            }
            try
            {
                if (_agentSpeech == null) _agentSpeech = new System.Speech.Synthesis.SpeechSynthesizer();
                _agentSpeech.SpeakAsyncCancelAll();
                _agentSpeech.SpeakAsync(value);
            }
            catch (Exception ex)
            {
                if (_agentStatus != null) _agentStatus.Text = "Local text-to-speech failed: " + ex.Message;
                Log("Agent speech failed: " + ex.Message, BrushError);
            }
        }

        private Grid BuildAppsTab()
        {
            Grid g = new Grid { Margin = new Thickness(18, 14, 18, 14) };
            g.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            g.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            g.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) });
            g.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });

            StackPanel heading = new StackPanel { Margin = new Thickness(4, 0, 4, 14) };
            heading.Children.Add(new TextBlock
            {
                Text = "Apps",
                FontSize = 24,
                FontWeight = FontWeights.Bold,
                Foreground = BrushFg
            });
            heading.Children.Add(new TextBlock
            {
                Text = "Use Laptop Tracker here as a full app panel. Its own sign-in, pairing, permissions, and privacy controls remain in effect.",
                TextWrapping = TextWrapping.Wrap,
                Foreground = BrushGray,
                Margin = new Thickness(0, 4, 0, 0)
            });
            Grid.SetRow(heading, 0);
            g.Children.Add(heading);

            _appsStatus = new TextBlock
            {
                Text = "Choose Laptop Tracker to start it inside this panel.",
                TextWrapping = TextWrapping.Wrap,
                Foreground = BrushGray,
                Margin = new Thickness(6, 0, 6, 8)
            };
            Grid.SetRow(_appsStatus, 1);
            g.Children.Add(_appsStatus);

            if (string.IsNullOrEmpty(_laptopTrackerExe))
                _laptopTrackerExe = AppConfig.Load().laptop_tracker_exe;
            Border trackerPanel = new Border
            {
                Background = BrushBg,
                BorderBrush = BrushBorder,
                BorderThickness = new Thickness(1),
                CornerRadius = new CornerRadius(10),
                ClipToBounds = true,
                MinHeight = 280
            };
            _laptopTrackerHost = new TrackerWindowHost();
            trackerPanel.Child = _laptopTrackerHost;
            Grid.SetRow(trackerPanel, 2);
            g.Children.Add(trackerPanel);

            WrapPanel actions = new WrapPanel
            {
                Margin = new Thickness(4, 10, 4, 8)
            };
            Button launch = MakeStyledButton("Open Laptop Tracker in panel", "PrimaryButton");
            launch.Margin = new Thickness(0, 0, 8, 0);
            launch.Click += delegate { LaunchLaptopTracker(); };
            actions.Children.Add(launch);
            Button browse = MakeButton("Choose app...");
            browse.Click += delegate
            {
                Microsoft.Win32.OpenFileDialog dialog = new Microsoft.Win32.OpenFileDialog
                {
                    Title = "Choose Laptop Tracker",
                    Filter = "Laptop Tracker executable (FIND-App.exe;FIND.exe)|FIND-App.exe;FIND.exe|Executable files (*.exe)|*.exe",
                    CheckFileExists = true,
                    Multiselect = false
                };
                if (dialog.ShowDialog(this) != true) return;
                _laptopTrackerExe = dialog.FileName;
                AppConfig config = AppConfig.Load();
                config.laptop_tracker_exe = _laptopTrackerExe;
                config.Save();
                _appsStatus.Text = "Laptop Tracker selected. Open it here when you are ready.";
            };
            actions.Children.Add(browse);
            Button showApk = MakeButton("Show Android APK");
            showApk.Margin = new Thickness(8, 0, 0, 0);
            showApk.Click += delegate { ChooseLaptopTrackerApkLocation(); };
            actions.Children.Add(showApk);
            Button launchCalls = MakeStyledButton("Open cross-platform calls", "PrimaryButton");
            launchCalls.Margin = new Thickness(8, 0, 0, 0);
            launchCalls.Click += delegate { LaunchCallsCompanion(); };
            actions.Children.Add(launchCalls);
            Button chooseCalls = MakeButton("Choose calls app...");
            chooseCalls.Margin = new Thickness(8, 0, 0, 0);
            chooseCalls.Click += delegate
            {
                Microsoft.Win32.OpenFileDialog dialog = new Microsoft.Win32.OpenFileDialog
                {
                    Title = "Choose USSD Manager Calls",
                    Filter = "USSD Manager Calls (USSDCalls.exe)|USSDCalls.exe|Executable files (*.exe)|*.exe",
                    CheckFileExists = true,
                    Multiselect = false
                };
                if (dialog.ShowDialog(this) != true) return;
                _callsCompanionExe = dialog.FileName;
                AppConfig config = AppConfig.Load();
                config.calls_companion_exe = _callsCompanionExe;
                config.Save();
                _appsStatus.Text = "Cross-platform call companion selected. Open it when you are ready.";
            };
            actions.Children.Add(chooseCalls);
            Grid.SetRow(actions, 3);
            g.Children.Add(actions);
            return g;
        }

        private void LaunchCallsCompanion()
        {
            try
            {
                if (_callsCompanionProcess != null && !_callsCompanionProcess.HasExited)
                {
                    _appsStatus.Text = "Cross-platform calls are already open in their companion window.";
                    return;
                }
                if (_callsCompanionProcess != null)
                {
                    _callsCompanionProcess.Dispose();
                    _callsCompanionProcess = null;
                }
                if (string.IsNullOrEmpty(_callsCompanionExe))
                    _callsCompanionExe = AppConfig.Load().calls_companion_exe;
                if (string.IsNullOrEmpty(_callsCompanionExe))
                    _callsCompanionExe = Path.Combine(AppDomain.CurrentDomain.BaseDirectory,
                        "USSDCalls", "USSDCalls.exe");
                if (!File.Exists(_callsCompanionExe))
                {
                    _appsStatus.Text = "USSD Manager Calls was not found. Install the complete Windows release ZIP or choose its executable.";
                    Log("Cross-platform calls companion is missing: " + _callsCompanionExe, BrushWarn);
                    return;
                }
                string path = Path.GetFullPath(_callsCompanionExe);
                _callsCompanionProcess = Process.Start(new ProcessStartInfo
                {
                    FileName = path,
                    WorkingDirectory = Path.GetDirectoryName(path),
                    UseShellExecute = false
                });
                if (_callsCompanionProcess == null)
                    throw new InvalidOperationException("Windows did not return a process for USSD Manager Calls.");
                AppConfig config = AppConfig.Load();
                config.calls_companion_exe = path;
                config.Save();
                _appsStatus.Text = "Cross-platform calls opened. Use the same calling service and invitation as your Android contact.";
                Log("Opened the LiveKit call companion.", BrushSuccess);
            }
            catch (Exception ex)
            {
                _appsStatus.Text = "Cross-platform calls could not be opened: " + ex.Message;
                Log("Cross-platform call companion launch failed: " + ex.Message, BrushError);
            }
        }

        private void LaunchLaptopTracker()
        {
            try
            {
                if (_laptopTrackerProcess != null && !_laptopTrackerProcess.HasExited)
                {
                    IntPtr existingWindow = _laptopTrackerProcess.MainWindowHandle;
                    if (existingWindow != IntPtr.Zero && _laptopTrackerHost != null &&
                        _laptopTrackerHost.AttachWindow(existingWindow))
                        _appsStatus.Text = "Laptop Tracker is open in this panel.";
                    else
                        _appsStatus.Text = "Laptop Tracker is already starting. Please try again in a moment.";
                    return;
                }
                if (_laptopTrackerProcess != null)
                {
                    _laptopTrackerProcess.Dispose();
                    _laptopTrackerProcess = null;
                }
                if (string.IsNullOrWhiteSpace(_laptopTrackerExe) || !File.Exists(_laptopTrackerExe))
                {
                    _appsStatus.Text = "Laptop Tracker was not found. Choose its executable, then open it again.";
                    Log("Laptop Tracker executable is missing: " + (_laptopTrackerExe ?? ""), BrushWarn);
                    return;
                }
                string path = Path.GetFullPath(_laptopTrackerExe);
                _laptopTrackerProcess = Process.Start(new ProcessStartInfo
                {
                    FileName = path,
                    WorkingDirectory = Path.GetDirectoryName(path),
                    UseShellExecute = true
                });
                if (_laptopTrackerProcess == null)
                    throw new InvalidOperationException("Windows did not return a process for Laptop Tracker.");
                _appsStatus.Text = "Starting Laptop Tracker in this panel...";
                Process tracker = _laptopTrackerProcess;
                Task.Run(delegate
                {
                    IntPtr window = IntPtr.Zero;
                    string windowError = null;
                    try
                    {
                        for (int attempt = 0; attempt < 150; attempt++)
                        {
                            if (tracker.HasExited) break;
                            tracker.Refresh();
                            window = tracker.MainWindowHandle;
                            if (window != IntPtr.Zero) break;
                            Thread.Sleep(100);
                        }
                    }
                    catch (InvalidOperationException ex)
                    {
                        windowError = ex.Message;
                    }
                    Dispatcher.BeginInvoke(new Action(delegate
                    {
                        if (!string.IsNullOrEmpty(windowError))
                        {
                            _appsStatus.Text = "Could not read the Laptop Tracker window: " + windowError;
                            Log("Laptop Tracker window lookup failed: " + windowError, BrushError);
                            return;
                        }
                        if (window == IntPtr.Zero)
                        {
                            _appsStatus.Text = "Laptop Tracker did not create a window. Check the selected executable and try again.";
                            Log("Laptop Tracker did not create a window within 15 seconds.", BrushWarn);
                            return;
                        }
                        if (_laptopTrackerHost == null || !_laptopTrackerHost.AttachWindow(window))
                        {
                            _appsStatus.Text = "Laptop Tracker started but could not be embedded. Close it and verify you selected the desktop app.";
                            Log("Laptop Tracker window could not be embedded in the Apps panel.", BrushError);
                            return;
                        }
                        _appsStatus.Text = "Laptop Tracker is open in this panel. Its own sign-in and permission prompts remain active.";
                        Log("Opened Laptop Tracker in the Apps panel.", BrushSuccess);
                    }));
                });
            }
            catch (Exception ex)
            {
                _appsStatus.Text = "Laptop Tracker could not be opened: " + ex.Message;
                Log("Laptop Tracker launch failed: " + ex.Message, BrushError);
            }
        }

        private sealed class TrackerWindowHost : HwndHost
        {
            private const int GwlStyle = -16;
            private const int WsChild = 0x40000000;
            private const int WsVisible = 0x10000000;
            private const int WsClipSiblings = 0x04000000;
            private const int WsClipChildren = 0x02000000;
            private const int WsPopup = unchecked((int)0x80000000);
            private const int WsCaption = 0x00C00000;
            private const int WsThickFrame = 0x00040000;
            private const int WsSysMenu = 0x00080000;
            private const int WsMinimizeBox = 0x00020000;
            private const int WsMaximizeBox = 0x00010000;
            private const uint SwpNoSize = 0x0001;
            private const uint SwpNoMove = 0x0002;
            private const uint SwpNoZOrder = 0x0004;
            private const uint SwpFrameChanged = 0x0020;
            private const int ShowNormal = 5;

            private IntPtr _hostHandle;
            private IntPtr _trackerHandle;
            private int _originalStyle;
            private bool _hasOriginalStyle;

            public bool AttachWindow(IntPtr window)
            {
                if (window == IntPtr.Zero || _hostHandle == IntPtr.Zero) return false;
                if (_trackerHandle == window)
                {
                    ResizeTrackerWindow();
                    return true;
                }

                _originalStyle = GetWindowLong(window, GwlStyle);
                _hasOriginalStyle = true;
                SetParent(window, _hostHandle);
                if (GetParent(window) != _hostHandle)
                {
                    _hasOriginalStyle = false;
                    return false;
                }

                int childStyle = (_originalStyle & ~(WsPopup | WsCaption | WsThickFrame |
                    WsSysMenu | WsMinimizeBox | WsMaximizeBox)) |
                    WsChild | WsVisible | WsClipSiblings | WsClipChildren;
                SetWindowLong(window, GwlStyle, childStyle);
                _trackerHandle = window;
                SetWindowPos(window, IntPtr.Zero, 0, 0, 0, 0,
                    SwpNoZOrder | SwpFrameChanged | SwpNoMove | SwpNoSize);
                ShowWindow(window, ShowNormal);
                ResizeTrackerWindow();
                return true;
            }

            protected override HandleRef BuildWindowCore(HandleRef hwndParent)
            {
                _hostHandle = CreateWindowEx(0, "static", "",
                    WsChild | WsVisible | WsClipSiblings | WsClipChildren,
                    0, 0, 1, 1, hwndParent.Handle, IntPtr.Zero,
                    GetModuleHandle(null), IntPtr.Zero);
                if (_hostHandle == IntPtr.Zero)
                    throw new InvalidOperationException("Could not create the Laptop Tracker panel host (Win32 " +
                        Marshal.GetLastWin32Error() + ").");
                return new HandleRef(this, _hostHandle);
            }

            protected override void DestroyWindowCore(HandleRef hwnd)
            {
                DetachTrackerWindow();
                if (hwnd.Handle != IntPtr.Zero) DestroyWindow(hwnd.Handle);
                _hostHandle = IntPtr.Zero;
            }

            protected override void OnWindowPositionChanged(Rect rect)
            {
                base.OnWindowPositionChanged(rect);
                ResizeTrackerWindow();
            }

            private void ResizeTrackerWindow()
            {
                if (_trackerHandle == IntPtr.Zero || _hostHandle == IntPtr.Zero) return;
                double width = ActualWidth;
                double height = ActualHeight;
                PresentationSource source = PresentationSource.FromVisual(this);
                if (source != null && source.CompositionTarget != null)
                {
                    Matrix transform = source.CompositionTarget.TransformToDevice;
                    Point size = transform.Transform(new Point(width, height));
                    width = size.X;
                    height = size.Y;
                }
                MoveWindow(_trackerHandle, 0, 0,
                    Math.Max(1, (int)Math.Round(width)),
                    Math.Max(1, (int)Math.Round(height)), true);
            }

            private void DetachTrackerWindow()
            {
                if (_trackerHandle == IntPtr.Zero) return;
                if (_hasOriginalStyle)
                {
                    SetParent(_trackerHandle, IntPtr.Zero);
                    SetWindowLong(_trackerHandle, GwlStyle, _originalStyle);
                    SetWindowPos(_trackerHandle, IntPtr.Zero, 0, 0, 0, 0,
                        SwpNoZOrder | SwpFrameChanged | SwpNoMove | SwpNoSize);
                    ShowWindow(_trackerHandle, ShowNormal);
                }
                _trackerHandle = IntPtr.Zero;
                _hasOriginalStyle = false;
            }

            [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
            private static extern IntPtr CreateWindowEx(int exStyle, string className, string windowName,
                int style, int x, int y, int width, int height, IntPtr parent, IntPtr menu,
                IntPtr instance, IntPtr parameter);

            [DllImport("user32.dll", SetLastError = true)]
            private static extern bool DestroyWindow(IntPtr handle);

            [DllImport("user32.dll")]
            private static extern IntPtr SetParent(IntPtr child, IntPtr parent);

            [DllImport("user32.dll")]
            private static extern IntPtr GetParent(IntPtr child);

            [DllImport("user32.dll", EntryPoint = "GetWindowLongW", SetLastError = true)]
            private static extern int GetWindowLong(IntPtr handle, int index);

            [DllImport("user32.dll", EntryPoint = "SetWindowLongW", SetLastError = true)]
            private static extern int SetWindowLong(IntPtr handle, int index, int value);

            [DllImport("user32.dll", SetLastError = true)]
            private static extern bool SetWindowPos(IntPtr handle, IntPtr insertAfter,
                int x, int y, int width, int height, uint flags);

            [DllImport("user32.dll", SetLastError = true)]
            private static extern bool MoveWindow(IntPtr handle, int x, int y,
                int width, int height, bool repaint);

            [DllImport("user32.dll")]
            private static extern bool ShowWindow(IntPtr handle, int command);

            [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
            private static extern IntPtr GetModuleHandle(string moduleName);
        }

        private void OpenLaptopTrackerApkLocation(string path)
        {
            if (!File.Exists(path))
            {
                _appsStatus.Text = "Laptop Tracker Android APK was not found at " + path;
                Log("Laptop Tracker APK is missing: " + path, BrushWarn);
                return;
            }
            try
            {
                Process.Start(new ProcessStartInfo
                {
                    FileName = "explorer.exe",
                    Arguments = "/select,\"" + path + "\"",
                    UseShellExecute = true
                });
                _appsStatus.Text = "Opened File Explorer with the Laptop Tracker Android APK selected.";
            }
            catch (Exception ex)
            {
                _appsStatus.Text = "The APK could not be shown in File Explorer: " + ex.Message;
                Log("Laptop Tracker APK open failed: " + ex.Message, BrushError);
            }
        }

        private void ChooseLaptopTrackerApkLocation()
        {
            Microsoft.Win32.OpenFileDialog dialog = new Microsoft.Win32.OpenFileDialog
            {
                Title = "Choose Laptop Tracker Android APK",
                Filter = "Android application package (*.apk)|*.apk",
                CheckFileExists = true,
                Multiselect = false
            };
            if (dialog.ShowDialog(this) == true)
                OpenLaptopTrackerApkLocation(dialog.FileName);
        }

        private Grid BuildTrackerTab()
        {
            Grid g = new Grid { Margin = new Thickness(14, 10, 14, 10) };
            g.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            g.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) });

            StackPanel heading = new StackPanel { Margin = new Thickness(4, 0, 4, 10) };
            heading.Children.Add(new TextBlock
            {
                Text = "Device tracking session",
                FontSize = 22,
                FontWeight = FontWeights.Bold,
                Foreground = BrushFg
            });
            heading.Children.Add(new TextBlock
            {
                Text = "Connect to the authenticated tracker service for paired-device status and last reported locations. Refresh status to view those points on a map. This app never tracks in the background; it reads and shares its own location only after you click Share current location once.",
                TextWrapping = TextWrapping.Wrap,
                Foreground = BrushGray,
                Margin = new Thickness(0, 4, 0, 0)
            });
            Grid.SetRow(heading, 0);
            g.Children.Add(heading);

            Grid workspace = new Grid();
            workspace.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(380) });
            workspace.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            workspace.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) });
            workspace.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });

            ScrollViewer controlScroll = new ScrollViewer
            {
                VerticalScrollBarVisibility = ScrollBarVisibility.Auto,
                HorizontalScrollBarVisibility = ScrollBarVisibility.Disabled,
                Margin = new Thickness(0, 0, 8, 0)
            };
            StackPanel controls = new StackPanel();
            controlScroll.Content = controls;

            StackPanel connection = new StackPanel();
            connection.Children.Add(new TextBlock
            {
                Text = "Tracker connection",
                FontSize = 15,
                FontWeight = FontWeights.SemiBold,
                Foreground = BrushFg,
                Margin = new Thickness(2, 0, 2, 8)
            });
            _trackerServerBox = MakeTextBox(0);
            _trackerServerBox.HorizontalAlignment = HorizontalAlignment.Stretch;
            AddTrackerInput(connection, "Tracker service URL (HTTPS)", _trackerServerBox);

            _trackerPairBox = MakeTextBox(0);
            _trackerPairBox.HorizontalAlignment = HorizontalAlignment.Stretch;
            AddTrackerInput(connection, "Pairing code", _trackerPairBox);

            _trackerDeviceBox = MakeTextBox(0);
            _trackerDeviceBox.HorizontalAlignment = HorizontalAlignment.Stretch;
            AddTrackerInput(connection, "Device ID", _trackerDeviceBox);
            controls.Children.Add(MakeServiceCard(connection));

            StackPanel actionCard = new StackPanel();
            actionCard.Children.Add(new TextBlock
            {
                Text = "Device actions",
                FontSize = 15,
                FontWeight = FontWeights.SemiBold,
                Foreground = BrushFg,
                Margin = new Thickness(2, 0, 2, 8)
            });
            WrapPanel actions = new WrapPanel { Margin = new Thickness(0, 2, 0, 4) };
            AddTrackerAction(actions, "Generate pairing code", "Generate pairing code", false, false,
                delegate(TrackerBridge bridge, string pair, string device) { return bridge.GeneratePair(); }, "PrimaryButton");
            AddTrackerAction(actions, "Verify pairing", "Verify pairing", true, false,
                delegate(TrackerBridge bridge, string pair, string device) { return bridge.VerifyPair(pair); }, "GhostButton");
            AddTrackerAction(actions, "Refresh status", "Refresh status", false, true,
                delegate(TrackerBridge bridge, string pair, string device) { return bridge.PairInfo(device); }, "GhostButton");
            AddTrackerAction(actions, "Send status check-in", "Send status check-in", false, true,
                delegate(TrackerBridge bridge, string pair, string device) { return bridge.Heartbeat(device, null, null, "ussd-app-status"); }, "GhostButton");
            AddTrackerAction(actions, "Share current location once", "Share current location once", false, true,
                delegate(TrackerBridge bridge, string pair, string device)
                {
                    System.Device.Location.GeoCoordinate location = ReadCurrentLocationOnce();
                    return bridge.Heartbeat(device, location.Latitude, location.Longitude, "ussd-app-location");
                }, "PrimaryButton");
            AddTrackerAction(actions, "Enable lost mode", "Enable lost mode", false, true,
                delegate(TrackerBridge bridge, string pair, string device) { return bridge.LostMode(device, true); }, "DangerQuietButton");
            AddTrackerAction(actions, "Disable lost mode", "Disable lost mode", false, true,
                delegate(TrackerBridge bridge, string pair, string device) { return bridge.LostMode(device, false); }, "GhostButton");
            actionCard.Children.Add(actions);
            actionCard.Children.Add(new TextBlock
            {
                Text = "Use HTTPS. Device credentials are protected with Windows DPAPI for this user. Share a generated pairing code only with a device you control.",
                TextWrapping = TextWrapping.Wrap,
                Foreground = BrushGray,
                Margin = new Thickness(4, 8, 4, 0)
            });
            controls.Children.Add(MakeServiceCard(actionCard));
            Grid.SetColumn(controlScroll, 0);
            workspace.Children.Add(controlScroll);

            Grid results = new Grid { Margin = new Thickness(8, 0, 0, 0) };
            results.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            results.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) });
            results.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });

            StackPanel statusHead = new StackPanel();
            statusHead.Children.Add(new TextBlock
            {
                Text = "Device status",
                FontSize = 15,
                FontWeight = FontWeights.SemiBold,
                Foreground = BrushFg,
                Margin = new Thickness(2, 0, 2, 6)
            });
            _trackerStatus = new TextBlock
            {
                Text = "Not connected",
                TextWrapping = TextWrapping.Wrap,
                Foreground = BrushGray,
                Margin = new Thickness(2, 0, 2, 8)
            };
            statusHead.Children.Add(_trackerStatus);
            Grid.SetRow(statusHead, 0);
            results.Children.Add(statusHead);

            Grid mapHost = new Grid { MinHeight = 220 };
            _trackerMapCanvas = new Canvas
            {
                ClipToBounds = true,
                Background = Theme.Chrome,
                HorizontalAlignment = HorizontalAlignment.Stretch,
                VerticalAlignment = VerticalAlignment.Stretch
            };
            _trackerMapCanvas.SizeChanged += delegate { PlotTrackerMap(); };
            _trackerMapHint = new TextBlock
            {
                Text = "Refresh status to plot last reported points. Locations are last reported, not a live feed.",
                TextWrapping = TextWrapping.Wrap,
                Foreground = BrushGray,
                Margin = new Thickness(16),
                HorizontalAlignment = HorizontalAlignment.Center,
                VerticalAlignment = VerticalAlignment.Center
            };
            mapHost.Children.Add(_trackerMapCanvas);
            mapHost.Children.Add(_trackerMapHint);
            Grid.SetRow(mapHost, 1);
            results.Children.Add(mapHost);

            StackPanel report = new StackPanel();
            _trackerOutput = MakeMultiBox();
            _trackerOutput.IsReadOnly = true;
            _trackerOutput.Height = 90;
            _trackerOutput.HorizontalAlignment = HorizontalAlignment.Stretch;
            _trackerOutput.Margin = new Thickness(0, 8, 0, 4);
            report.Children.Add(_trackerOutput);
            _trackerMapLinks = new StackPanel { Margin = new Thickness(0, 4, 0, 0) };
            report.Children.Add(_trackerMapLinks);
            report.Children.Add(new TextBlock
            {
                Text = "Open Maps only when you choose; the map provider receives the selected coordinates.",
                TextWrapping = TextWrapping.Wrap,
                Foreground = BrushGray,
                Margin = new Thickness(2, 8, 2, 0)
            });
            Grid.SetRow(report, 2);
            results.Children.Add(report);

            Border resultsCard = MakeServiceCard(results);
            resultsCard.Margin = new Thickness(0);
            Grid.SetColumn(resultsCard, 1);
            workspace.Children.Add(resultsCard);
            workspace.SizeChanged += delegate
            {
                bool stackCards = workspace.ActualWidth < 900;
                workspace.ColumnDefinitions[0].Width = stackCards ? new GridLength(1, GridUnitType.Star) : new GridLength(380);
                Grid.SetColumn(resultsCard, stackCards ? 0 : 1);
                Grid.SetRow(resultsCard, stackCards ? 1 : 0);
                workspace.RowDefinitions[0].Height = stackCards ? GridLength.Auto : new GridLength(1, GridUnitType.Star);
                workspace.RowDefinitions[1].Height = stackCards ? new GridLength(1, GridUnitType.Star) : new GridLength(0);
            };
            Grid.SetRow(workspace, 1);
            g.Children.Add(workspace);
            return g;
        }

        private static Border MakeServiceCard(UIElement content)
        {
            return new Border
            {
                Background = Theme.Panel,
                BorderBrush = Theme.CardBorder,
                BorderThickness = new Thickness(1),
                CornerRadius = new CornerRadius(12),
                Padding = new Thickness(16),
                Margin = new Thickness(4, 6, 4, 10),
                Child = content
            };
        }

        private static System.Device.Location.GeoCoordinate ReadCurrentLocationOnce()
        {
            System.Device.Location.GeoCoordinateWatcher watcher =
                new System.Device.Location.GeoCoordinateWatcher(System.Device.Location.GeoPositionAccuracy.Default);
            using (AutoResetEvent received = new AutoResetEvent(false))
            {
                System.Device.Location.GeoCoordinate location = null;
                EventHandler<System.Device.Location.GeoPositionChangedEventArgs<System.Device.Location.GeoCoordinate>> handler =
                    delegate(object sender, System.Device.Location.GeoPositionChangedEventArgs<System.Device.Location.GeoCoordinate> e)
                    {
                        if (e.Position.Location == null || e.Position.Location.IsUnknown) return;
                        location = e.Position.Location;
                        received.Set();
                    };
                watcher.PositionChanged += handler;
                try
                {
                    watcher.Start(false);
                    if (!received.WaitOne(TimeSpan.FromSeconds(30)))
                        throw new TimeoutException("No Windows location fix arrived within 30 seconds. Check that Location services are enabled; nothing was shared.");
                    if (location == null || location.IsUnknown)
                        throw new InvalidOperationException("Windows did not provide a usable location fix. Nothing was shared.");
                    return location;
                }
                finally
                {
                    watcher.PositionChanged -= handler;
                    watcher.Stop();
                }
            }
        }

        private static void AddTrackerInput(StackPanel parent, string label, TextBox input)
        {
            parent.Children.Add(new TextBlock
            {
                Text = label,
                Foreground = BrushFg,
                FontWeight = FontWeights.SemiBold,
                Margin = new Thickness(4, 4, 4, 2)
            });
            input.Margin = new Thickness(4, 0, 4, 6);
            input.MinHeight = 30;
            parent.Children.Add(input);
        }

        private void AddTrackerAction(WrapPanel parent, string label, string action, bool needsPair, bool needsDevice,
            Func<TrackerBridge, string, string, TrackerBridge.Reply> request)
        {
            AddTrackerAction(parent, label, action, needsPair, needsDevice, request, null);
        }

        private void AddTrackerAction(WrapPanel parent, string label, string action, bool needsPair, bool needsDevice,
            Func<TrackerBridge, string, string, TrackerBridge.Reply> request, string styleKey)
        {
            Button button = string.IsNullOrEmpty(styleKey) ? MakeButton(label) : MakeStyledButton(label, styleKey);
            button.Margin = new Thickness(3);
            button.Click += delegate { RunTrackerRequest(action, needsPair, needsDevice, request); };
            parent.Children.Add(button);
            _trackerActionButtons.Add(button);
        }

        private void RunTrackerRequest(string action, bool needsPair, bool needsDevice,
            Func<TrackerBridge, string, string, TrackerBridge.Reply> request)
        {
            if (_trackerBusy) return;

            string server = _trackerServerBox == null ? "" : (_trackerServerBox.Text ?? "").Trim();
            string pair = _trackerPairBox == null ? "" : (_trackerPairBox.Text ?? "").Trim();
            string device = _trackerDeviceBox == null ? "" : (_trackerDeviceBox.Text ?? "").Trim();
            if (!TrackerBridge.IsSafeServerUrl(server))
            {
                SetTrackerResult("Enter a valid HTTPS tracker URL.", "");
                return;
            }
            if (needsPair && pair.Length == 0)
            {
                SetTrackerResult("Enter the pairing code first.", "");
                return;
            }
            if (needsDevice && device.Length == 0)
            {
                SetTrackerResult("Enter the device ID first.", "");
                return;
            }
            if (_cfg == null)
            {
                SetTrackerResult("App configuration is not ready. Try again after startup.", "");
                return;
            }

            string token = "";
            if (needsDevice)
            {
                try { token = TrackerBridge.UnprotectDeviceToken(_cfg.tracker_token_protected); }
                catch (Exception ex)
                {
                    SetTrackerResult("Could not unlock the saved tracker credential: " + ex.Message, "");
                    return;
                }
                if (token.Length == 0)
                {
                    SetTrackerResult("Pair this device before requesting authenticated tracker actions.", "");
                    return;
                }
            }

            _cfg.tracker_server = server;
            _cfg.tracker_pair_code = "";
            if (device.Length > 0) _cfg.tracker_device_id = device;
            try { _cfg.Save(); }
            catch (Exception ex)
            {
                SetTrackerResult("Could not save tracker settings: " + ex.Message, "");
                return;
            }

            _trackerBusy = true;
            SetTrackerButtonsEnabled(false);
            SetTrackerResult(action + " in progress...", "");
            System.Threading.ThreadPool.QueueUserWorkItem(delegate
            {
                TrackerBridge.Reply reply = null;
                string failure = "";
                try
                {
                    reply = request(new TrackerBridge(server, token), pair, device);
                    if (reply.Ok && (action == "Generate pairing code" || action == "Verify pairing"))
                    {
                        string newDevice = TrackerBridge.ReadJsonString(reply.Body, "deviceId");
                        string newToken = TrackerBridge.ReadJsonString(reply.Body, "deviceToken");
                        if (newDevice.Length == 0 || newToken.Length == 0)
                            throw new InvalidDataException("Tracker pairing response did not contain device credentials.");
                        _cfg.tracker_device_id = newDevice;
                        _cfg.tracker_token_protected = TrackerBridge.ProtectDeviceToken(newToken);
                        _cfg.tracker_pair_code = "";
                        _cfg.Save();
                    }
                }
                catch (Exception ex) { failure = ex.Message; }

                Dispatcher.BeginInvoke((Action)delegate
                {
                    _trackerBusy = false;
                    SetTrackerButtonsEnabled(true);
                    if (reply == null)
                        SetTrackerResult(action + " failed: " + (failure.Length == 0 ? "No response." : failure), "");
                    else
                    {
                        if (reply.Ok && action == "Refresh status")
                            RenderTrackerLocations(reply.Body);
                        if (reply.Ok && (action == "Generate pairing code" || action == "Verify pairing"))
                        {
                            _trackerDeviceBox.Text = _cfg.tracker_device_id;
                            string newPair = TrackerBridge.ReadJsonString(reply.Body, "pairCode");
                            if (newPair.Length > 0) _trackerPairBox.Text = newPair;
                        }
                        string heading = action + (reply.Ok ? " completed." : " failed.");
                        if (reply.StatusCode > 0) heading += " HTTP " + reply.StatusCode + ".";
                        if (reply.Error.Length > 0) heading += " " + reply.Error;
                        SetTrackerResult(heading, TrackerBridge.RedactDeviceToken(reply.Body));
                    }
                });
            });
        }

        private void RenderTrackerLocations(string body)
        {
            if (_trackerMapLinks == null) return;
            _trackerMapLinks.Children.Clear();
            List<Tuple<string, double, double>> points = new List<Tuple<string, double, double>>();
            string json = body ?? "";
            int devicesIndex = json.IndexOf("\"devices\"", StringComparison.Ordinal);
            if (devicesIndex >= 0) json = json.Substring(devicesIndex);
            MatchCollection locations = Regex.Matches(json,
                "\"deviceId\"\\s*:\\s*\"([^\"]+)\"[^}]{0,800}?\"location\"\\s*:\\s*\\{\\s*\"lat\"\\s*:\\s*(-?[0-9]+(?:\\.[0-9]+)?)\\s*,\\s*\"lng\"\\s*:\\s*(-?[0-9]+(?:\\.[0-9]+)?)");
            int found = 0;
            foreach (Match match in locations)
            {
                double lat, lng;
                if (!double.TryParse(match.Groups[2].Value, NumberStyles.Float, CultureInfo.InvariantCulture, out lat) ||
                    !double.TryParse(match.Groups[3].Value, NumberStyles.Float, CultureInfo.InvariantCulture, out lng) ||
                    double.IsNaN(lat) || double.IsInfinity(lat) || lat < -90 || lat > 90 ||
                    double.IsNaN(lng) || double.IsInfinity(lng) || lng < -180 || lng > 180)
                    continue;

                string deviceId = match.Groups[1].Value;
                points.Add(Tuple.Create(deviceId, lat, lng));
                TextBlock coordinates = new TextBlock
                {
                    Text = "Paired device " + deviceId + " - last reported location: " +
                           lat.ToString("F6", CultureInfo.InvariantCulture) +
                           ", " + lng.ToString("F6", CultureInfo.InvariantCulture),
                    Foreground = BrushGray,
                    Margin = new Thickness(2, 6, 2, 2)
                };
                _trackerMapLinks.Children.Add(coordinates);
                Button openMap = MakeButton("Open last reported location in Maps");
                openMap.Margin = new Thickness(2, 2, 2, 6);
                string query = lat.ToString(CultureInfo.InvariantCulture) + "," +
                               lng.ToString(CultureInfo.InvariantCulture);
                openMap.Click += delegate
                {
                    try { System.Diagnostics.Process.Start("https://www.google.com/maps/search/?api=1&query=" + query); }
                    catch (Exception ex) { SetTrackerResult("Could not open a map: " + ex.Message, ""); }
                };
                _trackerMapLinks.Children.Add(openMap);
                found++;
            }
            if (points.Count > 1)
            {
                string ownDevice = _cfg == null ? "" : (_cfg.tracker_device_id ?? "");
                Tuple<string, double, double> origin = null;
                Tuple<string, double, double> destination = null;
                for (int i = 0; i < points.Count; i++)
                {
                    if (string.Equals(points[i].Item1, ownDevice, StringComparison.Ordinal))
                    {
                        origin = points[i];
                        break;
                    }
                }
                if (origin == null) origin = points[0];
                for (int i = 0; i < points.Count; i++)
                {
                    if (!string.Equals(points[i].Item1, origin.Item1, StringComparison.Ordinal))
                    {
                        destination = points[i];
                        break;
                    }
                }
                if (destination == null)
                    for (int i = 1; i < points.Count; i++)
                        if (!object.ReferenceEquals(points[i], origin))
                        {
                            destination = points[i];
                            break;
                        }

                if (destination != null)
                {
                    string start = origin.Item2.ToString(CultureInfo.InvariantCulture) + "," +
                                   origin.Item3.ToString(CultureInfo.InvariantCulture);
                    string end = destination.Item2.ToString(CultureInfo.InvariantCulture) + "," +
                                 destination.Item3.ToString(CultureInfo.InvariantCulture);
                    Button compare = MakeButton("Compare two reported locations in Maps");
                    compare.Margin = new Thickness(2, 8, 2, 4);
                    compare.Click += delegate
                    {
                        try
                        {
                            System.Diagnostics.Process.Start(
                                "https://www.google.com/maps/dir/?api=1&origin=" + start + "&destination=" + end);
                        }
                        catch (Exception ex) { SetTrackerResult("Could not open a map: " + ex.Message, ""); }
                    };
                    _trackerMapLinks.Children.Insert(0, compare);
                }
            }
            if (found == 0)
                _trackerMapLinks.Children.Add(new TextBlock
                {
                    Text = "No paired-device location has been reported. The device must share a location while available; offline devices cannot report live updates.",
                    TextWrapping = TextWrapping.Wrap,
                    Foreground = BrushGray,
                    Margin = new Thickness(2, 6, 2, 2)
                });
            _trackerMapPoints = points;
            PlotTrackerMap();
        }

        private void PlotTrackerMap()
        {
            if (_trackerMapCanvas == null) return;
            _trackerMapCanvas.Children.Clear();
            double w = _trackerMapCanvas.ActualWidth;
            double h = _trackerMapCanvas.ActualHeight;
            if (w < 8 || h < 8) return;

            for (int i = 0; i < 6; i++)
            {
                double x = (w / 6.0) * i;
                double y = (h / 6.0) * i;
                _trackerMapCanvas.Children.Add(new System.Windows.Shapes.Line
                {
                    X1 = x, Y1 = 0, X2 = x, Y2 = h,
                    Stroke = Theme.CardBorder, StrokeThickness = 1
                });
                _trackerMapCanvas.Children.Add(new System.Windows.Shapes.Line
                {
                    X1 = 0, Y1 = y, X2 = w, Y2 = y,
                    Stroke = Theme.CardBorder, StrokeThickness = 1
                });
            }

            List<Tuple<string, double, double>> points = _trackerMapPoints;
            if (points == null || points.Count == 0)
            {
                if (_trackerMapHint != null) _trackerMapHint.Visibility = Visibility.Visible;
                return;
            }
            if (_trackerMapHint != null) _trackerMapHint.Visibility = Visibility.Collapsed;

            double minLat = 90, maxLat = -90, minLng = 180, maxLng = -180;
            for (int i = 0; i < points.Count; i++)
            {
                if (points[i].Item2 < minLat) minLat = points[i].Item2;
                if (points[i].Item2 > maxLat) maxLat = points[i].Item2;
                if (points[i].Item3 < minLng) minLng = points[i].Item3;
                if (points[i].Item3 > maxLng) maxLng = points[i].Item3;
            }
            if (Math.Abs(maxLat - minLat) < 0.002) { minLat -= 0.01; maxLat += 0.01; }
            if (Math.Abs(maxLng - minLng) < 0.002) { minLng -= 0.01; maxLng += 0.01; }

            for (int i = 0; i < points.Count; i++)
            {
                double nx = (points[i].Item3 - minLng) / (maxLng - minLng);
                double ny = 1.0 - (points[i].Item2 - minLat) / (maxLat - minLat);
                double cx = 16 + nx * (w - 32);
                double cy = 16 + ny * (h - 32);
                System.Windows.Shapes.Ellipse pin = new System.Windows.Shapes.Ellipse
                {
                    Width = 14,
                    Height = 14,
                    Fill = Theme.Accent,
                    Stroke = Brushes.White,
                    StrokeThickness = 2
                };
                Canvas.SetLeft(pin, cx - 7);
                Canvas.SetTop(pin, cy - 7);
                _trackerMapCanvas.Children.Add(pin);
            }
        }

        private void SetTrackerButtonsEnabled(bool enabled)
        {
            for (int i = 0; i < _trackerActionButtons.Count; i++)
                _trackerActionButtons[i].IsEnabled = enabled;
        }

        private void SetTrackerResult(string status, string body)
        {
            if (_trackerStatus != null) _trackerStatus.Text = status;
            if (_trackerOutput != null) _trackerOutput.Text = body ?? "";
        }

        private Grid BuildDialerTab()
        {
            Grid g = new Grid { Margin = new Thickness(6) };
            g.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });   // transport switcher
            g.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) }); // main content
            g.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(320) });
            g.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });

            // Transport Mode Switcher (Cellular / VoIP pill) — spans both columns
            Border modeSwitcher = new Border
            {
                Background = Theme.Chrome,
                BorderBrush = Theme.CardBorder,
                BorderThickness = new Thickness(0, 0, 0, 1),
                Padding = new Thickness(12, 8, 12, 8)
            };
            Grid.SetColumnSpan(modeSwitcher, 2);
            Grid.SetRow(modeSwitcher, 0);

            StackPanel modeRow = new StackPanel { Orientation = Orientation.Horizontal };

            TextBlock modeLabel = new TextBlock
            {
                Text = "TRANSPORT",
                Foreground = BrushGray,
                FontWeight = FontWeights.Bold,
                FontSize = 10,
                VerticalAlignment = VerticalAlignment.Center,
                Margin = new Thickness(0, 0, 12, 0)
            };
            modeRow.Children.Add(modeLabel);

            // Segmented pill container
            Border modePill = new Border
            {
                Background = Theme.Keypad,
                CornerRadius = new CornerRadius(20),
                Padding = new Thickness(3)
            };
            StackPanel modeInner = new StackPanel { Orientation = Orientation.Horizontal };

            _btnTransportCellular = new Button
            {
                Content = "\uD83D\uDCDE  Cellular",
                Padding = new Thickness(14, 5, 14, 5),
                Background = Theme.Accent,
                Foreground = Brushes.White,
                BorderThickness = new Thickness(0),
                FontWeight = FontWeights.Bold,
                Cursor = Cursors.Hand
            };
            Style cellStyle = TryStyle("PrimaryButton");
            if (cellStyle != null) _btnTransportCellular.Style = cellStyle;
            _btnTransportCellular.Background = Theme.Accent;
            _btnTransportCellular.Foreground = Brushes.White;

            _btnTransportVoip = new Button
            {
                Content = "\uD83C\uDF10  VoIP / LAN",
                Padding = new Thickness(14, 5, 14, 5),
                Background = Brushes.Transparent,
                Foreground = BrushGray,
                BorderThickness = new Thickness(0),
                Cursor = Cursors.Hand
            };

            _btnTransportCellular.Click += delegate { SetDialerTransport("cellular"); };
            _btnTransportVoip.Click += delegate { SetDialerTransport("voip"); };

            modeInner.Children.Add(_btnTransportCellular);
            modeInner.Children.Add(_btnTransportVoip);
            modePill.Child = modeInner;
            modeRow.Children.Add(modePill);

            // Quick signal/status indicator next to the switcher
            _callStateText = new TextBlock
            {
                Text = "Ready",
                FontSize = 13,
                FontWeight = FontWeights.SemiBold,
                Foreground = BrushGray,
                VerticalAlignment = VerticalAlignment.Center,
                Margin = new Thickness(18, 0, 0, 0)
            };
            modeRow.Children.Add(_callStateText);
            _callTimerText = new TextBlock
            {
                Text = "",
                FontSize = 13,
                Foreground = BrushGray,
                FontFamily = new FontFamily("Consolas"),
                VerticalAlignment = VerticalAlignment.Center,
                Margin = new Thickness(10, 0, 0, 0)
            };
            modeRow.Children.Add(_callTimerText);

            // App Caller ID display — spacer then the 700-XXXXXXX number
            // Users share this number with others to call them without a SIM.
            TextBlock appIdLabel = new TextBlock
            {
                Text = "Your App ID:",
                Foreground = BrushGray,
                FontSize = 11,
                VerticalAlignment = VerticalAlignment.Center,
                Margin = new Thickness(20, 0, 4, 0)
            };
            modeRow.Children.Add(appIdLabel);
            TextBlock appIdNum = new TextBlock
            {
                Text = AppNum.Format(_myNumber ?? ""),
                Foreground = BrushAccent,
                FontSize = 12,
                FontWeight = FontWeights.Bold,
                FontFamily = new FontFamily("Consolas"),
                VerticalAlignment = VerticalAlignment.Center,
                ToolTip = "Share this number with others so they can call you directly through the app (no SIM required)",
                Cursor = Cursors.Hand
            };
            appIdNum.MouseLeftButtonUp += delegate
            {
                try { Clipboard.SetText(SanitizeNumber(_myNumber ?? "")); Log("App caller ID copied to clipboard.", BrushSuccess); } catch { }
            };
            modeRow.Children.Add(appIdNum);

            modeSwitcher.Child = modeRow;
            g.Children.Add(modeSwitcher);

            // Left: number + keypad
            StackPanel left = new StackPanel { Margin = new Thickness(4, 4, 4, 4) };
            Grid.SetRow(left, 1);
            Grid.SetColumn(left, 0);
            left.Children.Add(new TextBlock { Text = "NUMBER", Foreground = BrushGray, FontWeight = FontWeights.Bold, FontSize = 11 });
            _txtNumber = MakeTextBox(0);
            _txtNumber.FontSize = 24;
            _txtNumber.Height = 40;
            _txtNumber.TextAlignment = TextAlignment.Center;
            _txtNumber.FontFamily = new FontFamily("Consolas");
            _txtNumber.Margin = new Thickness(0, 4, 6, 0);
            _txtNumber.ToolTip = "Number to dial - press Enter to call";
            _txtNumber.SetValue(System.Windows.Automation.AutomationProperties.NameProperty, "Dial number");
            _txtNumber.KeyDown += async delegate(object s, KeyEventArgs e)
            {
                if (e.Key == Key.Enter) { e.Handled = true; await StartCallAsync(); }
            };

            Style smallCircle = TryStyle("CircleIconButton");
            Button btnBack = new Button { Content = "\u232B", Cursor = Cursors.Hand, ToolTip = "Backspace", VerticalAlignment = VerticalAlignment.Center, Margin = new Thickness(0, 4, 0, 0) };
            Button btnClearNum = new Button { Content = "C", Cursor = Cursors.Hand, ToolTip = "Clear number", VerticalAlignment = VerticalAlignment.Center, Margin = new Thickness(0, 4, 0, 0) };
            Button[] auxKeys = new Button[] { btnBack, btnClearNum };
            for (int i = 0; i < auxKeys.Length; i++)
            {
                if (smallCircle != null) auxKeys[i].Style = smallCircle;
                else { auxKeys[i].Width = 44; auxKeys[i].Height = 44; auxKeys[i].FontSize = 16; auxKeys[i].Background = BrushPanel; auxKeys[i].Foreground = BrushFg; auxKeys[i].BorderBrush = BrushBorder; auxKeys[i].Margin = new Thickness(2); }
                WireButtonEffects(auxKeys[i]);
            }
            btnBack.Click += delegate { Backspace(); };
            btnClearNum.Click += delegate { _txtNumber.Text = ""; };

            Grid dispRow = new Grid();
            dispRow.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            dispRow.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
            dispRow.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
            dispRow.Children.Add(_txtNumber);
            Grid.SetColumn(_txtNumber, 0);
            dispRow.Children.Add(btnBack);
            Grid.SetColumn(btnBack, 1);
            dispRow.Children.Add(btnClearNum);
            Grid.SetColumn(btnClearNum, 2);
            left.Children.Add(dispRow);

            // Keypad / Recents segmented switch (spec: dialer keeps recents)
            Grid seg = new Grid { Margin = new Thickness(0, 6, 0, 0) };
            seg.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            seg.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            _tabKeypad = new Button { Content = "Keypad", Cursor = Cursors.Hand, Height = 32, FontSize = 12, FontWeight = FontWeights.Bold, ToolTip = "Number keypad" };
            _tabRecents = new Button { Content = "Recents", Cursor = Cursors.Hand, Height = 32, FontSize = 12, ToolTip = "Recent calls - click an entry to dial it" };
            _tabKeypad.Margin = new Thickness(0, 0, 3, 0);
            _tabRecents.Margin = new Thickness(3, 0, 0, 0);
            Grid.SetColumn(_tabKeypad, 0);
            Grid.SetColumn(_tabRecents, 1);
            seg.Children.Add(_tabKeypad);
            seg.Children.Add(_tabRecents);
            _tabKeypad.Click += delegate { SelectDialerPane(true); };
            _tabRecents.Click += delegate { SelectDialerPane(false); };
            left.Children.Add(seg);

            // Two stacked panes; only one visible at a time.
            Grid panes = new Grid { Margin = new Thickness(0, 2, 0, 0) };
            _keypadPane = new StackPanel();
            _recentsPane = new StackPanel { Visibility = Visibility.Collapsed };
            panes.Children.Add(_keypadPane);
            panes.Children.Add(_recentsPane);
            left.Children.Add(panes);

            Grid pad = new Grid { Margin = new Thickness(0, 4, 0, 0), MaxWidth = 216, HorizontalAlignment = HorizontalAlignment.Center };
            for (int i = 0; i < 4; i++) pad.RowDefinitions.Add(new RowDefinition { Height = new GridLength(68) });
            for (int i = 0; i < 3; i++) pad.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            string[] keys = new string[] { "1", "2", "3", "4", "5", "6", "7", "8", "9", "*", "0", "#" };
            Style circleStyle = TryStyle("DialerCircleButton");
            for (int i = 0; i < keys.Length; i++)
            {
                Button k = new Button
                {
                    Content = keys[i],
                    Cursor = Cursors.Hand
                };
                if (circleStyle != null) k.Style = circleStyle;
                else { k.FontSize = 20; k.Background = BrushPanel; k.Foreground = BrushFg; k.BorderBrush = BrushBorder; k.Margin = new Thickness(4); }
                string digit = keys[i];
                WireButtonEffects(k);
                k.Click += delegate { KeyPress(digit); };
                Grid.SetRow(k, i / 3);
                Grid.SetColumn(k, i % 3);
                pad.Children.Add(k);
            }
            _keypadPane.Children.Add(pad);

            StackPanel actions = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 4, 0, 0), HorizontalAlignment = HorizontalAlignment.Center };
            _btnAnswer = MakeButton("Answer");
            Style successStyle = TryStyle("SuccessButton");
            if (successStyle != null) _btnAnswer.Style = successStyle;
            else _btnAnswer.Background = BrushGreen;
            _btnAnswer.Margin = new Thickness(4);
            _btnAnswer.Visibility = Visibility.Collapsed;
            _btnAnswer.Click += async delegate { await AnswerCallAsync(); };
            _btnDecline = MakeButton("Decline");
            Style dangerStyle = TryStyle("DangerButton");
            if (dangerStyle != null) _btnDecline.Style = dangerStyle;
            else _btnDecline.Background = BrushRed;
            _btnDecline.Margin = new Thickness(4);
            _btnDecline.Visibility = Visibility.Collapsed;
            _btnDecline.Click += async delegate { await EndCallAsync(); };
            Button btnCall = MakeButton("CALL");
            Style callStyle = TryStyle("CallButton");
            if (callStyle != null) { btnCall.Style = callStyle; btnCall.Padding = new Thickness(28, 8, 28, 8); }
            else btnCall.Background = BrushGreen;
            btnCall.FontWeight = FontWeights.Bold;
            btnCall.Margin = new Thickness(4);
            btnCall.ToolTip = "Place a call to the number (Enter in the number box also dials)";
            btnCall.Click += async delegate { await StartCallAsync(); };
            Button btnEnd = MakeButton("END");
            if (dangerStyle != null) { btnEnd.Style = dangerStyle; btnEnd.Padding = new Thickness(28, 8, 28, 8); }
            else btnEnd.Background = BrushRed;
            btnEnd.FontWeight = FontWeights.Bold;
            btnEnd.Margin = new Thickness(4);
            btnEnd.ToolTip = "End the current call";
            btnEnd.Click += async delegate { await EndCallAsync(); };
            actions.Children.Add(btnCall);
            actions.Children.Add(btnEnd);
            actions.Children.Add(_btnAnswer);
            actions.Children.Add(_btnDecline);
            _keypadPane.Children.Add(actions);

            _dtmfEcho = new TextBlock { Text = "", Foreground = BrushWarn, Margin = new Thickness(0, 6, 0, 0), HorizontalAlignment = HorizontalAlignment.Center, FontFamily = new FontFamily("Consolas"), Visibility = Visibility.Collapsed };
            _keypadPane.Children.Add(_dtmfEcho);

            // Recents pane: header (label + clear) + scrollable history rows
            Grid recHead = new Grid();
            recHead.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            recHead.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
            TextBlock recLabel = new TextBlock { Text = "RECENT", Foreground = BrushGray, FontWeight = FontWeights.Bold, FontSize = 11, VerticalAlignment = VerticalAlignment.Center };
            Button btnClearHist = new Button
            {
                Content = "Clear",
                Cursor = Cursors.Hand,
                FontSize = 11,
                Padding = new Thickness(8, 2, 8, 2),
                ToolTip = "Clear the call history",
                HorizontalAlignment = HorizontalAlignment.Right
            };
            btnClearHist.Click += delegate
            {
                _callHistory.Clear();
                SaveCallHistory();
                RefreshRecentsView();
                Log("Call history cleared.", BrushGray);
            };
            Grid.SetColumn(recLabel, 0);
            Grid.SetColumn(btnClearHist, 1);
            recHead.Children.Add(recLabel);
            recHead.Children.Add(btnClearHist);
            _recentsPane.Children.Add(recHead);

            _recentsEmpty = new TextBlock
            {
                Text = "No calls yet. Placed, answered and missed calls show up here.",
                Foreground = BrushGray,
                FontSize = 11,
                TextWrapping = TextWrapping.Wrap,
                Margin = new Thickness(0, 8, 0, 0)
            };
            _recentsPane.Children.Add(_recentsEmpty);

            ScrollViewer recScroll = new ScrollViewer
            {
                MaxHeight = 300,
                Margin = new Thickness(0, 8, 0, 0),
                VerticalScrollBarVisibility = ScrollBarVisibility.Auto,
                HorizontalScrollBarVisibility = ScrollBarVisibility.Disabled
            };
            _recentsPanel = new StackPanel();
            recScroll.Content = _recentsPanel;
            _recentsPane.Children.Add(recScroll);
            SelectDialerPane(true);
            RefreshRecentsView();
            ScrollViewer leftScroll = new ScrollViewer
            {
                Content = left,
                VerticalScrollBarVisibility = ScrollBarVisibility.Auto,
                HorizontalScrollBarVisibility = ScrollBarVisibility.Disabled
            };
            Grid.SetRow(leftScroll, 1);
            Grid.SetColumn(leftScroll, 0);
            g.Children.Add(leftScroll);

            // Right: VoIP / LAN call panel (modern card layout)
            StackPanel right = new StackPanel { Margin = new Thickness(10, 8, 8, 8) };
            Grid.SetRow(right, 1);

            _clipText = new TextBlock { Text = "", Foreground = BrushAccent, FontSize = 13, Margin = new Thickness(0, 0, 0, 8), TextWrapping = TextWrapping.Wrap };
            right.Children.Add(_clipText);

            // Calls (LAN + internet via relay)
            GroupBox voipGroup = MakeGroup("Calls (LAN + Internet)");
            StackPanel voipSp = new StackPanel { Margin = new Thickness(4) };
            _voipStateText = new TextBlock { Text = "Idle", Foreground = BrushGray, FontWeight = FontWeights.Bold, Margin = new Thickness(0, 2, 0, 6) };
            voipSp.Children.Add(_voipStateText);

            // identity + relay settings
            StackPanel idRow = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 2, 0, 4) };
            idRow.Children.Add(new TextBlock { Text = "My #:", Foreground = BrushGray, VerticalAlignment = VerticalAlignment.Center, Margin = new Thickness(0, 0, 6, 0) });
            _txtMyNumber = MakeTextBox(118);
            _txtMyNumber.IsReadOnly = true;
            _txtMyNumber.IsReadOnlyCaretVisible = false;
            _txtMyNumber.ToolTip = "This device's virtual number - other devices dial this number over the internet";
            idRow.Children.Add(_txtMyNumber);
            voipSp.Children.Add(idRow);
            StackPanel relayRow = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 0, 0, 4) };
            relayRow.Children.Add(new TextBlock { Text = "Relay:", Foreground = BrushGray, VerticalAlignment = VerticalAlignment.Center, Margin = new Thickness(0, 0, 6, 0) });
            _txtRelay = MakeTextBox(118);
            _txtRelay.ToolTip = "Call server address (host:port), e.g. 192.168.1.10:45675 - press Enter to apply";
            _txtRelay.KeyDown += delegate(object s, KeyEventArgs e)
            {
                if (e.Key == Key.Enter) { e.Handled = true; ApplyCallSettings(); }
            };
            relayRow.Children.Add(_txtRelay);
            _chkHostCalls = new CheckBox
            {
                Content = "Host server",
                Foreground = BrushFg,
                Margin = new Thickness(8, 0, 0, 0),
                VerticalAlignment = VerticalAlignment.Center,
                ToolTip = "Run the internet call server on this PC (port " + CallServer.DEFAULT_PORT + ")"
            };
            _chkHostCalls.Checked += delegate { EnsureCallServer(); SaveStateSafe(); };
            _chkHostCalls.Unchecked += delegate
            {
                if (_callServer != null)
                {
                    try { _callServer.Stop(); } catch { }
                    _callServer = null;
                    Log("Call server stopped.", BrushGray);
                }
                SaveStateSafe();
            };
            relayRow.Children.Add(_chkHostCalls);
            voipSp.Children.Add(relayRow);

            // Which server is this, really? Deliberately a standing line rather than a
            // log message: the fingerprint is only worth anything while somebody can
            // still see it, and a relay that swaps its key must not be able to do that
            // behind a wall of scrolled-past gray text.
            _relayTrustText = new TextBlock
            {
                Text = "Relay identity: not connected yet",
                Foreground = BrushGray,
                FontSize = 11,
                TextWrapping = TextWrapping.Wrap,
                Margin = new Thickness(0, 0, 0, 4)
            };
            // Deliberately NO AutomationProperties.Name on this one. Setting a Name on a
            // TextBlock replaces the text a screen reader speaks, so naming it "Relay
            // identity" would have made the element findable and its actual content - the
            // fingerprint somebody is supposed to compare - unreadable. The text carries
            // its own label for that reason.
            voipSp.Children.Add(_relayTrustText);
            _chkRelayMedia = new CheckBox
            {
                Content = "Route calls through the relay",
                Foreground = BrushFg,
                VerticalAlignment = VerticalAlignment.Center,
                Margin = new Thickness(0, 0, 0, 4),
                ToolTip = "Send call audio and video over the relay instead of directly to the peer. " +
                          "Use it where UDP is blocked or shaped (hotspots, corporate Wi-Fi, symmetric NAT); " +
                          "it adds one hop and does not hide your address from the peer."
            };
            _chkRelayMedia.SetValue(System.Windows.Automation.AutomationProperties.NameProperty, "Route calls through the relay");
            _chkRelayMedia.Checked += delegate { ApplyCallSettings(); SaveStateSafe(); };
            _chkRelayMedia.Unchecked += delegate { ApplyCallSettings(); SaveStateSafe(); };
            voipSp.Children.Add(_chkRelayMedia);
            _chkPortMap = new CheckBox
            {
                Content = "Open my router port (UPnP)",
                Foreground = BrushFg,
                VerticalAlignment = VerticalAlignment.Center,
                Margin = new Thickness(0, 0, 0, 4),
                ToolTip = "When this PC hosts the relay, ask the router to forward its port so peers " +
                          "outside this network can reach it. Needs a router that answers UPnP: it does " +
                          "nothing on a VPS, a corporate network, or carrier-grade NAT, and the log says " +
                          "which of those happened."
            };
            _chkPortMap.SetValue(System.Windows.Automation.AutomationProperties.NameProperty, "Open my router port (UPnP)");
            _chkPortMap.Checked += delegate
            {
                SaveStateSafe();
                if (_callServer != null && _callServer.Running) TryOpenRouterPort(_callServer, CallServer.DEFAULT_PORT);
                else Log("Turn on Host server first - there is nothing to open a port for yet.", BrushGray);
            };
            _chkPortMap.Unchecked += delegate { SaveStateSafe(); };
            voipSp.Children.Add(_chkPortMap);

            voipSp.Children.Add(new TextBlock { Text = "Peers (LAN + directory):", Foreground = BrushGray, Margin = new Thickness(0, 2, 0, 2) });
            _lvPeers = new ListView
            {
                Background = BrushPanel,
                Foreground = BrushFg,
                BorderBrush = BrushBorder,
                Height = 110,
                Margin = new Thickness(0, 0, 0, 4)
            };
            GridView peersGv = new GridView();
            peersGv.Columns.Add(new GridViewColumn { Header = "Status", Width = 92, DisplayMemberBinding = new Binding("Status") });
            peersGv.Columns.Add(new GridViewColumn { Header = "Peer", Width = 140, DisplayMemberBinding = new Binding("Name") });
            peersGv.Columns.Add(new GridViewColumn { Header = "Address", Width = 130, DisplayMemberBinding = new Binding("Address") });
            _lvPeers.View = peersGv;
            voipSp.Children.Add(_lvPeers);
            StackPanel ipRow = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 2, 0, 4) };
            ipRow.Children.Add(new TextBlock { Text = "IP:", Foreground = BrushGray, VerticalAlignment = VerticalAlignment.Center, Margin = new Thickness(0, 0, 6, 0) });
            _txtVoipIp = MakeTextBox(140);
            _txtVoipIp.ToolTip = "Peer IP if not auto-discovered";
            // accessible name: screen readers + UIA automation can find it
            _txtVoipIp.SetValue(System.Windows.Automation.AutomationProperties.NameProperty, "Peer IP");
            ipRow.Children.Add(_txtVoipIp);
            voipSp.Children.Add(ipRow);
            StackPanel voipBtns = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 2, 0, 0) };
            _btnVoipVoice = MakeButton("Voice Call");
            _btnVoipVoice.Background = BrushGreen;
            _btnVoipVoice.Margin = new Thickness(0, 0, 4, 0);
            _btnVoipVoice.Click += delegate { StartVoipCall(false); };
            _btnVoipVideo = MakeButton("Video Call");
            _btnVoipVideo.Background = BrushAccent;
            _btnVoipVideo.Margin = new Thickness(0, 0, 4, 0);
            _btnVoipVideo.Click += delegate { StartVoipCall(true); };
            _btnVoipHangup = MakeButton("Hang Up");
            _btnVoipHangup.Background = BrushRed;
            _btnVoipHangup.IsEnabled = false;
            _btnVoipHangup.ToolTip = "End the VoIP call";
            _btnVoipHangup.Click += delegate { HangupVoip(); };
            voipBtns.Children.Add(_btnVoipVoice);
            voipBtns.Children.Add(_btnVoipVideo);
            voipBtns.Children.Add(_btnVoipHangup);
            voipSp.Children.Add(voipBtns);
            // call-quality options: mic noise filter + WAV archive
            StackPanel voipOpts = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 8, 0, 0) };
            _chkNoiseFilter = new CheckBox
            {
                Content = "Noise filter",
                Foreground = BrushFg,
                IsChecked = true,
                VerticalAlignment = VerticalAlignment.Center,
                Margin = new Thickness(0, 0, 16, 0),
                ToolTip = "Noise gate + AGC + echo cancel on the microphone"
            };
            _chkNoiseFilter.Checked += delegate
            {
                _audioFilter.Enabled = true;
                if (_cfg != null) { _cfg.noise_filter = true; try { _cfg.Save(); } catch { } }
            };
            _chkNoiseFilter.Unchecked += delegate
            {
                _audioFilter.Enabled = false;
                if (_cfg != null) { _cfg.noise_filter = false; try { _cfg.Save(); } catch { } }
            };
            _chkRecordCalls = new CheckBox
            {
                Content = "Record calls",
                Foreground = BrushFg,
                IsChecked = false,
                VerticalAlignment = VerticalAlignment.Center,
                ToolTip = "Save each VoIP call as a stereo WAV in recordings\\ (left = peer, right = you)"
            };
            _chkRecordCalls.Checked += delegate
            {
                if (_cfg != null) { _cfg.record_calls = true; try { _cfg.Save(); } catch { } }
            };
            _chkRecordCalls.Unchecked += delegate
            {
                if (_cfg != null) { _cfg.record_calls = false; try { _cfg.Save(); } catch { } }
            };
            voipOpts.Children.Add(_chkNoiseFilter);
            voipOpts.Children.Add(_chkRecordCalls);
            // Wake agent: the only way traffic for this number survives the
            // window being shut. Off by default because it registers a listener
            // that runs when the user is not looking, so it must be a choice.
            _chkAlwaysAwake = new CheckBox
            {
                Content = "Always awake",
                Foreground = BrushFg,
                IsChecked = false,
                VerticalAlignment = VerticalAlignment.Center,
                Margin = new Thickness(0, 0, 16, 0),
                ToolTip = "Leave a headless listener (UssdAgent.exe) on the relay when this window closes, and start it at sign-in. It decrypts and stores what arrives, then wakes the window - it cannot answer a call."
            };
            _chkAlwaysAwake.Checked += delegate
            {
                if (_suppressWakeAgentToggle || _cfg == null) return;
                _cfg.always_awake = true;
                try { _cfg.Save(); } catch { }
                Log("Wake agent: on. It takes over the relay when this window closes.", BrushSuccess);
                RegisterWakeAgentAtLogin(true);
            };
            _chkAlwaysAwake.Unchecked += delegate
            {
                if (_suppressWakeAgentToggle || _cfg == null) return;
                _cfg.always_awake = false;
                try { _cfg.Save(); } catch { }
                RegisterWakeAgentAtLogin(false);
                Log("Wake agent: off. Nothing will catch traffic while this window is shut.", BrushWarn);
            };
            voipOpts.Children.Add(_chkAlwaysAwake);
            voipSp.Children.Add(voipOpts);

            // D1b: the route table on screen. The router already knows which link
            // can carry what, and who it is allowed to help; showing that turns
            // "your message went this way" from a claim into something to look at.
            voipSp.Children.Add(new TextBlock { Text = "Routes (links your traffic can use):", Foreground = BrushGray, Margin = new Thickness(0, 10, 0, 2) });
            _lvRoutes = new ListView
            {
                Background = BrushPanel,
                Foreground = BrushFg,
                BorderBrush = BrushBorder,
                Height = 78,
                Margin = new Thickness(0, 0, 0, 4)
            };
            _lvRoutes.SetValue(System.Windows.Automation.AutomationProperties.NameProperty, "Route table");
            GridView routesGv = new GridView();
            routesGv.Columns.Add(new GridViewColumn { Header = "Link", Width = 70, DisplayMemberBinding = new Binding("Link") });
            routesGv.Columns.Add(new GridViewColumn { Header = "State", Width = 54, DisplayMemberBinding = new Binding("Ready") });
            routesGv.Columns.Add(new GridViewColumn { Header = "Max frame", Width = 74, DisplayMemberBinding = new Binding("MaxFrame") });
            routesGv.Columns.Add(new GridViewColumn { Header = "Speed", Width = 74, DisplayMemberBinding = new Binding("BitRate") });
            routesGv.Columns.Add(new GridViewColumn { Header = "For others", Width = 110, DisplayMemberBinding = new Binding("Consent") });
            _lvRoutes.View = routesGv;
            voipSp.Children.Add(_lvRoutes);

            StackPanel routeCtl = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 2, 0, 0) };
            _chkCarryPeers = new CheckBox
            {
                Content = "Carry traffic for other peers",
                Foreground = BrushFg,
                IsChecked = _cfg != null && _cfg.carry_for_peers,
                VerticalAlignment = VerticalAlignment.Center,
                Margin = new Thickness(0, 0, 12, 0),
                ToolTip = "On a mesh or radio link, your node relays for people you are not talking to. Off means those links carry only your own traffic. The relay hop is unaffected - it never carries anyone else's."
            };
            _chkCarryPeers.SetValue(System.Windows.Automation.AutomationProperties.NameProperty, "Carry traffic for other peers");
            _chkCarryPeers.Checked += delegate { SetCarryConsent(true); };
            _chkCarryPeers.Unchecked += delegate { SetCarryConsent(false); };
            Button btnRoutes = MakeButton("Refresh routes");
            btnRoutes.SetValue(System.Windows.Automation.AutomationProperties.NameProperty, "Refresh routes");
            btnRoutes.Click += delegate { RefreshRouteTable(); };
            routeCtl.Children.Add(_chkCarryPeers);
            routeCtl.Children.Add(btnRoutes);
            voipSp.Children.Add(routeCtl);
            RefreshRouteTable();
            voipGroup.Content = voipSp;
            right.Children.Add(voipGroup);

            ScrollViewer rightScroll = new ScrollViewer
            {
                Content = right,
                VerticalScrollBarVisibility = ScrollBarVisibility.Auto,
                HorizontalScrollBarVisibility = ScrollBarVisibility.Disabled
            };
            Grid.SetRow(rightScroll, 1);
            Grid.SetColumn(rightScroll, 1);
            g.Children.Add(rightScroll);

            _dialerGrid = g;
            BuildCallOverlay(g);
            return g;
        }

        // ---------- Video Call page (Zoom/Teams-style stage) ----------
        // Full-bleed video canvas; self-view is a picture-in-picture card in
        // ── Video Call Page — Google Meet-style full-screen stage ─────────
        // Row 0: top header bar (peer name + state + timer + end call)
        // Row 1: video stage (fills all space — remote video + PiP + idle card)
        // Row 2: floating control bar (mute / cam / share / end)
        private Grid BuildVideoTab()
        {
            Grid g = new Grid();
            g.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });        // 0: header
            g.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) }); // 1: stage
            g.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });        // 2: controls

            // ── Header ────────────────────────────────────────────────────
            Border header = new Border
            {
                Background = new SolidColorBrush(Color.FromRgb(0x12, 0x14, 0x1e)),
                BorderBrush = new SolidColorBrush(Color.FromRgb(0x2a, 0x2c, 0x3e)),
                BorderThickness = new Thickness(0, 0, 0, 1),
                Padding = new Thickness(16, 10, 16, 10)
            };
            DockPanel hdp = new DockPanel { LastChildFill = false };

            // Left: peer name + live state badge
            StackPanel hLeft = new StackPanel { Orientation = Orientation.Horizontal };
            System.Windows.Shapes.Ellipse liveDotVid = new System.Windows.Shapes.Ellipse
            {
                Width = 9, Height = 9,
                Fill = new SolidColorBrush(Color.FromRgb(0x33, 0xd0, 0x7a)),
                VerticalAlignment = VerticalAlignment.Center,
                Margin = new Thickness(0, 0, 8, 0)
            };
            _tileRemoteName = new TextBlock
            {
                Text = "Video Call",
                Foreground = Brushes.White,
                FontSize = 14,
                FontWeight = FontWeights.Bold,
                VerticalAlignment = VerticalAlignment.Center
            };
            _videoStateText = new TextBlock
            {
                Text = "waiting...",
                Foreground = new SolidColorBrush(Color.FromRgb(0x94, 0xa3, 0xb8)),
                FontSize = 11,
                VerticalAlignment = VerticalAlignment.Center,
                Margin = new Thickness(10, 0, 0, 0)
            };
            hLeft.Children.Add(liveDotVid);
            hLeft.Children.Add(_tileRemoteName);
            hLeft.Children.Add(_videoStateText);
            DockPanel.SetDock(hLeft, Dock.Left);
            hdp.Children.Add(hLeft);

            // Right: timer + chat toggle + end call
            StackPanel hRight = new StackPanel { Orientation = Orientation.Horizontal };
            TextBlock vidTimer = new TextBlock
            {
                Text = "",
                Foreground = new SolidColorBrush(Color.FromRgb(0x94, 0xa3, 0xb8)),
                FontFamily = new FontFamily("Consolas"),
                FontSize = 13,
                VerticalAlignment = VerticalAlignment.Center,
                Margin = new Thickness(0, 0, 16, 0)
            };
            // Wire timer updates — the existing tick updates _voipStateText; we
            // hook into VoIP state via a tag so the header timer stays current.
            _stageTag = vidTimer;   // reuse _stageTag as the timer reference
            hRight.Children.Add(vidTimer);

            Button btnChatToggle = MakeButton("\uD83D\uDCAC  Chat");
            btnChatToggle.Margin = new Thickness(0, 0, 8, 0);
            btnChatToggle.Padding = new Thickness(12, 5, 12, 5);
            bool chatDrawerOpen = false;
            Border chatDrawer = null;   // built below; reference set after
            btnChatToggle.Click += delegate
            {
                chatDrawerOpen = !chatDrawerOpen;
                if (chatDrawer != null)
                    chatDrawer.Visibility = chatDrawerOpen ? Visibility.Visible : Visibility.Collapsed;
            };
            hRight.Children.Add(btnChatToggle);

            Button btnEndVid = MakeButton("\uD83D\uDD34  End Call");
            Style dangerStyle = TryStyle("DangerButton");
            if (dangerStyle != null) btnEndVid.Style = dangerStyle;
            btnEndVid.Padding = new Thickness(14, 6, 14, 6);
            btnEndVid.FontWeight = FontWeights.Bold;
            btnEndVid.Click += delegate { HangupVoip(); };
            hRight.Children.Add(btnEndVid);
            DockPanel.SetDock(hRight, Dock.Right);
            hdp.Children.Add(hRight);

            header.Child = hdp;
            Grid.SetRow(header, 0);
            g.Children.Add(header);

            // ── Stage ─────────────────────────────────────────────────────
            // Dark canvas that fills all available space.
            Border stage = new Border
            {
                Background = new SolidColorBrush(Color.FromRgb(0x0c, 0x0e, 0x16)),
                ClipToBounds = true
            };
            Grid sg = new Grid();

            // Remote video stream (fills stage)
            _imgRemote = new Image { Stretch = Stretch.Uniform, VerticalAlignment = VerticalAlignment.Center };
            sg.Children.Add(_imgRemote);

            // Group-call tile grid. Collapsed unless we are in a room: a 1:1
            // call gets the full-bleed stage, a group gets one tile each.
            _confTiles = new UniformGrid { Rows = 0, Columns = 0, Margin = new Thickness(6) };
            _confHost = new Border
            {
                Background = new SolidColorBrush(Color.FromRgb(0x0c, 0x0e, 0x16)),
                Visibility = Visibility.Collapsed,
                Child = _confTiles
            };
            sg.Children.Add(_confHost);

            // Room status, top-left of the stage
            _confTag = new TextBlock
            {
                Visibility = Visibility.Collapsed,
                HorizontalAlignment = HorizontalAlignment.Left,
                VerticalAlignment = VerticalAlignment.Top,
                Margin = new Thickness(14, 12, 14, 12),
                Padding = new Thickness(10, 4, 10, 4),
                Background = new SolidColorBrush(Color.FromArgb(170, 0, 0, 0)),
                Foreground = Brushes.White,
                FontSize = 12,
                FontWeight = FontWeights.SemiBold
            };
            sg.Children.Add(_confTag);

            // Live transcription subtitles: bottom-centre, above the control pill.
            // Collapsed until whisper gives us something to say.
            _subsText = new TextBlock
            {
                Visibility = Visibility.Collapsed,
                MaxWidth = 620,
                TextWrapping = TextWrapping.Wrap,
                TextAlignment = TextAlignment.Center,
                FontSize = 15,
                FontWeight = FontWeights.SemiBold,
                Foreground = Brushes.White,
                Background = new SolidColorBrush(Color.FromArgb(150, 0, 0, 0)),
                Padding = new Thickness(12, 6, 12, 6),
                HorizontalAlignment = HorizontalAlignment.Center,
                VerticalAlignment = VerticalAlignment.Bottom,
                Margin = new Thickness(0, 0, 0, 88)
            };
            sg.Children.Add(_subsText);

            // Idle state card (shown when no call is active)
            _vidIdle = new StackPanel
            {
                HorizontalAlignment = HorizontalAlignment.Center,
                VerticalAlignment = VerticalAlignment.Center,
                IsHitTestVisible = false
            };
            // Animated gradient avatar
            _vidIdleAvatar = new System.Windows.Shapes.Ellipse
            {
                Width = 110, Height = 110,
                Fill = new LinearGradientBrush(
                    new GradientStopCollection(new GradientStop[] {
                        new GradientStop(Color.FromRgb(0x4f, 0x8c, 0xff), 0),
                        new GradientStop(Color.FromRgb(0x7b, 0x5c, 0xff), 1) }),
                    90),
                HorizontalAlignment = HorizontalAlignment.Center
            };
            _vidIdle.Children.Add(_vidIdleAvatar);
            _vidIdle.Children.Add(new TextBlock
            {
                Text = "No active video call",
                Foreground = new SolidColorBrush(Color.FromRgb(0xd0, 0xd8, 0xf0)),
                FontSize = 18,
                FontWeight = FontWeights.SemiBold,
                HorizontalAlignment = HorizontalAlignment.Center,
                Margin = new Thickness(0, 16, 0, 4)
            });
            _vidIdle.Children.Add(new TextBlock
            {
                Text = "Open the Chat Hub, select a peer and tap 🎥 Video\nor dial a 700-XXXXXXX app number from the Dialer.",
                Foreground = new SolidColorBrush(Color.FromRgb(0x64, 0x74, 0x90)),
                FontSize = 12,
                TextAlignment = TextAlignment.Center,
                Margin = new Thickness(0, 0, 0, 16),
                TextWrapping = TextWrapping.Wrap
            });
            Button cta = MakeButton("Go to Dialer");
            cta.Background = BrushAccent;
            cta.Padding = new Thickness(20, 8, 20, 8);
            cta.HorizontalAlignment = HorizontalAlignment.Center;
            cta.Click += delegate { ShowPage(0); };
            _vidIdle.Children.Add(cta);
            _vidIdleButton = cta;
            sg.Children.Add(_vidIdle);

            // Picture-in-picture self view (draggable bottom-right)
            Border pip = new Border
            {
                Width = 200, Height = 118,
                Background = Brushes.Black,
                CornerRadius = new CornerRadius(10),
                BorderBrush = new SolidColorBrush(Color.FromRgb(0x22, 0xc5, 0x5e)),
                BorderThickness = new Thickness(2),
                HorizontalAlignment = HorizontalAlignment.Right,
                VerticalAlignment = VerticalAlignment.Bottom,
                Margin = new Thickness(0, 0, 16, 16),
                ClipToBounds = true,
                Cursor = Cursors.SizeAll
            };
            Grid ppg = new Grid();
            _imgLocal = new Image { Stretch = Stretch.UniformToFill };
            ppg.Children.Add(_imgLocal);
            // "You" label
            Border pipLabel = new Border
            {
                Background = new SolidColorBrush(Color.FromArgb(160, 0, 0, 0)),
                CornerRadius = new CornerRadius(0, 0, 8, 0),
                HorizontalAlignment = HorizontalAlignment.Left,
                VerticalAlignment = VerticalAlignment.Bottom,
                Padding = new Thickness(8, 3, 8, 3)
            };
            _tileLocalName = new TextBlock { Text = "You", Foreground = Brushes.White, FontSize = 11, FontWeight = FontWeights.SemiBold };
            pipLabel.Child = _tileLocalName;
            ppg.Children.Add(pipLabel);
            pip.Child = ppg;
            sg.Children.Add(pip);
            _pipHost = pip;   // hidden in a group call - self gets a real tile

            // Slide-over chat drawer (right side, hidden by default)
            chatDrawer = new Border
            {
                Width = 280,
                Background = new SolidColorBrush(Color.FromArgb(230, 0x1e, 0x20, 0x30)),
                BorderBrush = new SolidColorBrush(Color.FromRgb(0x33, 0x35, 0x50)),
                BorderThickness = new Thickness(1, 0, 0, 0),
                HorizontalAlignment = HorizontalAlignment.Right,
                VerticalAlignment = VerticalAlignment.Stretch,
                Visibility = Visibility.Collapsed,
                Padding = new Thickness(0)
            };
            Grid chatDrawerGrid = new Grid();
            chatDrawerGrid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            chatDrawerGrid.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) });
            chatDrawerGrid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });

            Border chatHdr = new Border { Padding = new Thickness(12, 10, 12, 10), BorderBrush = new SolidColorBrush(Color.FromRgb(0x33, 0x35, 0x50)), BorderThickness = new Thickness(0, 0, 0, 1) };
            DockPanel chatHdrDp = new DockPanel { LastChildFill = false };
            TextBlock chatHdrLbl = new TextBlock { Text = "In-Call Chat", FontSize = 13, FontWeight = FontWeights.Bold, Foreground = Brushes.White, VerticalAlignment = VerticalAlignment.Center };
            DockPanel.SetDock(chatHdrLbl, Dock.Left);
            chatHdrDp.Children.Add(chatHdrLbl);
            chatHdr.Child = chatHdrDp;
            Grid.SetRow(chatHdr, 0);
            chatDrawerGrid.Children.Add(chatHdr);

            _lvVideoChat = new ListBox
            {
                Background = Brushes.Transparent,
                BorderThickness = new Thickness(0),
                Foreground = Brushes.White,
                FontSize = 12,
                Padding = new Thickness(8)
            };
            _lvVideoChat.Items.Add("Chat is available during calls");
            ScrollViewer.SetVerticalScrollBarVisibility(_lvVideoChat, ScrollBarVisibility.Auto);
            Grid.SetRow(_lvVideoChat, 1);
            chatDrawerGrid.Children.Add(_lvVideoChat);

            Border chatInput = new Border { Padding = new Thickness(8), BorderBrush = new SolidColorBrush(Color.FromRgb(0x33, 0x35, 0x50)), BorderThickness = new Thickness(0, 1, 0, 0) };
            DockPanel chatSendRow = new DockPanel { LastChildFill = true };
            _txtVideoChat = MakeTextBox(0);
            _txtVideoChat.ToolTip = "Message — Enter to send";
            _txtVideoChat.KeyDown += delegate(object s, KeyEventArgs e)
            {
                if (e.Key == Key.Enter) { e.Handled = true; SendVideoChat(); }
            };
            Button btnVidSend = MakeButton("Send");
            Style ps2 = TryStyle("PrimaryButton"); if (ps2 != null) btnVidSend.Style = ps2;
            btnVidSend.Padding = new Thickness(10, 5, 10, 5);
            btnVidSend.Margin = new Thickness(6, 0, 0, 0);
            DockPanel.SetDock(btnVidSend, Dock.Right);
            chatSendRow.Children.Add(btnVidSend);
            chatSendRow.Children.Add(_txtVideoChat);
            chatInput.Child = chatSendRow;
            Grid.SetRow(chatInput, 2);
            chatDrawerGrid.Children.Add(chatInput);
            chatDrawer.Child = chatDrawerGrid;
            sg.Children.Add(chatDrawer);

            stage.Child = sg;
            Grid.SetRow(stage, 1);
            g.Children.Add(stage);

            // ── Floating control bar (bottom, centered, glassmorphism pill) ─
            Border ctrlOuter = new Border
            {
                Background = new SolidColorBrush(Color.FromArgb(0, 0, 0, 0)),  // transparent container
                Padding = new Thickness(0, 0, 0, 16),
                VerticalAlignment = VerticalAlignment.Bottom,
                HorizontalAlignment = HorizontalAlignment.Stretch,
                IsHitTestVisible = false  // only the pill buttons catch clicks
            };
            Border ctrlPill = new Border
            {
                Background = new SolidColorBrush(Color.FromArgb(210, 0x14, 0x16, 0x22)),
                CornerRadius = new CornerRadius(28),
                Padding = new Thickness(12, 8, 12, 8),
                HorizontalAlignment = HorizontalAlignment.Center,
                IsHitTestVisible = true,
                Effect = TryFindEffect("PillShadow")
            };
            StackPanel ctrlBar = new StackPanel { Orientation = Orientation.Horizontal };

            // Helper: make a round control button with icon + label
            Func<string, string, Button> makeCtrlBtn = delegate(string icon, string label)
            {
                Button cb = new Button
                {
                    Background = new SolidColorBrush(Color.FromArgb(100, 0x30, 0x32, 0x45)),
                    BorderThickness = new Thickness(0),
                    Padding = new Thickness(0),
                    Width = 52, Height = 52,
                    Margin = new Thickness(5, 0, 5, 0),
                    Cursor = Cursors.Hand,
                    ToolTip = label
                };
                StackPanel cbsp = new StackPanel { HorizontalAlignment = HorizontalAlignment.Center, VerticalAlignment = VerticalAlignment.Center };
                cbsp.Children.Add(new TextBlock { Text = icon, FontSize = 18, HorizontalAlignment = HorizontalAlignment.Center });
                cbsp.Children.Add(new TextBlock { Text = label, FontSize = 9, Foreground = new SolidColorBrush(Color.FromRgb(0x94, 0xa3, 0xb8)), HorizontalAlignment = HorizontalAlignment.Center, Margin = new Thickness(0, 2, 0, 0) });
                cb.Content = cbsp;
                // Rounded template override
                ControlTemplate ct = new ControlTemplate(typeof(Button));
                FrameworkElementFactory bef = new FrameworkElementFactory(typeof(Border));
                bef.SetValue(Border.BackgroundProperty, new TemplateBindingExtension(Button.BackgroundProperty));
                bef.SetValue(Border.CornerRadiusProperty, new CornerRadius(26));
                FrameworkElementFactory cpf = new FrameworkElementFactory(typeof(ContentPresenter));
                cpf.SetValue(ContentPresenter.HorizontalAlignmentProperty, HorizontalAlignment.Center);
                cpf.SetValue(ContentPresenter.VerticalAlignmentProperty, VerticalAlignment.Center);
                bef.AppendChild(cpf);
                ct.VisualTree = bef;
                cb.Template = ct;
                return cb;
            };

            _btnMuteMic = makeCtrlBtn("\uD83C\uDFA4", "Mute");
            _btnMuteMic.Click += delegate { ToggleMicMute(); };
            ctrlBar.Children.Add(_btnMuteMic);

            _btnCamToggle = makeCtrlBtn("\uD83D\uDCF9", "Camera");
            _btnCamToggle.Click += delegate { ToggleCamera(); };
            ctrlBar.Children.Add(_btnCamToggle);

            // Group call: invites one more peer into the room we are in
            // (creating the room on first use).
            _btnAddParticipant = makeCtrlBtn("\uD83D\uDC65", "Add");
            _btnAddParticipant.ToolTip = "Add participant (group call)";
            _btnAddParticipant.Click += delegate { AddParticipantClick(); };
            ctrlBar.Children.Add(_btnAddParticipant);

            _btnShare = makeCtrlBtn("\uD83D\uDDA5", "Share");
            _btnShare.Click += delegate { ToggleScreenShare(); };
            ctrlBar.Children.Add(_btnShare);

            // Chat toggle in control bar too
            Button btnChatBar = makeCtrlBtn("\uD83D\uDCAC", "Chat");
            btnChatBar.Click += delegate
            {
                chatDrawerOpen = !chatDrawerOpen;
                chatDrawer.Visibility = chatDrawerOpen ? Visibility.Visible : Visibility.Collapsed;
            };
            ctrlBar.Children.Add(btnChatBar);

            // End call — red
            Button btnEndBar = makeCtrlBtn("\uD83D\uDD34", "End");
            btnEndBar.Background = new SolidColorBrush(Color.FromRgb(0xef, 0x44, 0x44));
            btnEndBar.Click += delegate { HangupVoip(); };
            ctrlBar.Children.Add(btnEndBar);

            ctrlPill.Child = ctrlBar;
            ctrlOuter.Child = ctrlPill;
            ctrlOuter.IsHitTestVisible = true;
            Grid.SetRow(ctrlOuter, 2);
            g.Children.Add(ctrlOuter);

            // Wire old side-panel references so SetVideoSide / SetVideoSideTab still compile
            _sideCol = new ColumnDefinition { Width = new GridLength(0) };
            _sideHost = new Grid();
            _sideHostTag = new int[] { 0, 1 };
            _btnSideChat = makeCtrlBtn("\uD83D\uDCAC", "Chat");
            _btnSideNotes = makeCtrlBtn("\uD83D\uDCDD", "Notes");
            _btnSideToggle = makeCtrlBtn("\u25BA", "Hide");
            _lvMoments = new ListBox();

            _videoGrid = g;
            return g;
        }


        // Show / hide the video side panel (toolbar stays inside the stage).
        private void SetVideoSide(bool open)
        {
            if (_sideCol == null) return;
            _sideCol.Width = open ? new GridLength(300) : new GridLength(0);
            if (_btnSideToggle != null)
                _btnSideToggle.Content = open ? "\u25BA" : "\u25C4";
        }

        // Which of the two sidebar sections is visible (0 chat, 1 notes).
        private void SetVideoSideTab(int idx)
        {
            if (_sideHost == null || _sideHostTag == null) return;
            for (int i = 0; i < _sideHost.Children.Count && i < _sideHostTag.Length; i++)
                _sideHost.Children[i].Visibility = _sideHostTag[i] == idx ? Visibility.Visible : Visibility.Collapsed;
            if (_btnSideChat != null) _btnSideChat.Background = idx == 0 ? BrushAccent : null;
            if (_btnSideNotes != null) _btnSideNotes.Background = idx == 1 ? BrushAccent : null;
            _sideTab = idx;
        }

        // Camera preview toggle (local capture only; frames go out when in a call).
        private void ToggleCamera()
        {
            if (_camRun) StopCamera();
            else StartCamera();
            if (_btnCamToggle != null)
                _btnCamToggle.Content = _camRun ? "Camera On" : "Camera";
        }

        // Screen share: GDI capture of the desktop, downscaled 50%, JPEG-encoded
        // and sent over the same encrypted video channel as the camera (the
        // camera is paused while sharing so the channel carries one stream).
        private void ToggleScreenShare()
        {
            if (_shareRun) { StopScreenShare(); return; }
            if (_voip == null || !_voip.InCall)
            {
                Log("Screen share needs an active call.", BrushGray);
                return;
            }
            StartScreenShare();
        }

        private void StartScreenShare()
        {
            _camWasOn = _camRun;
            StopCamera();
            _shareRun = true;
            if (_btnShare != null) _btnShare.Content = "Stop Share";
            _shareThread = new Thread((ThreadStart)SharePump);
            _shareThread.IsBackground = true;
            _shareThread.Start();
            Log("Screen share: sending the desktop over the call...", BrushAccent);
        }

        private void StopScreenShare()
        {
            _shareRun = false;
            if (_btnShare != null) _btnShare.Content = "Share";
            Log("Screen share stopped.", BrushGray);
            if (_camWasOn && _voip != null && _voip.InCall && _voip.VideoCall) StartCamera();
        }

        [System.Runtime.InteropServices.DllImport("user32.dll")]
        private static extern int GetSystemMetrics(int index);

        // 8 fps desktop JPEG (VM metric: SM_XVIRTUALSCREEN=76..SM_YVIRTUALSCREEN=79)
        private byte[] CaptureScreenJpeg()
        {
            int x = GetSystemMetrics(76), y = GetSystemMetrics(77);
            int w = GetSystemMetrics(78), h = GetSystemMetrics(79);
            if (w <= 0 || h <= 0) { w = GetSystemMetrics(0); h = GetSystemMetrics(1); }
            if (w <= 0 || h <= 0) return null;
            using (System.Drawing.Bitmap big = new System.Drawing.Bitmap(w, h))
            using (System.Drawing.Graphics gr = System.Drawing.Graphics.FromImage(big))
            {
                gr.CopyFromScreen(x, y, 0, 0, new System.Drawing.Size(w, h));
                using (System.Drawing.Bitmap small = new System.Drawing.Bitmap(w / 2, h / 2))
                using (System.Drawing.Graphics g2 = System.Drawing.Graphics.FromImage(small))
                {
                    g2.InterpolationMode = System.Drawing.Drawing2D.InterpolationMode.Bicubic;
                    g2.DrawImage(big, 0, 0, w / 2, h / 2);
                    using (MemoryStream ms = new MemoryStream())
                    {
                        System.Drawing.Imaging.ImageCodecInfo jpg = null;
                        foreach (System.Drawing.Imaging.ImageCodecInfo c in System.Drawing.Imaging.ImageCodecInfo.GetImageEncoders())
                            if (c.MimeType == "image/jpeg") { jpg = c; break; }
                        if (jpg == null) { small.Save(ms, System.Drawing.Imaging.ImageFormat.Jpeg); return ms.ToArray(); }
                        System.Drawing.Imaging.EncoderParameters ep = new System.Drawing.Imaging.EncoderParameters(1);
                        ep.Param[0] = new System.Drawing.Imaging.EncoderParameter(System.Drawing.Imaging.Encoder.Quality, 55L);
                        small.Save(ms, jpg, ep);
                        return ms.ToArray();
                    }
                }
            }
        }

        private void SharePump()
        {
            int fid = 0;
            try
            {
                while (_shareRun && _voip != null && _voip.InCall)
                {
                    byte[] jpeg = CaptureScreenJpeg();
                    if (jpeg == null) break;
                    const int chunk = 1200;
                    int count = (jpeg.Length + chunk - 1) / chunk;
                    if (count <= 128)
                    {
                        fid = (fid + 1) & 0x7FFF;
                        for (int i = 0; i < count; i++)
                        {
                            int off = i * chunk;
                            int n = Math.Min(chunk, jpeg.Length - off);
                            byte[] part = new byte[n];
                            Buffer.BlockCopy(jpeg, off, part, 0, n);
                            _voip.Media.SendVideo(part, fid, i, count);
                        }
                        ShowLocalPreview(jpeg);
                    }
                    Thread.Sleep(120);   // ~8 fps
                }
            }
            catch (Exception ex) { Log("Screen share error: " + ex.Message, BrushWarn); }
            finally
            {
                bool stop = _shareRun;
                _shareRun = false;
                if (stop)
                    Dispatcher.BeginInvoke((Action)delegate
                    {
                        if (_btnShare != null) _btnShare.Content = "Share";
                    });
            }
        }

        private void ShowLocalPreview(byte[] jpeg)
        {
            Dispatcher.BeginInvoke((Action)delegate { ShowBitmap(_imgLocal, jpeg); });
        }

        // Decode a frozen JPEG into an image control (safe from any thread).
        private void ShowBitmap(Image img, byte[] jpeg)
        {
            if (img == null || jpeg == null) return;
            try
            {
                using (MemoryStream ms = new MemoryStream(jpeg))
                {
                    var bmp = new System.Windows.Media.Imaging.BitmapImage();
                    bmp.BeginInit();
                    bmp.CacheOption = System.Windows.Media.Imaging.BitmapCacheOption.OnLoad;
                    bmp.StreamSource = ms;
                    bmp.EndInit();
                    bmp.Freeze();
                    img.Source = bmp;
                }
            }
            catch { }
        }

        private void SendVideoChat()
        {
            if (_txtVideoChat == null) return;
            string t = (_txtVideoChat.Text ?? "").Trim();
            if (t.Length == 0) return;
            _txtVideoChat.Text = "";
            string stamp = DateTime.Now.ToString("HH:mm");
            if (_voip != null && _voip.SendChatCall(t))
            {
                if (_lvVideoChat != null)
                    _lvVideoChat.Items.Add(new ListViewItem { Content = stamp + "  You: " + t, Foreground = Theme.Success });
                Log("Call chat sent.", BrushGray);
            }
            else
            {
                if (_lvVideoChat != null)
                    _lvVideoChat.Items.Add(stamp + "  You: " + t + " (not delivered - no active peer chat)");
                Log("Call chat not delivered (no active peer).", BrushWarn);
            }
            if (_lvVideoChat != null) _lvVideoChat.ScrollIntoView(_lvVideoChat.Items[_lvVideoChat.Items.Count - 1]);
        }

        private static System.Windows.Media.Effects.Effect TryFindEffect(string key)
        {
            if (Application.Current == null) return null;
            return Application.Current.TryFindResource(key) as System.Windows.Media.Effects.Effect;
        }

        private Grid BuildContactsTab()
        {
            Grid g = new Grid { Margin = new Thickness(6) };
            g.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            g.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) });

            // WrapPanel: fields/buttons wrap onto a second line when the
            // window is narrow instead of being clipped off the card.
            WrapPanel form = new WrapPanel { Margin = new Thickness(8, 6, 8, 2) };

            Label lblName = MakeLabel("Name:");
            lblName.VerticalAlignment = VerticalAlignment.Center;
            form.Children.Add(lblName);
            _txtCName = MakeTextBox(160);
            _txtCName.VerticalAlignment = VerticalAlignment.Center;
            _txtCName.SetValue(System.Windows.Automation.AutomationProperties.NameProperty, "Contact name");
            _txtCName.KeyDown += delegate(object s, KeyEventArgs e)
            {
                if (e.Key == Key.Enter) { e.Handled = true; AddContactFromFields(); }
            };
            form.Children.Add(_txtCName);
            Label lblNum = MakeLabel("Number:");
            lblNum.VerticalAlignment = VerticalAlignment.Center;
            form.Children.Add(lblNum);
            _txtCNum = MakeTextBox(160);
            _txtCNum.VerticalAlignment = VerticalAlignment.Center;
            _txtCNum.SetValue(System.Windows.Automation.AutomationProperties.NameProperty, "Contact number");
            _txtCNum.KeyDown += delegate(object s, KeyEventArgs e)
            {
                if (e.Key == Key.Enter) { e.Handled = true; AddContactFromFields(); }
            };
            form.Children.Add(_txtCNum);

            Button btnAdd = MakeButton("Add");
            btnAdd.Margin = new Thickness(10, 4, 0, 4);
            btnAdd.VerticalAlignment = VerticalAlignment.Center;
            btnAdd.Click += delegate { AddContactFromFields(); };
            form.Children.Add(btnAdd);

            // filter chips: All | Favorites | SIM | Device
            string[] cfilters = new string[] { "All", "Favorites", "SIM", "Device" };
            for (int i = 0; i < cfilters.Length; i++)
            {
                string f = cfilters[i];
                RadioButton rb = new RadioButton
                {
                    Content = f,
                    Foreground = BrushFg,
                    IsChecked = (f == _contactFilter),
                    VerticalAlignment = VerticalAlignment.Center,
                    Margin = new Thickness(12, 4, 0, 4)
                };
                string fl = f;
                rb.Checked += delegate
                {
                    _contactFilter = fl;
                    RefreshContactsView();
                };
                form.Children.Add(rb);
            }

            Button btnImport = MakeButton("Import SIM");
            btnImport.Margin = new Thickness(12, 4, 0, 4);
            btnImport.VerticalAlignment = VerticalAlignment.Center;
            btnImport.Click += async delegate { await ImportSimContactsAsync(); };
            form.Children.Add(btnImport);

            Grid.SetRow(form, 0);
            g.Children.Add(form);

            // split view: contact list (left) + details/actions card (right)
            Grid split = new Grid();
            split.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            split.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(300) });

            _lvContacts = MakeListView();
            _lvContacts.MinHeight = 280;
            GridView gv = new GridView();
            gv.Columns.Add(new GridViewColumn { Header = "", Width = 34, DisplayMemberBinding = new Binding("Star") });
            gv.Columns.Add(new GridViewColumn { Header = "Name", Width = 180, DisplayMemberBinding = new Binding("Name") });
            gv.Columns.Add(new GridViewColumn { Header = "Number", Width = 150, DisplayMemberBinding = new Binding("Number") });
            gv.Columns.Add(new GridViewColumn { Header = "Source", Width = 80, DisplayMemberBinding = new Binding("Source") });
            _lvContacts.View = gv;
            _lvContacts.SelectionChanged += delegate { UpdateContactDetail(); };
            _lvContacts.MouseDoubleClick += async delegate { await DialSelectedContactAsync(); };
            Grid.SetColumn(_lvContacts, 0);
            split.Children.Add(_lvContacts);

            Border detail = new Border
            {
                Background = BrushPanel,
                BorderBrush = BrushBorder,
                BorderThickness = new Thickness(1),
                Margin = new Thickness(8, 0, 0, 0),
                Padding = new Thickness(12, 10, 12, 10)
            };
            StackPanel dp = new StackPanel { VerticalAlignment = VerticalAlignment.Top };
            _ctDetailTitle = new TextBlock
            {
                Text = "No contact selected",
                FontSize = 20,
                FontWeight = FontWeights.Bold,
                Foreground = BrushFg,
                TextWrapping = TextWrapping.Wrap
            };
            dp.Children.Add(_ctDetailTitle);
            _ctDetailNum = new TextBlock { Text = "", FontSize = 15, Foreground = BrushGray, Margin = new Thickness(0, 6, 0, 0) };
            dp.Children.Add(_ctDetailNum);
            _ctDetailSrc = new TextBlock { Text = "", FontSize = 13, Foreground = BrushGray, Margin = new Thickness(0, 2, 0, 0) };
            dp.Children.Add(_ctDetailSrc);
            _ctDetailFav = new TextBlock { Text = "", FontSize = 13, Foreground = BrushAccent, Margin = new Thickness(0, 2, 0, 0) };
            dp.Children.Add(_ctDetailFav);

            _ctBtnFav = MakeButton("\u2606 Favorite");
            _ctBtnFav.Margin = new Thickness(0, 14, 0, 0);
            _ctBtnFav.Click += delegate { ToggleSelectedFavorite(); };
            dp.Children.Add(_ctBtnFav);

            WrapPanel actions = new WrapPanel { Margin = new Thickness(0, 14, 0, 0) };
            _ctBtnCall = MakeButton("Call");
            _ctBtnCall.Background = BrushGreen;
            _ctBtnCall.Margin = new Thickness(0, 0, 6, 6);
            _ctBtnCall.Click += async delegate { await DialSelectedContactAsync(); };
            actions.Children.Add(_ctBtnCall);
            _ctBtnVideo = MakeButton("Video");
            _ctBtnVideo.Background = BrushAccent;
            _ctBtnVideo.Margin = new Thickness(0, 0, 6, 6);
            _ctBtnVideo.Click += delegate { VideoSelectedContact(); };
            actions.Children.Add(_ctBtnVideo);
            _ctBtnSms = MakeButton("SMS");
            _ctBtnSms.Margin = new Thickness(0, 0, 6, 6);
            _ctBtnSms.Click += delegate { SmsSelectedContact(); };
            actions.Children.Add(_ctBtnSms);
            _ctBtnDel = MakeButton("Delete");
            _ctBtnDel.Background = BrushRed;
            _ctBtnDel.Margin = new Thickness(0, 0, 6, 6);
            _ctBtnDel.Click += delegate { DeleteSelectedContact(); };
            actions.Children.Add(_ctBtnDel);
            dp.Children.Add(actions);
            detail.Child = dp;
            Grid.SetColumn(detail, 1);
            split.Children.Add(detail);

            Grid.SetRow(split, 1);
            g.Children.Add(split);

            UpdateContactDetail();
            return g;
        }

        // ═══════════════════════════════════════════════════════════════════
        //  3-PANE CHAT HUB  (replaces old BuildSmsTab)
        //
        //  Pane 1 (80px)  → Category rail: Peers / SMS Messages / SMS Codes
        //  Pane 2 (260px) → Filtered list; updates on every Pane-1 click
        //  Pane 3 (*)     → Active workspace: Chat | Voice call | Video call | OTP view
        // ═══════════════════════════════════════════════════════════════════
        private Grid BuildSmsTab()
        {
            // ── Root: 4 rows ──────────────────────────────────────────────
            // Row 0: OTP floating banner  (collapsed unless OTP detected)
            // Row 1: 3-pane body
            // Row 2: bottom status micro-bar
            Grid root = new Grid();
            root.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });   // OTP banner
            root.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) }); // body
            root.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });   // bottom bar

            // ── OTP Alert Banner ──────────────────────────────────────────
            Border otpBanner = new Border
            {
                Background = new SolidColorBrush(System.Windows.Media.Color.FromRgb(0x1a, 0x2e, 0x4a)),
                BorderBrush = Theme.Accent,
                BorderThickness = new Thickness(0, 0, 0, 2),
                Padding = new Thickness(14, 8, 14, 8),
                Visibility = Visibility.Collapsed
            };
            DockPanel obdp = new DockPanel { LastChildFill = false };
            TextBlock otpIcon = new TextBlock { Text = "\uD83D\uDD11", FontSize = 15, VerticalAlignment = VerticalAlignment.Center, Margin = new Thickness(0, 0, 8, 0) };
            DockPanel.SetDock(otpIcon, Dock.Left);
            obdp.Children.Add(otpIcon);

            _hubOtpFrom = new TextBlock { Text = "OTP from BankGh", Foreground = Theme.Text, FontWeight = FontWeights.Bold, VerticalAlignment = VerticalAlignment.Center };
            DockPanel.SetDock(_hubOtpFrom, Dock.Left);
            obdp.Children.Add(_hubOtpFrom);

            _hubOtpCode = new TextBlock { Text = "849201", Foreground = Theme.Accent, FontSize = 18, FontWeight = FontWeights.Bold, VerticalAlignment = VerticalAlignment.Center, Margin = new Thickness(12, 0, 12, 0), FontFamily = new FontFamily("Consolas") };
            DockPanel.SetDock(_hubOtpCode, Dock.Left);
            obdp.Children.Add(_hubOtpCode);

            _hubOtpExpiry = new TextBlock { Text = "Expires in 04:59", Foreground = BrushWarn, VerticalAlignment = VerticalAlignment.Center };
            DockPanel.SetDock(_hubOtpExpiry, Dock.Left);
            obdp.Children.Add(_hubOtpExpiry);

            // Right: action buttons
            Button btnBannerDismiss = MakeButton("Dismiss");
            btnBannerDismiss.Margin = new Thickness(8, 0, 0, 0);
            btnBannerDismiss.Click += delegate { otpBanner.Visibility = Visibility.Collapsed; if (_hubOtpTimer != null) _hubOtpTimer.Stop(); };
            DockPanel.SetDock(btnBannerDismiss, Dock.Right);
            obdp.Children.Add(btnBannerDismiss);

            Button btnBannerCopy = MakeButton("Copy Code");
            btnBannerCopy.Margin = new Thickness(0, 0, 6, 0);
            Style primaryStyle = TryStyle("PrimaryButton");
            if (primaryStyle != null) btnBannerCopy.Style = primaryStyle;
            btnBannerCopy.Click += delegate
            {
                if (_hubOtpCode != null)
                    try { Clipboard.SetText(_hubOtpCode.Text); Log("OTP copied: " + _hubOtpCode.Text, BrushSuccess); } catch { }
            };
            DockPanel.SetDock(btnBannerCopy, Dock.Right);
            obdp.Children.Add(btnBannerCopy);

            otpBanner.Child = obdp;
            Grid.SetRow(otpBanner, 0);
            root.Children.Add(otpBanner);

            // ── Body: 3-column pane grid ───────────────────────────────────
            Grid body = new Grid();
            // CRITICAL: body must have a Star row so all children fill available height.
            // Without this, the body collapses to 0 height (or content height) and
            // the chat scrollviewer has nothing to measure against.
            body.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) });
            body.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(92) });    // Pane 1 category
            body.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1) });     // divider
            _hubPane2DivCol = new ColumnDefinition { Width = new GridLength(1) };               // divider before pane2
            _hubPane2Col = new ColumnDefinition { Width = new GridLength(260) };                // Pane 2 list
            body.ColumnDefinitions.Add(_hubPane2Col);   // col 2 = pane2
            body.ColumnDefinitions.Add(_hubPane2DivCol); // col 3 = divider
            body.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) }); // Pane 3

            // column separator lines
            Border sep1 = new Border { Background = Theme.CardBorder, Width = 1 };
            Grid.SetColumn(sep1, 1);
            Grid.SetRow(sep1, 0);
            body.Children.Add(sep1);
            Border sep2 = new Border { Background = Theme.CardBorder, Width = 1 };
            Grid.SetColumn(sep2, 3);
            Grid.SetRow(sep2, 0);
            body.Children.Add(sep2);

            // ── PANE 1: Category Rail ───────────────────────────────────
            Border pane1 = new Border { Background = new SolidColorBrush(Color.FromRgb(0x0d, 0x11, 0x1e)), Padding = new Thickness(6, 10, 6, 10) };
            StackPanel catPanel = new StackPanel { HorizontalAlignment = HorizontalAlignment.Stretch };

            catPanel.Children.Add(new TextBlock
            {
                Text = "CHAT",
                Foreground = BrushGray,
                FontWeight = FontWeights.Bold,
                FontSize = 9,
                HorizontalAlignment = HorizontalAlignment.Center,
                Margin = new Thickness(0, 0, 0, 8)
            });

            _hubBtnPeers = MakeCatButton("\uD83C\uDF10", "Peers", true);
            _hubUnreadPeers = MakeUnreadBadge();
            catPanel.Children.Add(WrapCatBtnBadge(_hubBtnPeers, _hubUnreadPeers));

            _hubBtnSms = MakeCatButton("\uD83D\uDCF1", "SMS msgs", false);
            _hubUnreadSms = MakeUnreadBadge();
            catPanel.Children.Add(WrapCatBtnBadge(_hubBtnSms, _hubUnreadSms));

            _hubBtnCodes = MakeCatButton("\uD83D\uDD11", "SMS codes", false);
            _hubUnreadCodes = MakeUnreadBadge();
            catPanel.Children.Add(WrapCatBtnBadge(_hubBtnCodes, _hubUnreadCodes));

            _hubBtnPeers.Click += delegate { HubSelectCategory("peers"); };
            _hubBtnSms.Click += delegate { HubSelectCategory("sms"); };
            _hubBtnCodes.Click += delegate { HubSelectCategory("codes"); };

            // Collapse / expand Pane 2 toggle at the bottom of rail
            catPanel.Children.Add(new Border { Height = 1, Background = Theme.CardBorder, Margin = new Thickness(0, 12, 0, 8) });
            _hubPane2Toggle = new Button
            {
                Content = "\u25C4",
                FontSize = 14,
                Background = Brushes.Transparent,
                BorderThickness = new Thickness(0),
                Cursor = Cursors.Hand,
                HorizontalAlignment = HorizontalAlignment.Center,
                ToolTip = "Collapse / expand conversation list",
                Padding = new Thickness(8, 6, 8, 6),
                Width = 74
            };
            _hubPane2Toggle.Click += delegate { HubTogglePane2(); };
            catPanel.Children.Add(_hubPane2Toggle);

            pane1.Child = catPanel;
            Grid.SetColumn(pane1, 0);
            Grid.SetRow(pane1, 0);
            body.Children.Add(pane1);

            // ── PANE 2: List Panel ──────────────────────────────────────
            Border pane2Border = new Border { Background = new SolidColorBrush(Color.FromRgb(0x12, 0x18, 0x28)) };
            Grid pane2Grid = new Grid();
            pane2Grid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });  // search bar
            pane2Grid.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) }); // list

            // Search bar
            Border searchBar = new Border
            {
                Background = new SolidColorBrush(Color.FromRgb(0x0d, 0x13, 0x22)),
                BorderBrush = new SolidColorBrush(Color.FromRgb(0x1f, 0x28, 0x3a)),
                BorderThickness = new Thickness(0, 0, 0, 1),
                Padding = new Thickness(8, 8, 8, 8)
            };
            TextBox txtSearch = new TextBox
            {
                Background = new SolidColorBrush(Color.FromRgb(0x16, 0x1d, 0x2d)),
                Foreground = new SolidColorBrush(Color.FromRgb(0x94, 0xa3, 0xb8)),
                CaretBrush = new SolidColorBrush(Color.FromRgb(0xa5, 0xb4, 0xfc)),
                BorderBrush = new SolidColorBrush(Color.FromRgb(0x2d, 0x3a, 0x52)),
                BorderThickness = new Thickness(1),
                Padding = new Thickness(10, 7, 10, 7),
                FontSize = 13
            };
            txtSearch.SetValue(System.Windows.Automation.AutomationProperties.NameProperty, "Search messages");
            string placeholderSearch = "\uD83D\uDD0D  Search...";
            txtSearch.Text = placeholderSearch;
            txtSearch.GotFocus += delegate
            {
                if (txtSearch.Text == placeholderSearch)
                {
                    txtSearch.Text = "";
                    txtSearch.Foreground = new SolidColorBrush(Color.FromRgb(0xe2, 0xe8, 0xf0));
                }
            };
            txtSearch.LostFocus += delegate
            {
                if (txtSearch.Text.Trim().Length == 0)
                {
                    txtSearch.Text = placeholderSearch;
                    txtSearch.Foreground = new SolidColorBrush(Color.FromRgb(0x64, 0x74, 0x8b));
                }
            };
            txtSearch.TextChanged += delegate
            {
                string q = txtSearch.Text == placeholderSearch ? "" : txtSearch.Text.Trim();
                _chatFilter = q;
                ChatReRender();
                HubRefreshPane2();
            };
            searchBar.Child = txtSearch;
            Grid.SetRow(searchBar, 0);
            pane2Grid.Children.Add(searchBar);

            ScrollViewer pane2Scroll = new ScrollViewer { VerticalScrollBarVisibility = ScrollBarVisibility.Auto };
            _hubPane2 = new StackPanel();
            pane2Scroll.Content = _hubPane2;
            Grid.SetRow(pane2Scroll, 1);
            pane2Grid.Children.Add(pane2Scroll);
            pane2Border.Child = pane2Grid;
            Grid.SetColumn(pane2Border, 2);
            Grid.SetRow(pane2Border, 0);
            body.Children.Add(pane2Border);

            // ── PANE 3: Active Workspace ────────────────────────────────
            Border pane3Border = new Border { Background = Theme.Bg };
            // pane3 must have a Star row so every workspace fills the full height.
            // Without this, the inner Grid rows (Star-row for messages) have no
            // reference height and the chat panel collapses to 0.
            Grid pane3 = new Grid();
            pane3.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) });
            pane3Border.Child = pane3;
            Grid.SetColumn(pane3Border, 4);
            Grid.SetRow(pane3Border, 0);
            body.Children.Add(pane3Border);

            // ── Pane 3a: Chat View ──────────────────────────────────────
            // IMPORTANT: must use proper star-row for messages so input bar is
            // always pinned at the bottom without requiring page-level scrolling.
            _hubPane3Chat = new Grid();
            _hubPane3Chat.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });   // row 0: header
            _hubPane3Chat.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) }); // row 1: messages
            _hubPane3Chat.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });   // row 2: reply preview (hidden by default)
            _hubPane3Chat.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });   // row 3: emoji picker
            _hubPane3Chat.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });   // row 4: input bar

            // ── Chat Header — professional messenger style (like image 3) ──
            // Dark purple/navy gradient header with avatar circle, name, status,
            // and call/video action buttons on the right.
            Border chatHeader = new Border
            {
                Background = new LinearGradientBrush(
                    new GradientStopCollection(new GradientStop[]
                    {
                        new GradientStop(Color.FromRgb(0x1e, 0x1b, 0x4b), 0),   // deep indigo
                        new GradientStop(Color.FromRgb(0x1e, 0x29, 0x3b), 1)    // dark slate
                    }), 90),
                Padding = new Thickness(14, 10, 14, 10)
            };
            Grid chGrid = new Grid();
            chGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });   // avatar
            chGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) }); // name+status
            chGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });   // actions

            // Avatar circle
            Border avatarCircle = new Border
            {
                Width = 40, Height = 40,
                CornerRadius = new CornerRadius(20),
                Background = new LinearGradientBrush(
                    new GradientStopCollection(new GradientStop[] {
                        new GradientStop(Color.FromRgb(0x6d, 0x28, 0xd9), 0),
                        new GradientStop(Color.FromRgb(0x7c, 0x3a, 0xed), 1) }),
                    90),
                Margin = new Thickness(0, 0, 12, 0)
            };
            TextBlock avatarInitials = new TextBlock
            {
                Text = "?",
                Foreground = Brushes.White,
                FontSize = 16,
                FontWeight = FontWeights.Bold,
                HorizontalAlignment = HorizontalAlignment.Center,
                VerticalAlignment = VerticalAlignment.Center
            };
            avatarCircle.Child = avatarInitials;
            Grid.SetColumn(avatarCircle, 0);
            chGrid.Children.Add(avatarCircle);

            // Name + status
            StackPanel nameStack = new StackPanel { VerticalAlignment = VerticalAlignment.Center };
            _hubPane3ContactName = new TextBlock
            {
                Text = "Select a contact",
                FontSize = 14,
                FontWeight = FontWeights.Bold,
                Foreground = Brushes.White
            };
            _hubPane3ContactMeta = new TextBlock
            {
                Text = "",
                Foreground = new SolidColorBrush(Color.FromRgb(0xa5, 0xb4, 0xfc)),
                FontSize = 11,
                Margin = new Thickness(0, 2, 0, 0)
            };
            // Glanceable half of the safety number: verifying a contact should not
            // require opening anything, and the digits only ever show once a real
            // session exists. Hidden for every other state, including "plain".
            _hubSecDigest = new TextBlock
            {
                Text = "",
                Visibility = Visibility.Collapsed,
                Foreground = new SolidColorBrush(Color.FromRgb(0x86, 0xef, 0xac)),
                FontFamily = new FontFamily("Consolas"),
                FontSize = 10,
                Margin = new Thickness(0, 2, 0, 0)
            };
            // No AutomationProperties.Name here on purpose: a TextBlock's
            // accessible name is its text, and "safety 33623 41363" is exactly
            // what both a reader and a test should get.
            nameStack.Children.Add(_hubPane3ContactName);
            nameStack.Children.Add(_hubPane3ContactMeta);
            nameStack.Children.Add(_hubSecDigest);
            Grid.SetColumn(nameStack, 1);
            chGrid.Children.Add(nameStack);

            // Store avatarInitials reference on the name TextBlock so 
            // HubUpdateContactAvatar can update it without a field.
            _hubPane3ContactName.Tag = avatarInitials;

            // Action buttons (right)
            StackPanel actionBtns = new StackPanel
            {
                Orientation = Orientation.Horizontal,
                VerticalAlignment = VerticalAlignment.Center
            };

            // Helper for round header icon buttons
            Action<Button> styleHeaderBtn = delegate(Button hb)
            {
                hb.Width = 36; hb.Height = 36;
                hb.Background = new SolidColorBrush(Color.FromArgb(60, 255, 255, 255));
                hb.Foreground = Brushes.White;
                hb.BorderThickness = new Thickness(0);
                hb.FontSize = 16;
                hb.Margin = new Thickness(4, 0, 0, 0);
                hb.Cursor = Cursors.Hand;
                // Round template
                ControlTemplate hct = new ControlTemplate(typeof(Button));
                FrameworkElementFactory hbf = new FrameworkElementFactory(typeof(Border));
                hbf.SetValue(Border.BackgroundProperty, new TemplateBindingExtension(Button.BackgroundProperty));
                hbf.SetValue(Border.CornerRadiusProperty, new CornerRadius(18));
                FrameworkElementFactory hcp = new FrameworkElementFactory(typeof(ContentPresenter));
                hcp.SetValue(ContentPresenter.HorizontalAlignmentProperty, HorizontalAlignment.Center);
                hcp.SetValue(ContentPresenter.VerticalAlignmentProperty, VerticalAlignment.Center);
                hbf.AppendChild(hcp);
                hct.VisualTree = hbf;
                hb.Template = hct;
            };

            Button btnHubVoice = new Button { Content = "\uD83D\uDCDE", ToolTip = "Voice call" };
            styleHeaderBtn(btnHubVoice);
            btnHubVoice.Click += delegate { HubStartVoiceCall(); };
            actionBtns.Children.Add(btnHubVoice);

            Button btnHubVideo = new Button { Content = "\uD83C\uDF9E", ToolTip = "Video call" };
            styleHeaderBtn(btnHubVideo);
            btnHubVideo.Click += delegate { HubStartVideoCall(); };
            actionBtns.Children.Add(btnHubVideo);

            Button btnHubInfo = new Button { Content = "\u2139", ToolTip = "Contact info" };
            styleHeaderBtn(btnHubInfo);
            btnHubInfo.Click += delegate
            {
                Log("Contact: " + (_hubPane3ContactName != null ? _hubPane3ContactName.Text : "?") + "  " + (_hubPane3ContactMeta != null ? _hubPane3ContactMeta.Text : ""), BrushGray);
            };
            actionBtns.Children.Add(btnHubInfo);

            Button btnHubExport = new Button { Content = "\u2B07", ToolTip = "Export chat transcript" };
            styleHeaderBtn(btnHubExport);
            btnHubExport.SetValue(System.Windows.Automation.AutomationProperties.NameProperty, "Export chat");
            btnHubExport.Click += delegate { ChatExport(); };
            actionBtns.Children.Add(btnHubExport);

            Button btnHubSec = new Button { Content = "\uD83D\uDD10", ToolTip = "End-to-end encryption status" };
            styleHeaderBtn(btnHubSec);
            btnHubSec.SetValue(System.Windows.Automation.AutomationProperties.NameProperty, "Chat encryption");
            btnHubSec.Click += delegate { ShowChatSecurity(); };
            actionBtns.Children.Add(btnHubSec);
            _secChip = btnHubSec;

            Grid.SetColumn(actionBtns, 2);
            chGrid.Children.Add(actionBtns);

            chatHeader.Child = chGrid;
            Grid.SetRow(chatHeader, 0);
            _hubPane3Chat.Children.Add(chatHeader);

            // Message scroll area — customisable via Settings > Chat Theme
            // Default: deep navy/indigo matching image 2 reference design
            _chatBgBrush = new SolidColorBrush(Color.FromRgb(0x1a, 0x20, 0x35));
            _chatScroll = new ScrollViewer
            {
                VerticalScrollBarVisibility = ScrollBarVisibility.Auto,
                HorizontalScrollBarVisibility = ScrollBarVisibility.Disabled,
                Background = _chatBgBrush,
                Padding = new Thickness(14, 10, 14, 16),
                CanContentScroll = false
            };
            _chatPanel = new StackPanel
            {
                VerticalAlignment = VerticalAlignment.Top,
                Margin = new Thickness(0)
            };
            _chatScroll.Content = _chatPanel;
            // Scroll to bottom when panel size changes (= new message added).
            // LayoutUpdated fires every frame which causes an infinite loop; 
            // SizeChanged only fires when the panel actually grows.
            // Auto-scroll is "sticky": it only follows the conversation while the
            // user is already at the bottom, so reading history is never yanked.
            _chatPanel.SizeChanged += delegate
            {
                try { if (_chatStickBottom) _chatScroll.ScrollToBottom(); } catch { }
            };
            _chatScroll.ScrollChanged += delegate
            {
                try
                {
                    // 24 px slack so a partly visible last bubble still counts as bottom.
                    _chatStickBottom = _chatScroll.VerticalOffset >= _chatScroll.ScrollableHeight - 24;
                }
                catch { }
            };
            // Window/pane resized: keep the newest message and the composer in view.
            _chatScroll.SizeChanged += delegate
            {
                try { if (_chatStickBottom) ChatScrollEnd(); } catch { }
            };
            Grid.SetRow(_chatScroll, 1);
            _hubPane3Chat.Children.Add(_chatScroll);

            // ── Reply preview bar (shown when replying to a message) ──────
            _replyPreview = new Border
            {
                Background = new SolidColorBrush(Color.FromRgb(0x1e, 0x28, 0x40)),
                BorderBrush = new SolidColorBrush(Color.FromRgb(0x6d, 0x28, 0xd9)),
                BorderThickness = new Thickness(3, 0, 0, 0),
                Padding = new Thickness(10, 6, 10, 6),
                Visibility = Visibility.Collapsed
            };
            Grid.SetRow(_replyPreview, 2);
            DockPanel rdp = new DockPanel { LastChildFill = true };
            Button btnCancelReply = new Button
            {
                Content = "✕",
                Background = Brushes.Transparent,
                BorderThickness = new Thickness(0),
                Foreground = new SolidColorBrush(Color.FromRgb(0x94, 0xa3, 0xb8)),
                Padding = new Thickness(8, 0, 0, 0),
                Cursor = Cursors.Hand,
                VerticalAlignment = VerticalAlignment.Center
            };
            btnCancelReply.Click += delegate { ClearReplyTo(); };
            DockPanel.SetDock(btnCancelReply, Dock.Right);
            rdp.Children.Add(btnCancelReply);
            StackPanel replyContent = new StackPanel();
            replyContent.Children.Add(new TextBlock
            {
                Text = "Replying to",
                Foreground = new SolidColorBrush(Color.FromRgb(0xa5, 0xb4, 0xfc)),
                FontSize = 11,
                FontWeight = FontWeights.Bold
            });
            replyContent.Children.Add(new TextBlock
            {
                Text = "",
                Foreground = new SolidColorBrush(Color.FromRgb(0x94, 0xa3, 0xb8)),
                FontSize = 11,
                TextTrimming = TextTrimming.CharacterEllipsis
            });
            rdp.Children.Add(replyContent);
            _replyPreview.Child = rdp;
            _hubPane3Chat.Children.Add(_replyPreview);

            // ── Emoji / Sticker Flyout Panel ─────────────────────────────
            _hubEmojiPicker = new StackPanel
            {
                Background = Theme.Panel,
                Visibility = Visibility.Collapsed
            };
            Border emojiPickerBorder = new Border
            {
                BorderBrush = Theme.CardBorder,
                BorderThickness = new Thickness(0, 1, 0, 1),
                Child = _hubEmojiPicker
            };

            // Tab row: Emojis | Stickers
            DockPanel epTabs = new DockPanel { Background = Theme.Chrome, LastChildFill = false };
            epTabs.Children.Add(new Border { Background = Theme.CardBorder, Width = 1 });
            DockPanel.SetDock((System.Windows.Controls.Border)epTabs.Children[epTabs.Children.Count - 1], Dock.Right);
            Button epTabEmoji = MakeButton("\uD83D\uDE00  Emojis");
            epTabEmoji.Background = Theme.AccentSoft;
            epTabEmoji.Foreground = BrushAccent;
            epTabEmoji.Padding = new Thickness(12, 5, 12, 5);
            epTabEmoji.Margin = new Thickness(4, 4, 0, 4);
            DockPanel.SetDock(epTabEmoji, Dock.Left);
            epTabs.Children.Add(epTabEmoji);
            Button epTabStickers = MakeButton("\uD83C\uDFA8  Stickers");
            epTabStickers.Background = Brushes.Transparent;
            epTabStickers.Padding = new Thickness(12, 5, 12, 5);
            epTabStickers.Margin = new Thickness(4, 4, 0, 4);
            DockPanel.SetDock(epTabStickers, Dock.Left);
            epTabs.Children.Add(epTabStickers);

            // GIF tab
            Button epTabGif = MakeButton("\uD83C\uDFA5  GIF");
            epTabGif.Background = Brushes.Transparent;
            epTabGif.Foreground = BrushGray;
            epTabGif.Padding = new Thickness(12, 5, 12, 5);
            epTabGif.Margin = new Thickness(4, 4, 0, 4);
            DockPanel.SetDock(epTabGif, Dock.Left);
            epTabs.Children.Add(epTabGif);

            _hubEmojiPicker.Children.Add(epTabs);

            // Emoji search row
            Border emojiSearchBorder = new Border
            {
                Background = Theme.Chrome,
                BorderBrush = Theme.CardBorder,
                BorderThickness = new Thickness(0, 0, 0, 1),
                Padding = new Thickness(8, 4, 8, 4)
            };
            TextBox emojiSearch = MakeTextBox(0);
            emojiSearch.SetValue(System.Windows.Automation.AutomationProperties.NameProperty, "Search emoji");
            string emojiPlaceholder = "Search emoji...";
            emojiSearch.Text = emojiPlaceholder;
            emojiSearch.Foreground = BrushGray;
            emojiSearch.GotFocus += delegate { if (emojiSearch.Text == emojiPlaceholder) { emojiSearch.Text = ""; emojiSearch.Foreground = BrushFg; } };
            emojiSearch.LostFocus += delegate { if ((emojiSearch.Text ?? "").Trim().Length == 0) { emojiSearch.Text = emojiPlaceholder; emojiSearch.Foreground = BrushGray; } };
            // emojiGrid declared here; assigned below — referenced in search handler above
            WrapPanel emojiGrid = null;
            emojiSearch.TextChanged += delegate
            {
                string q2 = emojiSearch.Text == emojiPlaceholder ? "" : (emojiSearch.Text ?? "").Trim().ToLower();
                if (emojiGrid == null) return;
                foreach (UIElement el in emojiGrid.Children)
                {
                    Button eb = el as Button;
                    if (eb == null) continue;
                    string tip = (eb.ToolTip ?? "").ToString().ToLower();
                    eb.Visibility = (q2.Length == 0 || tip.Contains(q2)) ? Visibility.Visible : Visibility.Collapsed;
                }
            };
            emojiSearchBorder.Child = emojiSearch;
            _hubEmojiPicker.Children.Add(emojiSearchBorder);

            // Recently used + full emoji grid
            emojiGrid = new WrapPanel { Margin = new Thickness(8, 6, 8, 4), MaxHeight = 130 };
            string[] emojisFull = new string[]
            {
                "\uD83D\uDE00","\uD83D\uDE02","\uD83D\uDE04","\uD83D\uDE06","\uD83D\uDE09","\uD83D\uDE0A",
                "\uD83D\uDE0D","\uD83D\uDE18","\uD83D\uDE1C","\uD83D\uDE20","\uD83D\uDE22","\uD83D\uDE2D",
                "\u2764\uFE0F","\uD83D\uDC94","\uD83D\uDC4D","\uD83D\uDC4E","\uD83D\uDC4F","\uD83D\uDE4F",
                "\uD83D\uDD25","\uD83C\uDF89","\uD83C\uDF81","\u2728","\uD83D\uDCE7","\uD83D\uDCDE",
                "\uD83C\uDFA4","\uD83C\uDFB5","\uD83D\uDCBB","\uD83D\uDCF1","\uD83D\uDD0D","\u2699\uFE0F",
                "\uD83D\uDE80","\uD83C\uDF0D","\uD83D\uDCCA","\uD83D\uDCCC","\u2705","\u274C"
            };
            foreach (string em in emojisFull)
            {
                string cap = em;
                Button eb = new Button
                {
                    Content = cap,
                    FontSize = 18,
                    Padding = new Thickness(3),
                    Margin = new Thickness(1),
                    Background = Brushes.Transparent,
                    BorderThickness = new Thickness(0),
                    Cursor = Cursors.Hand,
                    ToolTip = "Insert " + cap
                };
                eb.Click += delegate
                {
                    if (_txtChatInput != null)
                    {
                        int pos = _txtChatInput.CaretIndex;
                        _txtChatInput.Text = _txtChatInput.Text.Insert(pos, cap);
                        _txtChatInput.CaretIndex = pos + cap.Length;
                        _txtChatInput.Focus();
                    }
                };
                emojiGrid.Children.Add(eb);
            }
            ScrollViewer emojiScroll = new ScrollViewer { Content = emojiGrid, MaxHeight = 130, HorizontalScrollBarVisibility = ScrollBarVisibility.Disabled };
            _hubEmojiPicker.Children.Add(emojiScroll);

            // Sticker packs (shown when Stickers tab is clicked)
            StackPanel stickerSection = new StackPanel { Margin = new Thickness(8, 4, 8, 6), Visibility = Visibility.Collapsed };
            string[] stickerPacks = new[] { "\uD83D\uDC31 Tech Cats", "\uD83E\uDD16 System Badges", "\u26A1 Memes" };
            WrapPanel stickerRow = new WrapPanel();
            foreach (string sp in stickerPacks)
            {
                Border scard = new Border
                {
                    Background = Theme.Chrome,
                    BorderBrush = Theme.CardBorder,
                    BorderThickness = new Thickness(1),
                    CornerRadius = new CornerRadius(8),
                    Padding = new Thickness(10, 6, 10, 6),
                    Margin = new Thickness(0, 0, 6, 4),
                    Cursor = Cursors.Hand
                };
                string spCap = sp;
                scard.Child = new TextBlock { Text = sp, FontSize = 12, Foreground = BrushFg };
                scard.MouseLeftButtonUp += delegate
                {
                    if (_txtChatInput != null) { _txtChatInput.Text += " " + spCap.Substring(0, 2); _txtChatInput.Focus(); }
                };
                stickerRow.Children.Add(scard);
            }
            stickerSection.Children.Add(stickerRow);
            _hubEmojiPicker.Children.Add(stickerSection);

            epTabEmoji.Click += delegate
            {
                emojiScroll.Visibility = Visibility.Visible;
                stickerSection.Visibility = Visibility.Collapsed;
                epTabEmoji.Background = Theme.AccentSoft; epTabEmoji.Foreground = BrushAccent;
                epTabStickers.Background = Brushes.Transparent; epTabStickers.Foreground = BrushGray;
            };
            epTabStickers.Click += delegate
            {
                emojiScroll.Visibility = Visibility.Collapsed;
                stickerSection.Visibility = Visibility.Visible;
                epTabStickers.Background = Theme.AccentSoft; epTabStickers.Foreground = BrushAccent;
                epTabEmoji.Background = Brushes.Transparent; epTabEmoji.Foreground = BrushGray;
            };

            // ── Custom sticker tab ──────────────────────────────────────
            Button epTabCustom = MakeButton("\uD83C\uDF1F  My Stickers");
            epTabCustom.Background = Brushes.Transparent;
            epTabCustom.Padding = new Thickness(12, 5, 12, 5);
            epTabCustom.Margin = new Thickness(4, 4, 0, 4);
            DockPanel.SetDock(epTabCustom, Dock.Left);
            epTabs.Children.Add(epTabCustom);

            ScrollViewer customStickerScroll = new ScrollViewer
            {
                MaxHeight = 130,
                HorizontalScrollBarVisibility = ScrollBarVisibility.Disabled,
                VerticalScrollBarVisibility = ScrollBarVisibility.Auto,
                Visibility = Visibility.Collapsed
            };
            _customStickerPanel = new WrapPanel { Margin = new Thickness(6, 4, 6, 4) };
            customStickerScroll.Content = _customStickerPanel;
            _hubEmojiPicker.Children.Add(customStickerScroll);
            RebuildCustomStickers();

            epTabCustom.Click += delegate
            {
                emojiScroll.Visibility = Visibility.Collapsed;
                stickerSection.Visibility = Visibility.Collapsed;
                customStickerScroll.Visibility = Visibility.Visible;
                epTabCustom.Background = Theme.AccentSoft; epTabCustom.Foreground = BrushAccent;
                epTabEmoji.Background = Brushes.Transparent; epTabEmoji.Foreground = BrushGray;
                epTabStickers.Background = Brushes.Transparent; epTabStickers.Foreground = BrushGray;
            };
            epTabEmoji.Click += delegate
            {
                customStickerScroll.Visibility = Visibility.Collapsed;
            };
            epTabStickers.Click += delegate
            {
                customStickerScroll.Visibility = Visibility.Collapsed;
            };

            Grid.SetRow(emojiPickerBorder, 3);
            _hubPane3Chat.Children.Add(emojiPickerBorder);

            // ── Chat Input Row ────────────────────────────────────────────
            Border inputRow = new Border
            {
                // Slightly lighter than the chat bg — matches the reference design footer bar
                Background = new SolidColorBrush(Color.FromRgb(0x16, 0x1c, 0x2c)),
                BorderBrush = new SolidColorBrush(Color.FromRgb(0x1f, 0x28, 0x3a)),
                BorderThickness = new Thickness(0, 1, 0, 0),
                Padding = new Thickness(10, 10, 10, 10)
            };

            // Char count shown just above the input box
            _hubCharCount = new TextBlock
            {
                Text = "",
                Foreground = new SolidColorBrush(Color.FromRgb(0x64, 0x74, 0x8b)),
                FontSize = 10,
                HorizontalAlignment = HorizontalAlignment.Right,
                Margin = new Thickness(0, 0, 4, 2)
            };

            // ── The actual input row — single rounded container like image 2 ──
            // Layout: [actions strip left] [text area] [send button]
            // The actions strip holds emoji, attach, GIF, voice, AI in a row
            Border inputContainer = new Border
            {
                Background = new SolidColorBrush(Color.FromRgb(0x1e, 0x27, 0x3a)),
                CornerRadius = new CornerRadius(28),
                BorderBrush = new SolidColorBrush(Color.FromRgb(0x2d, 0x3a, 0x52)),
                BorderThickness = new Thickness(1)
            };
            Grid inputGrid = new Grid();
            inputGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });  // 0: left actions
            inputGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) }); // 1: text
            inputGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });  // 2: send

            // ── Left action icons ──────────────────────────────────────────
            StackPanel leftActions = new StackPanel
            {
                Orientation = Orientation.Horizontal,
                VerticalAlignment = VerticalAlignment.Bottom,
                Margin = new Thickness(6, 0, 0, 0)
            };

            Action<Button, string, string> styleInputBtn = delegate(Button ib, string icon, string tip)
            {
                ib.Content = icon;
                ib.FontSize = 17;
                ib.Background = Brushes.Transparent;
                ib.BorderThickness = new Thickness(0);
                ib.Padding = new Thickness(6, 8, 6, 8);
                ib.VerticalAlignment = VerticalAlignment.Center;
                ib.Cursor = Cursors.Hand;
                ib.Foreground = new SolidColorBrush(Color.FromRgb(0x94, 0xa3, 0xb8));
                ib.ToolTip = tip;
                ControlTemplate ibt = new ControlTemplate(typeof(Button));
                FrameworkElementFactory ibf = new FrameworkElementFactory(typeof(Border));
                ibf.SetValue(Border.BackgroundProperty, new TemplateBindingExtension(Button.BackgroundProperty));
                ibf.SetValue(Border.CornerRadiusProperty, new CornerRadius(16));
                ibf.SetValue(Border.PaddingProperty, new TemplateBindingExtension(Button.PaddingProperty));
                FrameworkElementFactory icp = new FrameworkElementFactory(typeof(ContentPresenter));
                icp.SetValue(ContentPresenter.HorizontalAlignmentProperty, HorizontalAlignment.Center);
                icp.SetValue(ContentPresenter.VerticalAlignmentProperty, VerticalAlignment.Center);
                icp.SetValue(TextBlock.ForegroundProperty, new TemplateBindingExtension(Button.ForegroundProperty));
                ibf.AppendChild(icp);
                ibt.VisualTree = ibf;
                ib.Template = ibt;
            };

            Button btnEmojiToggle = new Button();
            styleInputBtn(btnEmojiToggle, "\uD83D\uDE00", "Emoji, Stickers & GIFs");
            btnEmojiToggle.Click += delegate
            {
                _hubEmojiOpen = !_hubEmojiOpen;
                _hubEmojiPicker.Visibility = _hubEmojiOpen ? Visibility.Visible : Visibility.Collapsed;
            };
            leftActions.Children.Add(btnEmojiToggle);

            Button btnAttach = new Button();
            styleInputBtn(btnAttach, "\uD83D\uDCCE", "Attach: image, video, file, folder, PDF, link...");
            btnAttach.Click += delegate { ShowAttachMenu(btnAttach); };
            leftActions.Children.Add(btnAttach);

            _btnVoiceNote = new Button();
            styleInputBtn(_btnVoiceNote, "\uD83C\uDFA4", "Record & send voice note (up to 30s)");
            _btnVoiceNote.SetValue(System.Windows.Automation.AutomationProperties.NameProperty, "Record");
            _btnVoiceNote.Click += delegate { ToggleVoiceNote(); };
            leftActions.Children.Add(_btnVoiceNote);

            Button btnAiAssist = new Button();
            styleInputBtn(btnAiAssist, "\uD83E\uDD16", "AI assist — rephrase / complete / translate");
            btnAiAssist.Click += async delegate { await HubAiAssistAsync(); };
            leftActions.Children.Add(btnAiAssist);

            Grid.SetColumn(leftActions, 0);
            inputGrid.Children.Add(leftActions);

            // ── Text area ─────────────────────────────────────────────────
            // Transparent TextBox sits inside the rounded container — the container
            // provides the visible border/background so the TextBox looks native.
            Grid txtHost = new Grid();
            txtHost.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            txtHost.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });

            // Placeholder text (hidden once user types)
            TextBlock placeholder = new TextBlock
            {
                Text = "Type a message...",
                Foreground = new SolidColorBrush(Color.FromRgb(0x47, 0x55, 0x69)),
                FontSize = 13,
                VerticalAlignment = VerticalAlignment.Center,
                Margin = new Thickness(2, 8, 0, 8),
                IsHitTestVisible = false
            };
            txtHost.Children.Add(placeholder);
            Grid.SetRow(placeholder, 0);

            _txtChatInput = new TextBox
            {
                AcceptsReturn = true,
                TextWrapping = TextWrapping.Wrap,
                MaxLength = 0,
                MinHeight = 38,
                MaxHeight = 130,
                VerticalScrollBarVisibility = ScrollBarVisibility.Auto,
                Background = Brushes.Transparent,   // transparent — container provides bg
                Foreground = new SolidColorBrush(Color.FromRgb(0xe2, 0xe8, 0xf0)),
                CaretBrush = new SolidColorBrush(Color.FromRgb(0x7c, 0x3a, 0xed)),
                SelectionBrush = new SolidColorBrush(Color.FromArgb(100, 0x7c, 0x3a, 0xed)),
                BorderThickness = new Thickness(0),
                Padding = new Thickness(2, 8, 8, 8),
                FontSize = 13,
                VerticalContentAlignment = VerticalAlignment.Center
            };
            _txtChatInput.ToolTip = "Type a message — Enter to send, Shift+Enter for new line. Supports up to 100k chars.";
            _txtChatInput.SetValue(System.Windows.Automation.AutomationProperties.NameProperty, "Chat message");
            _txtChatInput.KeyDown += async delegate(object s2, KeyEventArgs e2)
            {
                if (e2.Key == Key.Enter && (Keyboard.Modifiers & ModifierKeys.Shift) == 0)
                {
                    e2.Handled = true;
                    await ChatSendAsync();
                }
            };
            _txtChatInput.TextChanged += delegate
            {
                ChatTypingPulse();
                int len = _txtChatInput.Text == null ? 0 : _txtChatInput.Text.Length;
                // Show/hide placeholder
                placeholder.Visibility = len == 0 ? Visibility.Visible : Visibility.Collapsed;
                // Char count
                if (_hubCharCount != null)
                {
                    _hubCharCount.Text = len > 1000 ? len + (len > 100000 ? " ⚠ compress" : "") : "";
                    _hubCharCount.Foreground = len > 80000
                        ? BrushWarn
                        : new SolidColorBrush(Color.FromRgb(0x64, 0x74, 0x8b));
                }
            };
            txtHost.Children.Add(_txtChatInput);

            Grid.SetColumn(txtHost, 1);
            inputGrid.Children.Add(txtHost);

            // ── Send button ────────────────────────────────────────────────
            // Circular violet button on the right, always visible, matches image 2
            Button btnHubSend = new Button();
            btnHubSend.Width = 42;
            btnHubSend.Height = 42;
            btnHubSend.Background = new SolidColorBrush(Color.FromRgb(0x6d, 0x28, 0xd9));
            btnHubSend.Foreground = Brushes.White;
            btnHubSend.BorderThickness = new Thickness(0);
            btnHubSend.Margin = new Thickness(8, 0, 6, 0);
            btnHubSend.Cursor = Cursors.Hand;
            btnHubSend.VerticalAlignment = VerticalAlignment.Bottom;
            btnHubSend.ToolTip = "Send message (Enter)";
            btnHubSend.SetValue(System.Windows.Automation.AutomationProperties.NameProperty, "Send");
            {
                ControlTemplate st = new ControlTemplate(typeof(Button));
                FrameworkElementFactory sbf = new FrameworkElementFactory(typeof(Border));
                sbf.SetValue(Border.BackgroundProperty, new TemplateBindingExtension(Button.BackgroundProperty));
                sbf.SetValue(Border.CornerRadiusProperty, new CornerRadius(21));
                FrameworkElementFactory scp = new FrameworkElementFactory(typeof(ContentPresenter));
                scp.SetValue(ContentPresenter.HorizontalAlignmentProperty, HorizontalAlignment.Center);
                scp.SetValue(ContentPresenter.VerticalAlignmentProperty, VerticalAlignment.Center);
                sbf.AppendChild(scp);
                st.VisualTree = sbf;
                btnHubSend.Template = st;
            }
            // Arrow icon inside the button
            TextBlock sendIcon = new TextBlock
            {
                Text = "\u27A4",
                FontSize = 16,
                Foreground = Brushes.White,
                HorizontalAlignment = HorizontalAlignment.Center,
                VerticalAlignment = VerticalAlignment.Center
            };
            btnHubSend.Content = sendIcon;
            btnHubSend.Click += async delegate { await ChatSendAsync(); };
            Grid.SetColumn(btnHubSend, 2);
            inputGrid.Children.Add(btnHubSend);

            inputContainer.Child = inputGrid;

            // Wrap char count + container in a StackPanel
            StackPanel inputWrapper = new StackPanel();
            inputWrapper.Children.Add(_hubCharCount);
            inputWrapper.Children.Add(inputContainer);
            inputRow.Child = inputWrapper;
            Grid.SetRow(inputRow, 4);
            _hubPane3Chat.Children.Add(inputRow);
            // Added last so it paints over the conversation, and inside the chat
            // pane so it is dismissed by switching conversation like anything else.
            BuildChatSecuritySheet();
            // ── Pane 3b: Voice Call View ─────────────────────────────────
            _hubPane3Voice = BuildHubVoiceView();

            // ── Pane 3c: Video Call View ─────────────────────────────────
            _hubPane3Video = BuildHubVideoView();

            // ── Pane 3d: OTP Detail View ─────────────────────────────────
            _hubPane3Otp = BuildHubOtpView(otpBanner);

            // Stack all pane-3 workspaces; only one visible at a time.
            // Each workspace sits in row 0 of pane3 and stretches to fill it.
            foreach (Grid ws in new[] { _hubPane3Chat, _hubPane3Voice, _hubPane3Video, _hubPane3Otp })
            {
                ws.Visibility = Visibility.Collapsed;
                ws.VerticalAlignment = VerticalAlignment.Stretch;
                ws.HorizontalAlignment = HorizontalAlignment.Stretch;
                Grid.SetRow(ws, 0);
                pane3.Children.Add(ws);
            }
            _hubPane3Chat.Visibility = Visibility.Visible;

            // Register sms-related fields used by old code paths
            _txtSmsTo = MakeTextBox(0);    // retained for SendSmsAsync()
            _txtSmsBody = MakeMultiBox();   // retained for SendSmsAsync()
            _txtChatTo = MakeTextBox(0);    // retained for ChatNumber()
            _txtChatSearch = MakeTextBox(0);
            _txtChatSearch.TextChanged += delegate
            {
                _chatFilter = _txtChatSearch.Text == null ? "" : _txtChatSearch.Text.Trim();
                ChatReRender();
            };
            _chatPartner = new TextBlock();

            Grid.SetRow(body, 1);
            root.Children.Add(body);

            // ── Thin bottom border (no extra height) ──────────────────────
            Border bottomBorder = new Border
            {
                Background = Theme.Panel,
                BorderBrush = Theme.CardBorder,
                BorderThickness = new Thickness(0, 1, 0, 0),
                Height = 0   // zero height — just provides the top border line visually
            };
            Grid.SetRow(bottomBorder, 2);
            root.Children.Add(bottomBorder);

            _smsGrid = root;

            // Build initial Pane 2 content (peers list)
            HubSelectCategory("peers");

            return root;
        }

        // ── Hub helper: category-pill button ────────────────────────────
        private Button MakeCatButton(string icon, string label, bool active)
        {
            Button b = new Button
            {
                Background = active ? Theme.AccentSoft : Brushes.Transparent,
                Foreground = active ? BrushAccent : BrushGray,
                FontWeight = active ? FontWeights.Bold : FontWeights.Normal,
                BorderThickness = new Thickness(0),
                Cursor = Cursors.Hand,
                HorizontalContentAlignment = HorizontalAlignment.Center,
                Padding = new Thickness(4, 10, 4, 10),
                Margin = new Thickness(0, 3, 0, 3),
                Width = 80,
                ToolTip = label
            };
            StackPanel sp = new StackPanel { HorizontalAlignment = HorizontalAlignment.Center };
            sp.Children.Add(new TextBlock { Text = icon, FontSize = 22, HorizontalAlignment = HorizontalAlignment.Center });
            sp.Children.Add(new TextBlock
            {
                Text = label,
                FontSize = 10,
                FontWeight = FontWeights.SemiBold,
                Foreground = active ? BrushAccent : BrushGray,
                HorizontalAlignment = HorizontalAlignment.Center,
                Margin = new Thickness(0, 3, 0, 0),
                TextAlignment = TextAlignment.Center,
                TextWrapping = TextWrapping.Wrap
            });
            b.Content = sp;
            b.SetValue(System.Windows.Automation.AutomationProperties.NameProperty, label);
            return b;
        }

        private TextBlock MakeUnreadBadge()
        {
            return new TextBlock
            {
                Text = "",
                Foreground = Brushes.White,
                Background = BrushRed,
                FontSize = 9,
                FontWeight = FontWeights.Bold,
                Padding = new Thickness(4, 1, 4, 1),
                Visibility = Visibility.Collapsed,
                HorizontalAlignment = HorizontalAlignment.Right,
                VerticalAlignment = VerticalAlignment.Top,
                Margin = new Thickness(0, 0, 4, 0)
            };
        }

        private FrameworkElement WrapCatBtnBadge(Button btn, TextBlock badge)
        {
            Grid g = new Grid();
            g.Children.Add(btn);
            g.Children.Add(badge);
            return g;
        }

        // ── Hub: select a Pane-1 category ───────────────────────────────
        private void HubSelectCategory(string cat)
        {
            _chatHubCategory = cat;
            foreach (Button b in new[] { _hubBtnPeers, _hubBtnSms, _hubBtnCodes })
            {
                if (b == null) continue;
                bool sel = (b == _hubBtnPeers && cat == "peers")
                        || (b == _hubBtnSms && cat == "sms")
                        || (b == _hubBtnCodes && cat == "codes");
                b.Background = sel ? Theme.AccentSoft : Brushes.Transparent;
                b.Foreground = sel ? BrushAccent : BrushGray;
                b.FontWeight = sel ? FontWeights.Bold : FontWeights.Normal;
                // Update the label TextBlock inside the StackPanel
                StackPanel sp2 = b.Content as StackPanel;
                if (sp2 != null && sp2.Children.Count >= 2)
                {
                    TextBlock lbl = sp2.Children[1] as TextBlock;
                    if (lbl != null) lbl.Foreground = sel ? BrushAccent : BrushGray;
                }
            }
            HubRefreshPane2();
        }

        // ── Hub: rebuild Pane 2 based on current category ───────────────
        private void HubRefreshPane2()
        {
            if (_hubPane2 == null) return;
            _hubPane2.Children.Clear();
            string q = (_chatFilter ?? "").ToLowerInvariant();

            if (_chatHubCategory == "peers")
            {
                // Header
                _hubPane2.Children.Add(MakePane2Header("Peers", _voip != null ? _voip.Peers.Count.ToString() + " online" : ""));

                if (_voip != null)
                {
                    foreach (VoipPeer p in _voip.Peers)
                    {
                        if (p.Number == _myNumber) continue;
                        if (q.Length > 0 && !p.Name.ToLowerInvariant().Contains(q) && !p.Number.ToLowerInvariant().Contains(q)) continue;
                        bool online = (DateTime.Now - p.LastSeen).TotalSeconds < 120;
                        string disp = p.Name ?? p.Ip ?? p.Number ?? "?";
                        string cn = (p.Number != null) ? ChatLookupName(p.Number) : null;
                        if (cn != null) disp = cn + " (" + p.Name + ")";
                        int unread = 0;
                        if (p.Number != null && _chatUnread.TryGetValue(SanitizeNumber(p.Number), out unread)) { }
                        _hubPane2.Children.Add(MakePane2Row(
                            disp, p.Ip ?? "", online, unread,
                            p.Number ?? p.Ip ?? ""));
                    }
                }
                if (_hubPane2.Children.Count <= 1)
                    _hubPane2.Children.Add(MakePane2Empty("No peers online. Start the app on another device on the same LAN."));
            }
            else if (_chatHubCategory == "sms")
            {
                _hubPane2.Children.Add(MakePane2Header("SMS Conversations", ""));
                // Build list from recent chat files
                try
                {
                    if (Directory.Exists(AppConfig.ChatsDir))
                    {
                        List<ChatRecent> rows = new List<ChatRecent>();
                        foreach (string f in Directory.GetFiles(AppConfig.ChatsDir, "chat_*.txt"))
                        {
                            try
                            {
                                string num = Path.GetFileNameWithoutExtension(f).Substring(5);
                                string[] lines2 = File.ReadAllLines(f);
                                string last = lines2.Length > 0 ? lines2[lines2.Length - 1] : "";
                                string[] parts = last.Split(new char[] { '|' }, 4);
                                string snippet = parts.Length >= 4 ? ChatPreview(parts[1], parts[3]) : last;
                                string when2 = parts.Length >= 1 ? parts[0] : "";
                                string name = ChatLookupName(num) ?? num;
                                int unread2 = 0;
                                _chatUnread.TryGetValue(num, out unread2);
                                // A search should behave like a transcript search: match the
                                // name, the number, the preview or any stored message, and
                                // never hide the conversation that is currently open.
                                bool match = q.Length == 0
                                    || name.ToLowerInvariant().Contains(q)
                                    || num.Contains(q)
                                    || snippet.ToLowerInvariant().Contains(q)
                                    || ChatFileHasMatch(lines2, q)
                                    || num == _chatOpenNum;
                                if (match)
                                    _hubPane2.Children.Add(MakePane2Row(name, snippet.Length > 40 ? snippet.Substring(0, 40) + "..." : snippet, true, unread2, num));
                            }
                            catch { }
                        }
                        if (_hubPane2.Children.Count <= 1)
                            _hubPane2.Children.Add(MakePane2Empty(q.Length > 0 ? "No conversations match this search." : "No SMS conversations yet."));
                    }
                    else _hubPane2.Children.Add(MakePane2Empty(q.Length > 0 ? "No conversations match this search." : "No SMS conversations yet."));
                }
                catch { }
            }
            else if (_chatHubCategory == "codes")
            {
                _hubPane2.Children.Add(MakePane2Header("Verification Codes", ""));
                if (_codes != null && _codes.Count > 0)
                {
                    foreach (SmsCode sc in _codes)
                    {
                        if (q.Length > 0 && !sc.Code.Contains(q) && !sc.From.ToLowerInvariant().Contains(q)) continue;
                        _hubPane2.Children.Add(MakePane2OtpRow(sc));
                    }
                }
                else _hubPane2.Children.Add(MakePane2Empty("No verification codes received yet."));
            }
        }

        private Border MakePane2Header(string title, string sub)
        {
            Border h = new Border
            {
                Background = new SolidColorBrush(Color.FromRgb(0x0d, 0x13, 0x22)),
                BorderBrush = new SolidColorBrush(Color.FromRgb(0x1f, 0x28, 0x3a)),
                BorderThickness = new Thickness(0, 0, 0, 1),
                Padding = new Thickness(10, 10, 10, 10)
            };
            StackPanel sp = new StackPanel();
            sp.Children.Add(new TextBlock
            {
                Text = title,
                FontWeight = FontWeights.Bold,
                Foreground = new SolidColorBrush(Color.FromRgb(0xe2, 0xe8, 0xf0)),
                FontSize = 13
            });
            if (sub.Length > 0)
                sp.Children.Add(new TextBlock
                {
                    Text = sub,
                    Foreground = new SolidColorBrush(Color.FromRgb(0x64, 0x74, 0x8b)),
                    FontSize = 10,
                    Margin = new Thickness(0, 2, 0, 0)
                });
            h.Child = sp;
            return h;
        }

        private Button MakePane2Row(string name, string snippet, bool online, int unread, string number)
        {
            // A Button (not a raw Border) so the row is keyboard- and
            // UI-Automation invokable; the template keeps the list look.
            Button row = new Button
            {
                BorderBrush = Theme.CardBorder,
                BorderThickness = new Thickness(0, 0, 0, 1),
                Padding = new Thickness(10, 10, 10, 10),
                Cursor = Cursors.Hand,
                Background = Brushes.Transparent,
                HorizontalContentAlignment = HorizontalAlignment.Stretch,
                Focusable = true,
                ToolTip = "Open chat with " + name
            };
            ControlTemplate rowTpl = new ControlTemplate(typeof(Button));
            FrameworkElementFactory rowBd = new FrameworkElementFactory(typeof(Border));
            rowBd.SetValue(Border.BackgroundProperty, new TemplateBindingExtension(Button.BackgroundProperty));
            rowBd.SetValue(Border.BorderBrushProperty, new TemplateBindingExtension(Button.BorderBrushProperty));
            rowBd.SetValue(Border.BorderThicknessProperty, new TemplateBindingExtension(Button.BorderThicknessProperty));
            rowBd.SetValue(Border.PaddingProperty, new TemplateBindingExtension(Button.PaddingProperty));
            FrameworkElementFactory rowCp = new FrameworkElementFactory(typeof(ContentPresenter));
            rowBd.AppendChild(rowCp);
            rowTpl.VisualTree = rowBd;
            row.Template = rowTpl;
            row.SetValue(System.Windows.Automation.AutomationProperties.NameProperty,
                "Open chat with " + name + " (" + number + ")");
            row.MouseEnter += delegate { row.Background = new SolidColorBrush(Color.FromRgb(0x1e, 0x28, 0x40)); };
            row.MouseLeave += delegate { row.Background = Brushes.Transparent; };
            Grid rg = new Grid();
            rg.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });  // avatar
            rg.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) }); // text
            rg.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });  // badge

            // Avatar circle with initials
            Border av = new Border
            {
                Width = 38, Height = 38,
                CornerRadius = new CornerRadius(19),
                Background = new LinearGradientBrush(
                    new GradientStopCollection(new GradientStop[]
                    {
                        new GradientStop(Color.FromRgb(0x4f, 0x8c, 0xff), 0),
                        new GradientStop(Color.FromRgb(0x7b, 0x5c, 0xff), 1)
                    }), 90),
                Margin = new Thickness(0, 0, 10, 0)
            };
            string initials = name.Length > 0 ? name[0].ToString().ToUpper() : "?";
            if (name.Length > 1)
            {
                int sp2 = name.IndexOf(' ');
                if (sp2 > 0 && sp2 < name.Length - 1) initials = "" + name[0] + name[sp2 + 1];
            }
            av.Child = new TextBlock
            {
                Text = initials,
                Foreground = Brushes.White,
                FontWeight = FontWeights.Bold,
                FontSize = 14,
                HorizontalAlignment = HorizontalAlignment.Center,
                VerticalAlignment = VerticalAlignment.Center
            };
            // Online dot overlay
            Grid avGrid = new Grid();
            avGrid.Children.Add(av);
            System.Windows.Shapes.Ellipse statusDot = new System.Windows.Shapes.Ellipse
            {
                Width = 10, Height = 10,
                Fill = online ? Theme.Success : BrushGray,
                Stroke = Theme.Bg, StrokeThickness = 2,
                HorizontalAlignment = HorizontalAlignment.Right,
                VerticalAlignment = VerticalAlignment.Bottom,
                Margin = new Thickness(0, 0, 0, 0)
            };
            avGrid.Children.Add(statusDot);
            Grid.SetColumn(avGrid, 0);
            rg.Children.Add(avGrid);

            StackPanel txt = new StackPanel { VerticalAlignment = VerticalAlignment.Center };
            TextBlock tbName = new TextBlock
            {
                Text = name,
                Foreground = new SolidColorBrush(Color.FromRgb(0xe2, 0xe8, 0xf0)),  // always white-ish
                FontWeight = unread > 0 ? FontWeights.Bold : FontWeights.Normal,
                FontSize = 13
            };
            txt.Children.Add(tbName);
            if (snippet.Length > 0)
                txt.Children.Add(new TextBlock
                {
                    Text = snippet,
                    Foreground = new SolidColorBrush(Color.FromRgb(0x94, 0xa3, 0xb8)),  // always readable slate
                    FontSize = 11,
                    Margin = new Thickness(0, 2, 0, 0),
                    TextTrimming = TextTrimming.CharacterEllipsis
                });
            Grid.SetColumn(txt, 1);
            rg.Children.Add(txt);

            if (unread > 0)
            {
                Border badge = new Border
                {
                    Background = BrushAccent,
                    CornerRadius = new CornerRadius(10),
                    Padding = new Thickness(5, 2, 5, 2),
                    VerticalAlignment = VerticalAlignment.Center
                };
                badge.Child = new TextBlock { Text = unread.ToString(), Foreground = Brushes.White, FontSize = 10, FontWeight = FontWeights.Bold };
                Grid.SetColumn(badge, 2);
                rg.Children.Add(badge);
            }

            row.Content = rg;
            string num = number;
            string nm = name;
            row.Click += delegate { HubOpenContact(nm, num); };
            return row;
        }

        private Border MakePane2OtpRow(SmsCode sc)
        {
            Border row = new Border
            {
                BorderBrush = Theme.CardBorder,
                BorderThickness = new Thickness(0, 0, 0, 1),
                Padding = new Thickness(10, 10, 10, 10),
                Cursor = Cursors.Hand,
                Background = Brushes.Transparent
            };
            row.MouseEnter += delegate { row.Background = new SolidColorBrush(Color.FromRgb(0x1e, 0x28, 0x40)); };
            row.MouseLeave += delegate { row.Background = Brushes.Transparent; };
            DockPanel dp = new DockPanel { LastChildFill = false };
            StackPanel left = new StackPanel();
            left.Children.Add(new TextBlock { Text = sc.From, FontWeight = FontWeights.Bold, Foreground = new SolidColorBrush(Color.FromRgb(0xe2, 0xe8, 0xf0)), FontSize = 13 });
            left.Children.Add(new TextBlock { Text = sc.Time, Foreground = new SolidColorBrush(Color.FromRgb(0x64, 0x74, 0x8b)), FontSize = 10 });
            DockPanel.SetDock(left, Dock.Left);
            dp.Children.Add(left);
            Border codeB = new Border
            {
                Background = Theme.AccentSoft,
                CornerRadius = new CornerRadius(8),
                Padding = new Thickness(8, 4, 8, 4),
                VerticalAlignment = VerticalAlignment.Center
            };
            codeB.Child = new TextBlock { Text = sc.Code, FontFamily = new FontFamily("Consolas"), FontSize = 16, FontWeight = FontWeights.Bold, Foreground = BrushAccent };
            DockPanel.SetDock(codeB, Dock.Right);
            dp.Children.Add(codeB);
            row.Child = dp;
            SmsCode scCap = sc;
            row.MouseLeftButtonUp += delegate { HubOpenOtp(scCap); };
            return row;
        }

        private Border MakePane2Empty(string msg)
        {
            return new Border
            {
                Padding = new Thickness(16, 28, 16, 28),
                Child = new TextBlock
                {
                    Text = msg,
                    Foreground = new SolidColorBrush(Color.FromRgb(0x64, 0x74, 0x8b)),
                    FontSize = 12,
                    TextWrapping = TextWrapping.Wrap,
                    HorizontalAlignment = HorizontalAlignment.Center,
                    TextAlignment = TextAlignment.Center
                }
            };
        }

        // ── Hub: open a contact in Pane 3 ────────────────────────────────
        private void HubOpenContact(string name, string number)
        {
            Log("Hub: open conversation " + name + " (" + number + ")", BrushGray);
            _chatWorkspace = "chat";
            HubShowWorkspace("chat");
            if (_hubPane3ContactName != null)
            {
                _hubPane3ContactName.Text = name;
                // Update avatar initials in the header
                HubUpdateContactAvatar(name);
            }
            string meta = number;
            // Check if peer is online
            if (_voip != null)
                foreach (VoipPeer p in _voip.Peers)
                    if (SanitizeNumber(p.Number ?? "") == SanitizeNumber(number) || p.Ip == number)
                    {
                        bool online = (DateTime.Now - p.LastSeen).TotalSeconds < 120;
                        meta = (online ? "\uD83D\uDFE2 Online" : "\uD83D\uDD34 Offline") + "  •  " + p.Ip;
                        break;
                    }
            if (_hubPane3ContactMeta != null) _hubPane3ContactMeta.Text = meta;
            // Update chat fields used by existing logic
            if (_txtChatTo != null) _txtChatTo.Text = number;
            ChatOpen();
        }

        // Update the avatar initials TextBlock in the chat header.
        // We store a reference via the Tag property on _hubPane3ContactName.
        private void HubUpdateContactAvatar(string name)
        {
            if (_hubPane3ContactName == null) return;
            TextBlock avatarTb = _hubPane3ContactName.Tag as TextBlock;
            if (avatarTb == null) return;
            string n = (name ?? "").Trim();
            if (n.Length == 0) { avatarTb.Text = "?"; return; }
            string ini = n[0].ToString().ToUpper();
            int sp = n.IndexOf(' ');
            if (sp > 0 && sp < n.Length - 1)
                ini = ("" + n[0] + n[sp + 1]).ToUpper();
            avatarTb.Text = ini;
        }

        // ── Add presence pill button to the app header bar ─────────────────
        // Called once after BuildUi; adds a clickable presence dot to the right
        // side of the header next to the other pills.
        private void AddPresenceButtonToHeader()
        {
            try
            {
                // Find the header DockPanel — it's the first child of the root Grid row 0
                Grid root = Content as Grid;
                if (root == null || root.Children.Count == 0) return;
                Border headerBorder = root.Children[0] as Border;
                if (headerBorder == null) return;
                DockPanel hd = headerBorder.Child as DockPanel;
                if (hd == null) return;

                _btnPresence = new Button
                {
                    Content = "🟢",
                    FontSize = 14,
                    Background = Brushes.Transparent,
                    BorderThickness = new Thickness(0),
                    Padding = new Thickness(8, 2, 8, 2),
                    Cursor = Cursors.Hand,
                    ToolTip = "Status: Available\nClick to change presence",
                    Margin = new Thickness(0, 0, 4, 0),
                    VerticalAlignment = VerticalAlignment.Center
                };
                _btnPresence.Click += delegate { ShowPresenceMenu(_btnPresence); };
                DockPanel.SetDock(_btnPresence, Dock.Right);
                // Insert before the first right-docked child
                hd.Children.Insert(0, _btnPresence);
            }
            catch (Exception ex) { Log("Presence btn: " + ex.Message, BrushGray); }
        }

        private void ShowPresenceMenu(UIElement anchor)
        {
            ContextMenu cm = new ContextMenu();
            string[] states  = { "available", "busy", "dnd", "away" };
            string[] labels  = { "🟢  Available", "🔴  Busy", "⛔  Do Not Disturb", "🟡  Away" };
            for (int i = 0; i < states.Length; i++)
            {
                string s = states[i]; string l = labels[i];
                MenuItem mi = new MenuItem { Header = l, IsChecked = (_myPresence == s) };
                mi.Click += delegate { SetPresence(s, ""); };
                cm.Items.Add(mi);
            }
            cm.Items.Add(new Separator());
            MenuItem miCustom = new MenuItem { Header = "✏  Set Status Text…" };
            miCustom.Click += delegate { ShowStatusTextDialog(); };
            cm.Items.Add(miCustom);
            cm.IsOpen = true;
            cm.PlacementTarget = anchor as FrameworkElement;
            cm.Placement = PlacementMode.Bottom;
        }

        private void ShowStatusTextDialog()
        {
            Window sw = new Window
            {
                Title = "Set Status Text",
                Width = 340,
                SizeToContent = SizeToContent.Height,
                ResizeMode = ResizeMode.NoResize,
                WindowStartupLocation = WindowStartupLocation.CenterOwner,
                Owner = this,
                Background = Theme.Bg
            };
            Border sc = new Border
            {
                Background = Theme.Card,
                BorderBrush = Theme.CardBorder,
                BorderThickness = new Thickness(1),
                CornerRadius = new CornerRadius(12),
                Padding = new Thickness(16, 14, 16, 14),
                Margin = new Thickness(10)
            };
            StackPanel sp = new StackPanel();
            sp.Children.Add(new TextBlock { Text = "Custom status text (shown to peers)", Foreground = BrushGray, FontSize = 12, Margin = new Thickness(0, 0, 0, 8) });
            TextBox tb = MakeTextBox(0);
            tb.Text = _myStatusText;
            tb.Margin = new Thickness(0, 0, 0, 12);
            sp.Children.Add(tb);
            StackPanel br = new StackPanel { Orientation = Orientation.Horizontal, HorizontalAlignment = HorizontalAlignment.Right };
            Button bc = MakeButton("Cancel"); bc.Margin = new Thickness(0, 0, 8, 0); bc.Click += delegate { sw.Close(); };
            Button bs = MakeButton("Set");
            Style ps = TryStyle("PrimaryButton"); if (ps != null) bs.Style = ps;
            bs.Click += delegate { SetPresence(_myPresence, tb.Text.Trim()); sw.Close(); };
            br.Children.Add(bc); br.Children.Add(bs);
            sp.Children.Add(br);
            sc.Child = sp; sw.Content = sc; sw.ShowDialog();
        }

        // ── Network quality indicator ─────────────────────────────────────
        // Updates a coloured dot in the status bar every 5 s.
        private void UpdateNetworkQualityIndicator()
        {
            if (_netQualityDot == null) return;
            // Use connection state for the status dot, not just network quality.
            // This directly answers "can my mate reach me right now?".
            bool relayOk = _voip != null && _voip.RelayReady;
            bool lanOnly = !relayOk && (_voip != null && _voip.LanPeersCount > 0);
            string qual = (_voip != null) ? _voip.NetworkQuality : "idle";
            Color dotColor;
            string tip;
            if (relayOk)
            {
                switch (qual)
                {
                    case "good":
                        dotColor = Color.FromRgb(0x22, 0xc5, 0x5e);
                        tip = "Connected \u2014 reachable worldwide";
                        break;
                    case "fair":
                        dotColor = Color.FromRgb(0xf5, 0x9e, 0x0b);
                        tip = "Connected \u2014 relay reachable, fair signal";
                        break;
                    case "poor":
                        dotColor = Color.FromRgb(0xef, 0x44, 0x44);
                        tip = "Connected \u2014 relay reachable, poor signal";
                        break;
                    default:
                        dotColor = Color.FromRgb(0x22, 0xc5, 0x5e);
                        tip = "Connected to relay \u2014 mate can call you";
                        break;
                }
            }
            else if (lanOnly)
            {
                dotColor = Color.FromRgb(0xf5, 0x9e, 0x0b);
                tip = "LAN only \u2014 not reachable over the internet (no relay)";
            }
            else
            {
                dotColor = Color.FromRgb(0xef, 0x44, 0x44);
                tip = "Disconnected \u2014 set a relay in Settings so your mate can reach you";
            }
            _netQualityDot.Fill = new SolidColorBrush(dotColor);
            if (_netQualityText != null)
            {
                _netQualityText.Text = relayOk ? "Online" : (lanOnly ? "LAN only" : "Offline");
                _netQualityText.Foreground = new SolidColorBrush(dotColor);
            }
            _netQualityDot.ToolTip = tip + (_voip != null && _voip.InCall ?
                string.Format("  RTT: {0:0}ms  Loss: {1}%", _voip.LastRttMs, _voip.PacketLoss100) : "");
        }

        // ── Navigation badges ─────────────────────────────────────────────
        // Overlays small red count pills on nav buttons when there are unreads.
        private void UpdateNavBadges()
        {
            // Page 3 = SMS/Chat — show total unread
            int totalUnread = 0;
            foreach (int v in _chatUnread.Values) totalUnread += v;
            totalUnread += _codes.Count > 0 ? 1 : 0;
            SetNavBadge(3, totalUnread);
        }

        private void SetNavBadge(int pageIndex, int count)
        {
            if (_navButtons == null || pageIndex >= _navButtons.Count) return;
            TextBlock badge;
            if (!_navBadges.TryGetValue(pageIndex, out badge))
            {
                // Create the badge overlay on first use
                Grid wrap = new Grid();
                Button navBtn = _navButtons[pageIndex];
                // Replace the nav button in its parent with a Grid containing both
                StackPanel parent = navBtn.Parent as StackPanel;
                if (parent == null) return;
                int idx = parent.Children.IndexOf(navBtn);
                if (idx < 0) return;
                parent.Children.RemoveAt(idx);
                wrap.Children.Add(navBtn);
                badge = new TextBlock
                {
                    Text = "",
                    Foreground = Brushes.White,
                    Background = new SolidColorBrush(Color.FromRgb(0xef, 0x44, 0x44)),
                    FontSize = 9,
                    FontWeight = FontWeights.Bold,
                    Padding = new Thickness(4, 1, 4, 1),
                    HorizontalAlignment = HorizontalAlignment.Right,
                    VerticalAlignment = VerticalAlignment.Top,
                    Margin = new Thickness(0, 2, 2, 0),
                    Visibility = Visibility.Collapsed
                };
                // Rounded corners via a Border wrapper
                Border badgeBorder = new Border
                {
                    CornerRadius = new CornerRadius(8),
                    Background = new SolidColorBrush(Color.FromRgb(0xef, 0x44, 0x44)),
                    Padding = new Thickness(4, 1, 4, 1),
                    HorizontalAlignment = HorizontalAlignment.Right,
                    VerticalAlignment = VerticalAlignment.Top,
                    Margin = new Thickness(0, 2, 2, 0),
                    Child = badge,
                    Visibility = Visibility.Collapsed
                };
                badge.Tag = badgeBorder;  // store border ref via tag
                wrap.Children.Add(badgeBorder);
                parent.Children.Insert(idx, wrap);
                _navBadges[pageIndex] = badge;
            }
            Badge_SetCount(badge, count);
        }

        private static void Badge_SetCount(TextBlock badge, int count)
        {
            if (badge == null) return;
            bool show = count > 0;
            badge.Text = count > 99 ? "99+" : count.ToString();
            badge.Visibility = show ? Visibility.Visible : Visibility.Collapsed;
            Border border = badge.Tag as Border;
            if (border != null) border.Visibility = badge.Visibility;
        }

        // ── Message reactions ─────────────────────────────────────────────
        // Stores reactions per message ID. Rendered as a small emoji strip
        // below the bubble via ChatAddReaction().
        private readonly Dictionary<string, List<string>> _msgReactions = new Dictionary<string, List<string>>();

        private void HandleReactionReceived(string from, string msgId, string emoji)
        {
            List<string> list;
            if (!_msgReactions.TryGetValue(msgId, out list))
            {
                list = new List<string>();
                _msgReactions[msgId] = list;
            }
            if (!list.Contains(emoji)) list.Add(emoji);
            // Rebuild open conversation to show new reaction
            ChatReRender();
            Log("Reaction from " + from + ": " + emoji, BrushGray);
        }

        // ── File Transfer ─────────────────────────────────────────────────
        private readonly Dictionary<string, FileTransferSession> _transfers =
            new Dictionary<string, FileTransferSession>();

        private bool PrepareFileTransfer(string peerNumber, string filePath, out string transferId,
            out string fileName, out long size, out string error)
        {
            transferId = null;
            fileName = null;
            size = 0;
            error = null;
            try
            {
                if (!File.Exists(filePath)) throw new FileNotFoundException("Attachment file not found.", filePath);
                FileInfo info = new FileInfo(filePath);
                size = info.Length;
                if (size > 52428800L) throw new InvalidOperationException("Attachments are limited to 50 MB.");
                fileName = Path.GetFileName(filePath);
                if (string.IsNullOrEmpty(fileName)) throw new InvalidOperationException("Attachment has no file name.");
                string hash = FileSha256(filePath);
                byte[] secret = new byte[32];
                using (System.Security.Cryptography.RandomNumberGenerator rng =
                    System.Security.Cryptography.RandomNumberGenerator.Create()) rng.GetBytes(secret);
                string secretBase64 = Convert.ToBase64String(secret);
                ChatKey transferKey = ChatKey.FromMaterial(secret);
                Array.Clear(secret, 0, secret.Length);
                transferId = Guid.NewGuid().ToString("N").Substring(0, 16).ToUpperInvariant();
                FileTransferSession session = new FileTransferSession
                {
                    Id = transferId, PeerNumber = peerNumber, FilePath = filePath,
                    FileName = fileName, SizeBytes = size, Direction = "out", State = "offered",
                    TransferKey = transferKey, Sha256 = hash
                };
                _transfers[transferId] = session;
                if (_voip == null || !_voip.SendFileOffer(peerNumber, fileName, size, transferId, secretBase64, hash))
                    throw new InvalidOperationException("The secure file offer could not be sent. Establish an encrypted chat session and retry.");
                Log("Secure file offer sent: " + fileName + " (" + FormatFileSize(size) + ").", BrushAccent);
                return true;
            }
            catch (Exception ex)
            {
                error = ex.Message;
                if (transferId != null) _transfers.Remove(transferId);
                return false;
            }
        }

        private void HandleFileOffer(string from, string transferId, string name, long size, string keyBase64, string hash)
        {
            try
            {
                string safeName = SafeReceivedFileName(name);
                byte[] key = Convert.FromBase64String(keyBase64);
                if (key.Length != 32 || size < 0 || size > 52428800L ||
                    !Regex.IsMatch(hash ?? "", "^[A-Fa-f0-9]{64}$"))
                {
                    Array.Clear(key, 0, key.Length);
                    throw new InvalidDataException("Invalid secure file offer.");
                }
                if (_transfers.ContainsKey(transferId))
                {
                    Array.Clear(key, 0, key.Length);
                    throw new InvalidDataException("Duplicate file-transfer identifier.");
                }
                ChatKey transferKey = ChatKey.FromMaterial(key);
                Array.Clear(key, 0, key.Length);
                _transfers[transferId] = new FileTransferSession
                {
                    Id = transferId, PeerNumber = from, FileName = safeName,
                    SizeBytes = size, Direction = "in", State = "offered",
                    TransferKey = transferKey, Sha256 = hash.ToUpperInvariant()
                };
                Log("Encrypted file offer from #" + from + ": " + safeName + " (" + FormatFileSize(size) + ").", BrushAccent);
                Toast.Show("File offer from #" + from, safeName + " (" + FormatFileSize(size) + ") - select to accept",
                    delegate { AcceptFileTransfer(transferId, from); });
                if (_chatOpenNum == from) ChatReRender();
            }
            catch (Exception ex) { Log("File offer rejected: " + ex.Message, BrushWarn); }
        }

        private void AcceptFileTransfer(string transferId, string from)
        {
            FileTransferSession s;
            if (!_transfers.TryGetValue(transferId, out s) || s.Direction != "in" ||
                s.PeerNumber != from || s.State != "offered") return;
            s.State = "accepted";
            System.Threading.Tasks.Task.Run(delegate
            {
                TcpListener lis = null;
                TcpClient tc = null;
                string partPath = null;
                try
                {
                    lis = new TcpListener(IPAddress.Any, 0);
                    lis.Start();
                    int port = ((IPEndPoint)lis.LocalEndpoint).Port;
                    if (_voip == null || !_voip.SendFileAccept(from, transferId, port))
                        throw new IOException("The encrypted acceptance could not be delivered.");
                    Dispatcher.BeginInvoke((Action)delegate { Log("Accepting encrypted transfer: " + s.FileName, BrushGray); });
                    tc = AcceptTransferClient(lis, 120000);
                    tc.ReceiveTimeout = 30000;
                    tc.SendTimeout = 30000;
                    lis.Stop();

                    string folder = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
                        "USSD Manager", "Received Files");
                    Directory.CreateDirectory(folder);
                    partPath = Path.Combine(folder, transferId + ".part");
                    using (NetworkStream ns = tc.GetStream())
                    using (FileStream fs = new FileStream(partPath, FileMode.CreateNew, FileAccess.Write, FileShare.None))
                    {
                        long received = 0;
                        int lastPct = -1;
                        while (received < s.SizeBytes)
                        {
                            byte[] frame = ReadTransferFrame(ns);
                            string plain = s.TransferKey.Decrypt(Encoding.ASCII.GetString(frame));
                            if (plain == null) throw new InvalidDataException("A file chunk failed authentication.");
                            byte[] chunk = Convert.FromBase64String(plain);
                            if (chunk.Length == 0 || chunk.Length > 24 * 1024 || received + chunk.Length > s.SizeBytes)
                                throw new InvalidDataException("Invalid file chunk length.");
                            fs.Write(chunk, 0, chunk.Length);
                            received += chunk.Length;
                            int pct = s.SizeBytes == 0 ? 100 : (int)(received * 100 / s.SizeBytes);
                            if (pct != lastPct)
                            {
                                lastPct = pct;
                                int progress = pct;
                                Dispatcher.BeginInvoke((Action)delegate
                                {
                                    if (_hubPane3ContactMeta != null) _hubPane3ContactMeta.Text = "Receiving file... " + progress + "%";
                                });
                            }
                        }
                        fs.Flush();
                        if (ns.ReadByte() != -1) throw new InvalidDataException("Unexpected data after the file.");
                    }
                    tc.Close();
                    tc = null;
                    string actualHash = FileSha256(partPath);
                    if (!string.Equals(actualHash, s.Sha256, StringComparison.OrdinalIgnoreCase))
                        throw new InvalidDataException("The file hash did not match the authenticated offer.");
                    string savePath = UniqueReceivedPath(folder, s.FileName);
                    File.Move(partPath, savePath);
                    partPath = null;
                    Dispatcher.BeginInvoke((Action)delegate
                    {
                        s.ReceivedPath = savePath;
                        s.State = "complete";
                        s.TransferKey = null;
                        Log("File received and verified: " + savePath, BrushSuccess);
                        if (_hubPane3ContactMeta != null) _hubPane3ContactMeta.Text = "";
                        if (_chatOpenNum == from) ChatReRender();
                    });
                }
                catch (Exception ex)
                {
                    if (partPath != null && File.Exists(partPath))
                    {
                        try { File.Delete(partPath); }
                        catch (Exception cleanup) { Dispatcher.BeginInvoke((Action)delegate { Log("Could not remove partial attachment: " + cleanup.Message, BrushWarn); }); }
                    }
                    Dispatcher.BeginInvoke((Action)delegate
                    {
                        s.State = "failed";
                        s.TransferKey = null;
                        Log("File transfer failed: " + ex.Message, BrushError);
                        if (_hubPane3ContactMeta != null) _hubPane3ContactMeta.Text = "";
                        if (_chatOpenNum == from) ChatReRender();
                    });
                }
                finally
                {
                    if (lis != null) try { lis.Stop(); } catch (Exception ex) { Dispatcher.BeginInvoke((Action)delegate { Log("File listener cleanup failed: " + ex.Message, BrushWarn); }); }
                    if (tc != null) try { tc.Close(); } catch (Exception ex) { Dispatcher.BeginInvoke((Action)delegate { Log("File socket cleanup failed: " + ex.Message, BrushWarn); }); }
                }
            });
        }

        private void RejectFileTransfer(string transferId, string from)
        {
            FileTransferSession s;
            if (!_transfers.TryGetValue(transferId, out s) || s.Direction != "in" ||
                s.PeerNumber != from || s.State != "offered") return;
            if (_voip == null || !_voip.SendFileReject(from, transferId))
            {
                Log("Could not send the encrypted decline for this file offer.", BrushWarn);
                return;
            }
            s.State = "rejected";
            s.TransferKey = null;
            Log("File offer declined.", BrushGray);
            if (_chatOpenNum == from) ChatReRender();
        }

        private void HandleFileAccept(string from, string transferId, int port)
        {
            FileTransferSession s;
            if (!_transfers.TryGetValue(transferId, out s) || s.Direction != "out" ||
                s.PeerNumber != from || s.State != "offered") return;
            s.State = "accepted";
            Log("Encrypted file offer accepted by #" + from + ".", BrushGray);
            System.Threading.Tasks.Task.Run(delegate
            {
                TcpClient tc = null;
                try
                {
                    if (_voip == null) throw new IOException("Relay service is unavailable.");
                    VoipPeer peer = _voip.FindByNumber(from);
                    if (peer == null || string.IsNullOrEmpty(peer.Ip))
                        throw new IOException("The recipient is no longer reachable through the relay directory.");
                    tc = new TcpClient(peer.Ip, port);
                    tc.SendTimeout = 30000;
                    tc.ReceiveTimeout = 30000;
                    using (NetworkStream ns = tc.GetStream())
                    using (FileStream fs = File.OpenRead(s.FilePath))
                    {
                        byte[] buf = new byte[24 * 1024];
                        long sent = 0;
                        int lastPct = -1;
                        while (sent < s.SizeBytes)
                        {
                            int want = (int)Math.Min(buf.Length, s.SizeBytes - sent);
                            int n = fs.Read(buf, 0, want);
                            if (n <= 0) throw new EndOfStreamException("The source file changed during transfer.");
                            byte[] chunk = new byte[n];
                            Buffer.BlockCopy(buf, 0, chunk, 0, n);
                            string sealedChunk = s.TransferKey.Encrypt(Convert.ToBase64String(chunk));
                            WriteTransferFrame(ns, Encoding.ASCII.GetBytes(sealedChunk));
                            sent += n;
                            int pct = s.SizeBytes == 0 ? 100 : (int)(sent * 100 / s.SizeBytes);
                            if (pct != lastPct)
                            {
                                lastPct = pct;
                                int progress = pct;
                                Dispatcher.BeginInvoke((Action)delegate
                                {
                                    if (_hubPane3ContactMeta != null) _hubPane3ContactMeta.Text = "Sending file... " + progress + "%";
                                });
                            }
                        }
                        ns.Flush();
                        tc.Client.Shutdown(SocketShutdown.Send);
                    }
                    tc.Close();
                    tc = null;
                    Dispatcher.BeginInvoke((Action)delegate
                    {
                        s.State = "complete";
                        s.TransferKey = null;
                        Log("Encrypted file sent: " + s.FileName, BrushSuccess);
                        if (_hubPane3ContactMeta != null) _hubPane3ContactMeta.Text = "";
                        if (_chatOpenNum == from) ChatReRender();
                    });
                }
                catch (Exception ex)
                {
                    Dispatcher.BeginInvoke((Action)delegate
                    {
                        s.State = "failed";
                        s.TransferKey = null;
                        Log("File send failed: " + ex.Message, BrushError);
                        if (_hubPane3ContactMeta != null) _hubPane3ContactMeta.Text = "";
                        if (_chatOpenNum == from) ChatReRender();
                    });
                }
                finally
                {
                    if (tc != null) try { tc.Close(); } catch (Exception ex) { Dispatcher.BeginInvoke((Action)delegate { Log("File socket cleanup failed: " + ex.Message, BrushWarn); }); }
                }
            });
        }

        private void HandleFileReject(string from, string transferId)
        {
            FileTransferSession s;
            if (!_transfers.TryGetValue(transferId, out s) || s.PeerNumber != from) return;
            if (s.State == "accepted") return;
            s.State = "rejected";
            s.TransferKey = null;
            Log("File transfer declined or cancelled by #" + from + ".", BrushWarn);
            if (_chatOpenNum == from) ChatReRender();
        }

        private static string FileSha256(string path)
        {
            using (System.Security.Cryptography.SHA256 sha = System.Security.Cryptography.SHA256.Create())
            using (FileStream fs = File.OpenRead(path))
            {
                byte[] hash = sha.ComputeHash(fs);
                StringBuilder hex = new StringBuilder(hash.Length * 2);
                for (int i = 0; i < hash.Length; i++) hex.Append(hash[i].ToString("X2"));
                return hex.ToString();
            }
        }

        private static string FormatFileSize(long bytes)
        {
            return bytes >= 1048576 ? (bytes / 1048576.0).ToString("0.0") + " MB"
                : bytes >= 1024 ? (bytes / 1024.0).ToString("0") + " KB" : bytes + " B";
        }

        private static string SafeReceivedFileName(string name)
        {
            string value = Path.GetFileName(name ?? "");
            char[] invalid = Path.GetInvalidFileNameChars();
            StringBuilder safe = new StringBuilder();
            for (int i = 0; i < value.Length && safe.Length < 180; i++)
                safe.Append(Array.IndexOf(invalid, value[i]) >= 0 ? '_' : value[i]);
            value = safe.ToString().Trim().Trim('.');
            return value.Length == 0 ? "attachment.bin" : value;
        }

        private static string UniqueReceivedPath(string folder, string name)
        {
            string safe = SafeReceivedFileName(name);
            string stem = Path.GetFileNameWithoutExtension(safe);
            string ext = Path.GetExtension(safe);
            string candidate = Path.Combine(folder, safe);
            int suffix = 1;
            while (File.Exists(candidate))
            {
                candidate = Path.Combine(folder, stem + " (" + suffix + ")" + ext);
                suffix++;
            }
            return candidate;
        }

        private static void WriteTransferFrame(Stream stream, byte[] payload)
        {
            if (payload == null || payload.Length == 0 || payload.Length > 65536)
                throw new InvalidDataException("Invalid encrypted chunk frame.");
            byte[] header = new byte[] {
                (byte)(payload.Length >> 24), (byte)(payload.Length >> 16),
                (byte)(payload.Length >> 8), (byte)payload.Length
            };
            stream.Write(header, 0, header.Length);
            stream.Write(payload, 0, payload.Length);
        }

        private static byte[] ReadTransferFrame(Stream stream)
        {
            byte[] header = ReadTransferBytes(stream, 4);
            int length = (header[0] << 24) | (header[1] << 16) | (header[2] << 8) | header[3];
            if (length < 1 || length > 65536) throw new InvalidDataException("Invalid encrypted chunk frame length.");
            return ReadTransferBytes(stream, length);
        }

        private static TcpClient AcceptTransferClient(TcpListener listener, int timeoutMs)
        {
            IAsyncResult pending = listener.BeginAcceptTcpClient(null, null);
            WaitHandle wait = pending.AsyncWaitHandle;
            try
            {
                if (!wait.WaitOne(timeoutMs, false))
                    throw new TimeoutException("No file connection arrived within two minutes.");
                return listener.EndAcceptTcpClient(pending);
            }
            finally { wait.Close(); }
        }

        private static byte[] ReadTransferBytes(Stream stream, int length)
        {
            byte[] data = new byte[length];
            int offset = 0;
            while (offset < length)
            {
                int n = stream.Read(data, offset, length - offset);
                if (n <= 0) throw new EndOfStreamException("The encrypted file stream ended unexpectedly.");
                offset += n;
            }
            return data;
        }

        // ── USSD session replay ───────────────────────────────────────────
        // Saves each complete USSD session (code + final response).
        // Shown as quick-repeat chips so users can re-run a previous session.
        private readonly List<UssdReplayItem> _ussdReplays = new List<UssdReplayItem>();

        private void RecordUssdSession(string code, string response)
        {
            if (string.IsNullOrEmpty(code)) return;
            // Deduplicate: update timestamp if same code exists
            foreach (UssdReplayItem r in _ussdReplays)
                if (r.Code == code) { r.When = DateTime.Now; r.LastResponse = response; return; }
            _ussdReplays.Insert(0, new UssdReplayItem { Code = code, When = DateTime.Now, LastResponse = response });
            while (_ussdReplays.Count > 20) _ussdReplays.RemoveAt(_ussdReplays.Count - 1);
            RefreshUssdReplayChips();
        }

        private WrapPanel _ussdReplayChips;

        private void RefreshUssdReplayChips()
        {
            if (_ussdReplayChips == null) return;
            _ussdReplayChips.Children.Clear();
            foreach (UssdReplayItem r in _ussdReplays)
            {
                UssdReplayItem cap = r;
                Button chip = new Button
                {
                    Content = r.Code,
                    Padding = new Thickness(10, 4, 10, 4),
                    Margin = new Thickness(0, 0, 6, 6),
                    Background = Theme.AccentSoft,
                    Foreground = BrushAccent,
                    BorderThickness = new Thickness(1),
                    BorderBrush = BrushAccent,
                    Cursor = Cursors.Hand,
                    FontFamily = new FontFamily("Consolas"),
                    FontSize = 12,
                    ToolTip = "Re-run " + r.Code + "\nLast: " + r.When.ToString("HH:mm") +
                              (r.LastResponse != null && r.LastResponse.Length > 0
                                ? "\n" + r.LastResponse.Substring(0, Math.Min(60, r.LastResponse.Length))
                                : "")
                };
                chip.Click += delegate
                {
                    if (_txtCode != null) _txtCode.Text = cap.Code;
                    Log("Replay: " + cap.Code, BrushGray);
                };
                _ussdReplayChips.Children.Add(chip);
            }
        }

        // ── Network quality dot in status bar ────────────────────────────
        private void AddNetworkQualityToStatusBar()
        {
            // Called from AddPresenceButtonToHeader after header is built.
            // We add the dot to the status bar instead (row 3 of root grid).
            try
            {
                Grid root = Content as Grid;
                if (root == null) return;
                // Find the status bar — it's the last child in row 3
                Border statusBar = null;
                foreach (UIElement el in root.Children)
                {
                    int r = Grid.GetRow(el);
                    if (r == 3) { statusBar = el as Border; break; }
                }
                if (statusBar == null) return;
                DockPanel sd = statusBar.Child as DockPanel;
                if (sd == null) return;

                _netQualityDot = new System.Windows.Shapes.Ellipse
                {
                    Width = 9, Height = 9,
                    Fill = new SolidColorBrush(Color.FromRgb(0x64, 0x74, 0x8b)),
                    VerticalAlignment = VerticalAlignment.Center,
                    Margin = new Thickness(10, 0, 4, 0)
                };
                _netQualityText = new TextBlock
                {
                    Text = "Network: Idle",
                    Foreground = BrushGray,
                    FontSize = 11,
                    VerticalAlignment = VerticalAlignment.Center
                };
                StackPanel netPill = new StackPanel { Orientation = Orientation.Horizontal };
                netPill.Children.Add(_netQualityDot);
                netPill.Children.Add(_netQualityText);
                DockPanel.SetDock(netPill, Dock.Left);
                // Insert after the existing port/carrier labels
                sd.Children.Insert(Math.Min(1, sd.Children.Count), netPill);
            }
            catch (Exception ex) { Log("NetQ UI: " + ex.Message, BrushGray); }
        }

        // ── Hub: open OTP view for a code ─────────────────────────────────
        private void HubOpenOtp(SmsCode sc)
        {
            _chatWorkspace = "otp";
            HubShowWorkspace("otp");
            if (_hubOtpCode != null) _hubOtpCode.Text = sc.Code;
            if (_hubOtpFrom != null) _hubOtpFrom.Text = "OTP from " + sc.From;
            // Run the update action stored in the grid's Tag
            if (_hubPane3Otp != null && _hubPane3Otp.Tag is Action<SmsCode>)
                ((Action<SmsCode>)_hubPane3Otp.Tag)(sc);
        }

        // ── Hub: direct dial voice call ────────────────────────────────────
        private void HubStartVoiceCall()
        {
            string num = _txtChatTo != null ? _txtChatTo.Text.Trim() : "";
            if (num.Length < 3) { Log("Hub: select a contact first.", BrushWarn); return; }
            _chatWorkspace = "voice";
            HubShowWorkspace("voice");
            if (_hubPane3ContactName != null && _hubCallState != null)
                _hubCallState.Text = "Calling " + (_hubPane3ContactName.Text ?? num) + "...";
            // 700-XXXXXXX app numbers are modem-free: they always route over
            // the relay/internet even when the transport switch says Cellular.
            string norm = AppNum.NormalizeForCall(num);
            if (AppNum.IsApp(norm) && _voip != null)
            {
                Log("App call \u279C " + AppNum.Format(norm) + " (no modem required)", BrushAccent);
                StartVoipCallByNumber(norm, false);
                return;
            }
            // Wire up the call — try VoIP first, fall back to cellular
            if (_voip != null && _dialerTransport != "cellular")
                StartVoipCallByNumber(num, false);
            else
            {
                _txtNumber.Text = num;
                var t = StartCallAsync();
            }
        }

        // ── Hub: direct dial video call ────────────────────────────────────
        private void HubStartVideoCall()
        {
            string num = _txtChatTo != null ? _txtChatTo.Text.Trim() : "";
            if (num.Length < 3) { Log("Hub: select a contact first.", BrushWarn); return; }
            _chatWorkspace = "video";
            HubShowWorkspace("video");
            StartVoipCallByNumber(num, true);
        }

        // ── Hub: show / hide Pane-3 workspaces ────────────────────────────
        private void HubShowWorkspace(string ws)
        {
            if (_hubPane3Chat  != null) _hubPane3Chat.Visibility  = (ws == "chat")  ? Visibility.Visible : Visibility.Collapsed;
            if (_hubPane3Voice != null) _hubPane3Voice.Visibility = (ws == "voice") ? Visibility.Visible : Visibility.Collapsed;
            if (_hubPane3Video != null) _hubPane3Video.Visibility = (ws == "video") ? Visibility.Visible : Visibility.Collapsed;
            if (_hubPane3Otp   != null) _hubPane3Otp.Visibility   = (ws == "otp")   ? Visibility.Visible : Visibility.Collapsed;
        }

        // ── Hub: collapse / expand Pane 2 ─────────────────────────────────
        private void HubTogglePane2()
        {
            _hubPane2Visible = !_hubPane2Visible;
            if (_hubPane2Col != null)
                _hubPane2Col.Width = _hubPane2Visible ? new GridLength(260) : new GridLength(0);
            if (_hubPane2DivCol != null)
                _hubPane2DivCol.Width = _hubPane2Visible ? new GridLength(1) : new GridLength(0);
            if (_hubPane2Toggle != null)
                _hubPane2Toggle.Content = _hubPane2Visible ? "\u25C4" : "\u25BA";  // ◄ or ►
            if (_hubPane2Toggle != null)
                _hubPane2Toggle.ToolTip = _hubPane2Visible ? "Collapse conversation list" : "Expand conversation list";
        }

        // ── Hub: attach menu — all file types ──────────────────────────────
        private void ShowAttachMenu(UIElement anchor)
        {
            ContextMenu cm = new ContextMenu();

            Action<string, string, System.Action> addItem = delegate(string icon, string label, System.Action handler)
            {
                MenuItem mi = new MenuItem { Header = icon + "  " + label };
                mi.Click += delegate { handler(); };
                cm.Items.Add(mi);
            };

            addItem("\uD83D\uDDBC", "Image  (PNG, JPG, GIF, BMP, WEBP)", delegate { HubAttachFile("image"); });
            addItem("\uD83C\uDFA5", "Video  (MP4, AVI, MOV, MKV, WEBM)", delegate { HubAttachFile("video"); });
            addItem("\uD83C\uDFA4", "Audio  (MP3, WAV, OGG, M4A)", delegate { HubAttachFile("audio"); });
            cm.Items.Add(new Separator());
            addItem("\uD83D\uDCC4", "Document  (any file)", delegate { HubAttachFile("file"); });
            addItem("\uD83D\uDCCB", "PDF  (*.pdf)", delegate { HubAttachFile("pdf"); });
            addItem("\uD83D\uDCD6", "Word Document  (*.docx, *.doc)", delegate { HubAttachFile("word"); });
            addItem("\uD83D\uDCCA", "Spreadsheet  (*.xlsx, *.csv)", delegate { HubAttachFile("excel"); });
            addItem("\uD83D\uDCBC", "Archive  (*.zip, *.7z, *.rar)", delegate { HubAttachFile("archive"); });
            cm.Items.Add(new Separator());
            addItem("\uD83D\uDCC1", "Folder  (zipped & sent)", delegate { HubAttachFolder(); });
            cm.Items.Add(new Separator());
            addItem("\uD83D\uDD17", "Link / URL", delegate { HubInsertLink(); });
            addItem("\uD83D\uDC64", "Contact card  (vCard)", delegate { HubShareContact(); });
            addItem("\uD83C\uDFA8", "Create Sticker from Image", delegate { HubCreateSticker(); });

            cm.IsOpen = true;
            cm.PlacementTarget = anchor as FrameworkElement;
            cm.Placement = PlacementMode.Top;
        }

        private void HubAttachFile(string kind)
        {
            Microsoft.Win32.OpenFileDialog dlg = new Microsoft.Win32.OpenFileDialog();
            switch (kind)
            {
                case "image":   dlg.Filter = "Images|*.png;*.jpg;*.jpeg;*.gif;*.bmp;*.webp;*.svg|All|*.*"; break;
                case "video":   dlg.Filter = "Video|*.mp4;*.avi;*.mov;*.mkv;*.webm;*.flv;*.wmv|All|*.*"; break;
                case "audio":   dlg.Filter = "Audio|*.mp3;*.wav;*.ogg;*.m4a;*.flac;*.aac|All|*.*"; break;
                case "pdf":     dlg.Filter = "PDF|*.pdf|All|*.*"; break;
                case "word":    dlg.Filter = "Word|*.docx;*.doc;*.odt|All|*.*"; break;
                case "excel":   dlg.Filter = "Spreadsheet|*.xlsx;*.xls;*.csv;*.ods|All|*.*"; break;
                case "archive": dlg.Filter = "Archive|*.zip;*.7z;*.rar;*.tar;*.gz|All|*.*"; break;
                default:        dlg.Filter = "All files|*.*"; break;
            }
            if (dlg.ShowDialog(this) != true) return;
            string path = dlg.FileName;
            string name = System.IO.Path.GetFileName(path);
            long size = 0;
            try { size = new System.IO.FileInfo(path).Length; } catch { }
            string sizeStr = size > 1048576 ? (size / 1048576.0).ToString("0.0") + " MB"
                           : size > 1024    ? (size / 1024.0).ToString("0") + " KB"
                           : size + " B";
            // Inline images under 4 MB
            if (kind == "image" && size < 4 * 1024 * 1024)
            {
                if (_txtChatInput != null) _txtChatInput.Text += "[IMAGE:" + path + "]";
                Log("Image attached: " + name, BrushGray);
            }
            else
            {
                if (_txtChatInput != null) _txtChatInput.Text += "[FILE:" + path + "|" + name + "|" + sizeStr + "]";
                Log(kind.ToUpper() + " attached: " + name + " (" + sizeStr + ")", BrushGray);
            }
        }

        private void HubAttachFolder()
        {
            try
            {
                System.Windows.Forms.FolderBrowserDialog fbd = new System.Windows.Forms.FolderBrowserDialog
                {
                    Description = "Select folder to attach (will be zipped)",
                    ShowNewFolderButton = false
                };
                if (fbd.ShowDialog() != System.Windows.Forms.DialogResult.OK) return;
                string folder = fbd.SelectedPath;
                string name = System.IO.Path.GetFileName(folder);
                string zipPath = System.IO.Path.Combine(System.IO.Path.GetTempPath(), name + "_" + DateTime.Now.Ticks + ".zip");
                System.IO.Compression.ZipFile.CreateFromDirectory(folder, zipPath);
                long size = new System.IO.FileInfo(zipPath).Length;
                string sizeStr = (size / 1024.0).ToString("0") + " KB";
                string msg = "[FILE:" + zipPath + "|" + name + ".zip|" + sizeStr + "]";
                if (_txtChatInput != null) _txtChatInput.Text += msg;
                Log("Folder zipped & attached: " + name + ".zip (" + sizeStr + ")", BrushSuccess);
            }
            catch (Exception ex)
            {
                Log("Folder attach error: " + ex.Message, BrushError);
            }
        }

        private void HubInsertLink()
        {
            Window lw = new Window
            {
                Title = "Insert Link",
                Width = 400,
                SizeToContent = SizeToContent.Height,
                ResizeMode = ResizeMode.NoResize,
                WindowStartupLocation = WindowStartupLocation.CenterOwner,
                Owner = this,
                Background = Theme.Bg
            };
            Border lc = new Border { Background = Theme.Card, BorderBrush = Theme.CardBorder, BorderThickness = new Thickness(1), CornerRadius = new CornerRadius(12), Padding = new Thickness(18, 14, 18, 14), Margin = new Thickness(10) };
            StackPanel lsp = new StackPanel();
            lsp.Children.Add(new TextBlock { Text = "Insert Link", FontSize = 14, FontWeight = FontWeights.Bold, Foreground = BrushFg, Margin = new Thickness(0, 0, 0, 10) });
            lsp.Children.Add(MakeKey("URL"));
            TextBox urlBox = MakeTextBox(0); urlBox.Margin = new Thickness(0, 2, 0, 8); urlBox.Text = "https://";
            lsp.Children.Add(urlBox);
            lsp.Children.Add(MakeKey("DISPLAY TEXT (optional)"));
            TextBox lblBox = MakeTextBox(0); lblBox.Margin = new Thickness(0, 2, 0, 12);
            lsp.Children.Add(lblBox);
            StackPanel lr = new StackPanel { Orientation = Orientation.Horizontal, HorizontalAlignment = HorizontalAlignment.Right };
            Button btnLCancel = MakeButton("Cancel"); btnLCancel.Margin = new Thickness(0, 0, 8, 0); btnLCancel.Click += delegate { lw.Close(); }; lr.Children.Add(btnLCancel);
            Button btnLInsert = MakeButton("Insert");
            Style ps = TryStyle("PrimaryButton"); if (ps != null) btnLInsert.Style = ps;
            btnLInsert.Click += delegate
            {
                string url = (urlBox.Text ?? "").Trim();
                string label = (lblBox.Text ?? "").Trim();
                if (url.Length > 0)
                {
                    string ins = label.Length > 0 ? "[" + label + "](" + url + ")" : url;
                    if (_txtChatInput != null) _txtChatInput.Text += ins;
                }
                lw.Close();
            };
            lr.Children.Add(btnLInsert);
            lsp.Children.Add(lr);
            lc.Child = lsp; lw.Content = lc; lw.ShowDialog();
        }

        private void HubCreateSticker()
        {
            Microsoft.Win32.OpenFileDialog dlg = new Microsoft.Win32.OpenFileDialog
            {
                Filter = "Images|*.png;*.jpg;*.jpeg;*.gif;*.bmp|All files|*.*",
                Title = "Create Sticker — select an image"
            };
            if (dlg.ShowDialog(this) != true) return;
            try
            {
                string src = dlg.FileName;
                string stickersDir = System.IO.Path.Combine(Home.Dir, "stickers");
                System.IO.Directory.CreateDirectory(stickersDir);
                string dest = System.IO.Path.Combine(stickersDir, "sticker_" + DateTime.Now.Ticks + System.IO.Path.GetExtension(src));
                System.IO.File.Copy(src, dest, true);
                Log("Sticker created: " + System.IO.Path.GetFileName(dest), BrushSuccess);
                // Rebuild the sticker panel so the new one appears immediately
                RebuildCustomStickers();
            }
            catch (Exception ex) { Log("Sticker create error: " + ex.Message, BrushError); }
        }

        // ── Sticker pack sync ─────────────────────────────────────────────
        // Two devices converge on one sticker set over the sealed chat channel:
        // REQ -> CAT -> WANT -> BIN, with a content hash doing the dedup, the
        // delta and the integrity check in one. Imported frames land in
        // stickers/shared/, so a pack you never made still shows in the tab.
        private string StickerRoot()
        {
            try { return System.IO.Path.Combine(Home.Dir, "stickers"); } catch { return null; }
        }

        private void SyncStickersClick()
        {
            if (_voip == null || !_voip.ChatRelayReady)
            {
                Log("Sticker sync needs the relay connected.", BrushWarn);
                return;
            }
            List<VoipPeer> online = new List<VoipPeer>();
            foreach (VoipPeer p in _voip.Peers)
            {
                if (p == null || string.IsNullOrEmpty(p.Number)) continue;
                if (p.Number == _myNumber) continue;
                if (!p.Status.StartsWith("\u25CF")) continue;
                online.Add(p);
            }
            if (online.Count == 0)
            {
                Toast.Show("No peer to sync with",
                    "Sticker sync needs another online device on the same relay.", null);
                return;
            }
            VoipPeer target = online.Count == 1 ? online[0] : PickStickerPeer(online);
            if (target == null) return;
            try
            {
                _voip.SendStickerLine(target.Number, StickerSync.MakeReq(StickerSync.SyncPack));
                Log("Sticker sync: asked #" + target.Number + " (" + target.Name + ") what they hold.", BrushGray);
            }
            catch (Exception ex) { Log("Sticker sync failed: " + ex.Message, BrushError); }
        }

        private VoipPeer PickStickerPeer(List<VoipPeer> online)
        {
            VoipPeer picked = null;
            Window pw = new Window
            {
                Title = "Sync stickers from",
                Width = 400,
                SizeToContent = SizeToContent.Height,
                ResizeMode = ResizeMode.NoResize,
                WindowStartupLocation = WindowStartupLocation.CenterOwner,
                Owner = this,
                Background = Theme.Bg
            };
            Border pc = new Border { Background = Theme.Card, BorderBrush = Theme.CardBorder, BorderThickness = new Thickness(1), CornerRadius = new CornerRadius(12), Padding = new Thickness(18, 14, 18, 14), Margin = new Thickness(10) };
            StackPanel pp = new StackPanel();
            pp.Children.Add(new TextBlock { Text = "Sync stickers from", FontSize = 14, FontWeight = FontWeights.Bold, Foreground = BrushFg, Margin = new Thickness(0, 0, 0, 8) });
            foreach (VoipPeer p in online)
            {
                VoipPeer captured = p;
                Button row = MakeButton(p.Name + "  \u00b7  #" + p.Number);
                row.HorizontalAlignment = HorizontalAlignment.Stretch;
                row.Margin = new Thickness(0, 2, 0, 2);
                row.Click += delegate { picked = captured; pw.Close(); };
                pp.Children.Add(row);
            }
            pc.Child = pp; pw.Content = pc; pw.ShowDialog();
            return picked;
        }

        private void HandleStickerLine(string from, string line)
        {
            Dispatcher.BeginInvoke((Action)delegate
            {
                string root = StickerRoot();
                if (root == null || _voip == null) return;
                try
                {
                    string packId;
                    // They asked what we hold: answer with our catalogue.
                    if (StickerSync.IsReq(line, out packId))
                    {
                        Dictionary<string, string> cat = StickerSync.CatalogAll(root);
                        _voip.SendStickerLine(from, StickerSync.MakeCat(packId, cat));
                        Log("Sticker sync: offered " + cat.Count + " frame(s) to #" + from + ".", BrushGray);
                        return;
                    }
                    string verb = line.Split('|')[0];
                    if (verb == "STKIT_CAT")
                    {
                        Dictionary<string, string> remote;
                        if (!StickerSync.TryParseCat(line, out packId, out remote)) return;
                        List<string> missing = StickerSync.Missing(remote, StickerSync.CatalogAll(root));
                        if (missing.Count == 0)
                        {
                            Log("Sticker sync: already have everything #" + from + " offered.", BrushSuccess);
                            return;
                        }
                        _voip.SendStickerLine(from, StickerSync.MakeWant(packId, missing));
                        Log("Sticker sync: asked #" + from + " for " + missing.Count + " frame(s).", BrushGray);
                        return;
                    }
                    if (verb == "STKIT_WANT")
                    {
                        List<string> hashes;
                        if (!StickerSync.TryParseWant(line, out packId, out hashes)) return;
                        // Reading up to 24 files and sealing each is real work:
                        // it goes on a worker thread so the UI stays responsive.
                        string r2 = root, peer = from, pid = packId;
                        List<string> want = hashes;
                        Thread t = new Thread((ThreadStart)delegate { ServeStickerFrames(r2, peer, pid, want); });
                        t.IsBackground = true;
                        t.Start();
                        return;
                    }
                    if (verb == "STKIT_BIN")
                    {
                        string fileName, hash;
                        byte[] data;
                        if (!StickerSync.TryParseBin(line, out packId, out fileName, out hash, out data)) return;
                        string written = StickerSync.Import(root, packId, fileName, hash, data);
                        if (written != null)
                        {
                            StickerSync.WriteManifest(System.IO.Path.Combine(root, packId),
                                packId, "Shared with me", "#");
                            Log("Sticker synced from #" + from + ": " + fileName, BrushSuccess);
                            RebuildCustomStickers();
                        }
                        else if (System.IO.File.Exists(System.IO.Path.Combine(System.IO.Path.Combine(root, packId), fileName)))
                            Log("Sticker already on this device: " + fileName, BrushGray);
                        else Log("Sticker rejected (name or hash): " + fileName, BrushWarn);
                        return;
                    }
                }
                catch (Exception ex) { Log("Sticker sync: " + ex.Message, BrushWarn); }
            });
        }

        private void ServeStickerFrames(string root, string peer, string packId, List<string> hashes)
        {
            int sent = 0, skipped = 0;
            foreach (string h in hashes)
            {
                string path = StickerSync.FindFrame(root, h);
                if (path == null) { skipped++; continue; }
                byte[] data;
                try { data = System.IO.File.ReadAllBytes(path); }
                catch { skipped++; continue; }
                if (data.Length == 0 || data.Length > StickerSync.MaxFrameBytes) { skipped++; continue; }
                try
                {
                    _voip.SendStickerLine(peer, StickerSync.MakeBin(packId, System.IO.Path.GetFileName(path), data));
                    sent++;
                }
                catch { skipped++; }
            }
            int s = sent, k = skipped;
            Dispatcher.BeginInvoke((Action)delegate
            {
                Log("Sticker sync: sent " + s + " frame(s) to #" + peer +
                    (k > 0 ? ", " + k + " unavailable" : ""), BrushSuccess);
            });
        }

        // Rebuild the custom stickers section inside the emoji picker
        private WrapPanel _customStickerPanel;
        // Frames in the stickers root, or inside every pack folder - the tab
        // shows both, so synced packs are usable straight away.
        private static void CollectStickerFrames(string root, List<string> into, bool packFolders)
        {
            try
            {
                if (!packFolders)
                {
                    into.AddRange(System.IO.Directory.GetFiles(root, "*.png"));
                    into.AddRange(System.IO.Directory.GetFiles(root, "*.jpg"));
                    into.AddRange(System.IO.Directory.GetFiles(root, "*.gif"));
                    return;
                }
                foreach (string dir in System.IO.Directory.GetDirectories(root))
                {
                    into.AddRange(System.IO.Directory.GetFiles(dir, "*.png"));
                    into.AddRange(System.IO.Directory.GetFiles(dir, "*.gif"));
                }
            }
            catch { }
        }

        private void RebuildCustomStickers()
        {
            if (_customStickerPanel == null) return;
            _customStickerPanel.Children.Clear();
            Button syncBtn = new Button
            {
                Content = "\uD83D\uDD04 Sync from peer",
                FontSize = 11,
                Margin = new Thickness(2, 2, 6, 2),
                Padding = new Thickness(8, 4, 8, 4),
                Cursor = Cursors.Hand,
                ToolTip = "Compare sticker hashes with an online peer and pull only what is missing"
            };
            Style syncStyle = TryStyle("SecondaryButton");
            if (syncStyle != null) syncBtn.Style = syncStyle;
            syncBtn.Click += delegate { SyncStickersClick(); };
            _customStickerPanel.Children.Add(syncBtn);
            string stickersDir = System.IO.Path.Combine(Home.Dir, "stickers");
            if (!System.IO.Directory.Exists(stickersDir)) return;
            List<string> stickerFiles = new List<string>();
            CollectStickerFrames(stickersDir, stickerFiles, false);
            // Pack folders count too - that is where synced frames land.
            CollectStickerFrames(stickersDir, stickerFiles, true);
            foreach (string f in stickerFiles)
            {
                try
                {
                    BitmapImage bmp = new BitmapImage();
                    bmp.BeginInit();
                    bmp.UriSource = new Uri(f, UriKind.Absolute);
                    bmp.DecodePixelWidth = 64;
                    bmp.EndInit();
                    Image img = new Image { Source = bmp, Width = 64, Height = 64, Margin = new Thickness(3), Cursor = Cursors.Hand, ToolTip = System.IO.Path.GetFileName(f) };
                    string fileCap = f;
                    img.MouseLeftButtonUp += delegate
                    {
                        if (_txtChatInput != null) _txtChatInput.Text += "[STICKER:" + fileCap + "]";
                    };
                    _customStickerPanel.Children.Add(img);
                }
                catch { }
            }
        }

        // ── Hub: apply chat background (colour or image) ───────────────────
        private void ApplyChatBackground()
        {
            if (_chatScroll == null) return;
            if (!string.IsNullOrEmpty(_chatBgImagePath) && System.IO.File.Exists(_chatBgImagePath))
            {
                try
                {
                    BitmapImage bmp = new BitmapImage(new Uri(_chatBgImagePath, UriKind.Absolute));
                    _chatScroll.Background = new ImageBrush(bmp) { Stretch = Stretch.UniformToFill, Opacity = 0.25 };
                    return;
                }
                catch { }
            }
            // Fall back to solid colour
            if (_chatBgBrush != null)
                _chatScroll.Background = _chatBgBrush;
        }

        // ── Hub: AI assistant (calls configured API) ───────────────────────
        private async Task HubAiAssistAsync()
        {
            if (!_aiEnabled)
            {
                Log("AI: disabled — go to Settings > AI to enable it and add an API key.", BrushWarn);
                // Open settings dialog on the AI tab
                ShowSettingsDialog();
                return;
            }
            if (string.IsNullOrEmpty(_aiApiKey))
            {
                Log("AI: no API key — add one in Settings > AI.", BrushWarn);
                ShowSettingsDialog();
                return;
            }
            if (_txtChatInput == null) return;
            string prompt = (_txtChatInput.Text ?? "").Trim();
            if (prompt.Length == 0)
            {
                Log("AI: type a prompt first (e.g. 'Write a professional reply to...')", BrushWarn);
                return;
            }

            Log("AI \uD83E\uDD16 sending to " + _aiModel + "...", BrushGray);
            _txtChatInput.IsEnabled = false;
            try
            {
                string result = await Task.Run(delegate { return CallAiApi(prompt); });
                if (_txtChatInput != null)
                {
                    _txtChatInput.Text = result;
                    _txtChatInput.CaretIndex = result.Length;
                    _txtChatInput.Focus();
                }
                Log("AI \u2705 response (" + result.Length + " chars) — edit if needed, then Send.", BrushSuccess);
            }
            catch (Exception ex)
            {
                Log("AI \u274C " + ex.Message, BrushError);
            }
            finally
            {
                if (_txtChatInput != null) _txtChatInput.IsEnabled = true;
            }
        }

        private string CallAiApi(string prompt)
        {
            try
            {
                System.Net.ServicePointManager.SecurityProtocol =
                    System.Net.SecurityProtocolType.Tls12;
                System.Net.HttpWebRequest req =
                    (System.Net.HttpWebRequest)System.Net.WebRequest.Create(_aiEndpoint);
                req.Method = "POST";
                req.ContentType = "application/json";
                req.Headers["Authorization"] = "Bearer " + _aiApiKey;
                req.Timeout = 30000;

                // Sanitise prompt for JSON: escape backslash, quote, and control chars
                string safePrompt = prompt
                    .Replace("\\", "\\\\")
                    .Replace("\"", "\\\"")
                    .Replace("\r", "\\r")
                    .Replace("\n", "\\n")
                    .Replace("\t", "\\t");

                string body =
                    "{\"model\":\"" + _aiModel + "\"," +
                    "\"messages\":[{\"role\":\"user\",\"content\":\"" + safePrompt + "\"}]," +
                    "\"max_tokens\":1000}";

                byte[] bytes = System.Text.Encoding.UTF8.GetBytes(body);
                req.ContentLength = bytes.Length;
                using (System.IO.Stream s = req.GetRequestStream())
                    s.Write(bytes, 0, bytes.Length);

                string json;
                using (System.Net.HttpWebResponse resp =
                    (System.Net.HttpWebResponse)req.GetResponse())
                using (System.IO.StreamReader reader =
                    new System.IO.StreamReader(resp.GetResponseStream(),
                        System.Text.Encoding.UTF8))
                    json = reader.ReadToEnd();

                // Try multiple response formats:
                // 1. OpenAI / Groq: choices[0].message.content
                // 2. Gemini: candidates[0].content.parts[0].text
                // 3. Any provider: first "content" or "text" string value

                // Pattern 1 — OpenAI style: "content": "..."
                Match m = Regex.Match(json,
                    "\"content\"\\s*:\\s*\"((?:[^\"\\\\]|\\\\.)*)\"",
                    RegexOptions.Singleline);
                if (m.Success)
                    return UnescapeJson(m.Groups[1].Value);

                // Pattern 2 — Gemini style: "text": "..."
                m = Regex.Match(json,
                    "\"text\"\\s*:\\s*\"((?:[^\"\\\\]|\\\\.)*)\"",
                    RegexOptions.Singleline);
                if (m.Success)
                    return UnescapeJson(m.Groups[1].Value);

                // Pattern 3 — error message
                m = Regex.Match(json, "\"message\"\\s*:\\s*\"((?:[^\"\\\\]|\\\\.)*)\"");
                if (m.Success)
                    throw new Exception("API error: " + UnescapeJson(m.Groups[1].Value));

                // Fallback: return raw JSON (truncated)
                return json.Length > 400 ? json.Substring(0, 400) + "..." : json;
            }
            catch (System.Net.WebException wex)
            {
                string detail = "";
                if (wex.Response != null)
                    try
                    {
                        using (System.IO.StreamReader er =
                            new System.IO.StreamReader(wex.Response.GetResponseStream()))
                            detail = er.ReadToEnd();
                    }
                    catch { }
                throw new Exception("HTTP " + wex.Status + ": " +
                    (detail.Length > 200 ? detail.Substring(0, 200) : detail));
            }
        }

        private static string UnescapeJson(string s)
        {
            return s
                .Replace("\\n", "\n")
                .Replace("\\r", "\r")
                .Replace("\\t", "\t")
                .Replace("\\\"", "\"")
                .Replace("\\\\", "\\");
        }

        // ── Hub: build Google Meet-style video call view ───────────────────
        private Grid BuildHubVideoView()
        {
            Grid g = new Grid();
            g.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });       // header pill
            g.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) }); // stage
            g.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });       // control bar

            // Header
            Border vh = new Border { Background = new SolidColorBrush(Color.FromRgb(0x12, 0x14, 0x1e)), Padding = new Thickness(14, 8, 14, 8) };
            DockPanel vhd = new DockPanel { LastChildFill = false };
            _videoStateText = new TextBlock { Text = "Video Call", Foreground = Brushes.White, FontSize = 13, FontWeight = FontWeights.Bold, VerticalAlignment = VerticalAlignment.Center };
            DockPanel.SetDock(_videoStateText, Dock.Left);
            vhd.Children.Add(_videoStateText);
            TextBlock vhPing = new TextBlock { Text = "1080p • -- ms", Foreground = BrushGray, FontSize = 11, VerticalAlignment = VerticalAlignment.Center, Margin = new Thickness(12, 0, 0, 0) };
            DockPanel.SetDock(vhPing, Dock.Left);
            vhd.Children.Add(vhPing);
            Button btnVhEnd = MakeButton("\uD83D\uDD34  End Call");
            Style danSty = TryStyle("DangerButton");
            if (danSty != null) btnVhEnd.Style = danSty;
            btnVhEnd.Click += delegate { HangupVoip(); HubShowWorkspace("chat"); };
            DockPanel.SetDock(btnVhEnd, Dock.Right);
            vhd.Children.Add(btnVhEnd);
            vh.Child = vhd;
            Grid.SetRow(vh, 0);
            g.Children.Add(vh);

            // Video stage (reuses _imgRemote from BuildVideoTab — they share the same image source)
            Border stage = new Border { Background = new SolidColorBrush(Color.FromRgb(0x0e, 0x0e, 0x16)), ClipToBounds = true };
            Grid sg = new Grid();
            Image remoteImg = new Image { Stretch = Stretch.Uniform };
            // Mirror binding: both _imgRemote and this will show frames via ShowRemoteFrame()
            sg.Children.Add(remoteImg);

            // PiP self view
            Border pip = new Border
            {
                Width = 180, Height = 112,
                Background = Brushes.Black,
                CornerRadius = new CornerRadius(8),
                BorderBrush = Theme.Success,
                BorderThickness = new Thickness(2),
                HorizontalAlignment = HorizontalAlignment.Right,
                VerticalAlignment = VerticalAlignment.Bottom,
                Margin = new Thickness(10),
                ClipToBounds = true
            };
            Image localImg = new Image { Stretch = Stretch.UniformToFill };
            pip.Child = localImg;
            sg.Children.Add(pip);

            stage.Child = sg;
            Grid.SetRow(stage, 1);
            g.Children.Add(stage);

            // Floating control bar
            Border ctrlBar = new Border
            {
                Background = new SolidColorBrush(Color.FromArgb(210, 0x16, 0x18, 0x22)),
                Padding = new Thickness(10, 8, 10, 8)
            };
            StackPanel cbsp = new StackPanel { Orientation = Orientation.Horizontal, HorizontalAlignment = HorizontalAlignment.Center };
            Button bMute = MakeButton("\uD83C\uDFA4  Mute"); bMute.Margin = new Thickness(4, 0, 4, 0); bMute.Click += delegate { ToggleMicMute(); };
            Button bCam  = MakeButton("\uD83D\uDCF9  Camera"); bCam.Margin = new Thickness(4, 0, 4, 0); bCam.Click += delegate { ToggleCamera(); };
            Button bShare = MakeButton("\uD83D\uDDA5  Share"); bShare.Margin = new Thickness(4, 0, 4, 0); bShare.Click += delegate { ToggleScreenShare(); };
            Button bHangV = MakeButton("\uD83D\uDD34  End Call"); if (danSty != null) bHangV.Style = danSty; bHangV.Margin = new Thickness(16, 0, 4, 0); bHangV.Click += delegate { HangupVoip(); HubShowWorkspace("chat"); };
            cbsp.Children.Add(bMute); cbsp.Children.Add(bCam); cbsp.Children.Add(bShare); cbsp.Children.Add(bHangV);
            ctrlBar.Child = cbsp;
            Grid.SetRow(ctrlBar, 2);
            g.Children.Add(ctrlBar);

            return g;
        }

        // ── Hub: build voice call view ─────────────────────────────────────
        private Grid BuildHubVoiceView()
        {
            Grid g = new Grid();
            g.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            g.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) });
            g.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });

            // Header
            Border vch = new Border { Background = Theme.Panel, BorderBrush = Theme.CardBorder, BorderThickness = new Thickness(0, 0, 0, 1), Padding = new Thickness(14, 8, 14, 8) };
            DockPanel vchd = new DockPanel { LastChildFill = false };
            _hubCallState = new TextBlock { Text = "Voice Call", Foreground = BrushFg, FontSize = 13, FontWeight = FontWeights.Bold, VerticalAlignment = VerticalAlignment.Center };
            DockPanel.SetDock(_hubCallState, Dock.Left);
            vchd.Children.Add(_hubCallState);
            _hubCallTimer = new TextBlock { Text = "00:00", Foreground = BrushGray, FontFamily = new FontFamily("Consolas"), FontSize = 13, VerticalAlignment = VerticalAlignment.Center, Margin = new Thickness(12, 0, 0, 0) };
            DockPanel.SetDock(_hubCallTimer, Dock.Left);
            vchd.Children.Add(_hubCallTimer);
            vch.Child = vchd;
            Grid.SetRow(vch, 0);
            g.Children.Add(vch);

            // Center stage: avatar + audio ring
            StackPanel stage = new StackPanel { HorizontalAlignment = HorizontalAlignment.Center, VerticalAlignment = VerticalAlignment.Center };
            Border avatarBorder = new Border
            {
                Width = 100, Height = 100,
                CornerRadius = new CornerRadius(50),
                Background = new LinearGradientBrush(
                    new GradientStopCollection(new GradientStop[]
                    {
                        new GradientStop(Color.FromRgb(0x4f, 0x8c, 0xff), 0),
                        new GradientStop(Color.FromRgb(0x7b, 0x5c, 0xff), 1)
                    }), 90),
                HorizontalAlignment = HorizontalAlignment.Center
            };
            TextBlock avatarTb = new TextBlock { Text = "?", Foreground = Brushes.White, FontSize = 36, FontWeight = FontWeights.Bold, HorizontalAlignment = HorizontalAlignment.Center, VerticalAlignment = VerticalAlignment.Center };
            avatarBorder.Child = avatarTb;
            stage.Children.Add(avatarBorder);

            TextBlock nameLabel = new TextBlock { Text = "", Foreground = BrushFg, FontSize = 18, FontWeight = FontWeights.Bold, HorizontalAlignment = HorizontalAlignment.Center, Margin = new Thickness(0, 14, 0, 0) };
            stage.Children.Add(nameLabel);

            // Audio ring animation text
            TextBlock audioRing = new TextBlock
            {
                Text = "\uD83D\uDD0A  )))  (((\uD83D\uDD0A",
                Foreground = BrushAccent,
                FontSize = 16,
                HorizontalAlignment = HorizontalAlignment.Center,
                Margin = new Thickness(0, 10, 0, 0),
                Opacity = 0.8
            };
            stage.Children.Add(audioRing);
            TextBlock codecLabel = new TextBlock { Text = "48 kHz • Opus", Foreground = BrushGray, FontSize = 12, HorizontalAlignment = HorizontalAlignment.Center, Margin = new Thickness(0, 6, 0, 0) };
            stage.Children.Add(codecLabel);
            Grid.SetRow(stage, 1);
            g.Children.Add(stage);

            // Keep nameLabel in sync with selected contact
            if (_hubPane3ContactName != null)
            {
                // Wire up via a reference: whenever contact name changes we update
                _hubPane3ContactName.TargetUpdated += delegate { nameLabel.Text = _hubPane3ContactName.Text; };
            }
            nameLabel.Loaded += delegate { if (_hubPane3ContactName != null) nameLabel.Text = _hubPane3ContactName.Text; };

            // Control bar
            Border vcCtrl = new Border { Background = Theme.Panel, BorderBrush = Theme.CardBorder, BorderThickness = new Thickness(0, 1, 0, 0), Padding = new Thickness(10, 10, 10, 10) };
            StackPanel vcSp = new StackPanel { Orientation = Orientation.Horizontal, HorizontalAlignment = HorizontalAlignment.Center };
            Button vcMute = MakeButton("\uD83C\uDFA4  Mute"); vcMute.Margin = new Thickness(4, 0, 4, 0); vcMute.Click += delegate { ToggleMicMute(); };
            Button vcKpad = MakeButton("\uD83D\uDD22  Keypad"); vcKpad.Margin = new Thickness(4, 0, 4, 0); vcKpad.Click += delegate { ToggleOverlayKeypad(); };
            Button vcEnd = MakeButton("\uD83D\uDD34  End Call");
            Style danSty2 = TryStyle("DangerButton");
            if (danSty2 != null) vcEnd.Style = danSty2;
            vcEnd.Margin = new Thickness(16, 0, 4, 0);
            vcEnd.Click += delegate
            {
                HangupVoip();
                var t = EndCallAsync();
                HubShowWorkspace("chat");
            };
            vcSp.Children.Add(vcMute); vcSp.Children.Add(vcKpad); vcSp.Children.Add(vcEnd);
            vcCtrl.Child = vcSp;
            Grid.SetRow(vcCtrl, 2);
            g.Children.Add(vcCtrl);

            return g;
        }

        // ── Hub: build OTP detail view ─────────────────────────────────────
        private Grid BuildHubOtpView(Border otpBannerRef)
        {
            Grid g = new Grid();
            g.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            g.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) });
            g.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });

            Border otpHeader = new Border { Background = Theme.Panel, BorderBrush = Theme.CardBorder, BorderThickness = new Thickness(0, 0, 0, 1), Padding = new Thickness(14, 8, 14, 8) };
            otpHeader.Child = new TextBlock { Text = "\uD83D\uDD11  Verification Code", FontSize = 14, FontWeight = FontWeights.Bold, Foreground = BrushFg };
            Grid.SetRow(otpHeader, 0);
            g.Children.Add(otpHeader);

            StackPanel body = new StackPanel { HorizontalAlignment = HorizontalAlignment.Center, VerticalAlignment = VerticalAlignment.Center, Margin = new Thickness(20) };
            TextBlock fromLbl = new TextBlock { Text = "From", Foreground = BrushGray, FontSize = 12, HorizontalAlignment = HorizontalAlignment.Center };
            body.Children.Add(fromLbl);
            TextBlock fromVal = new TextBlock { Text = "—", Foreground = BrushFg, FontSize = 16, FontWeight = FontWeights.Bold, HorizontalAlignment = HorizontalAlignment.Center, Margin = new Thickness(0, 2, 0, 14) };
            body.Children.Add(fromVal);

            Border codeDisplay = new Border
            {
                Background = Theme.Chrome,
                BorderBrush = Theme.Accent,
                BorderThickness = new Thickness(2),
                CornerRadius = new CornerRadius(12),
                Padding = new Thickness(28, 16, 28, 16),
                HorizontalAlignment = HorizontalAlignment.Center,
                Margin = new Thickness(0, 0, 0, 14)
            };
            TextBlock codeVal = new TextBlock
            {
                Text = "------",
                Foreground = BrushAccent,
                FontSize = 36,
                FontFamily = new FontFamily("Consolas"),
                FontWeight = FontWeights.Bold,
                HorizontalAlignment = HorizontalAlignment.Center
            };
            codeDisplay.Child = codeVal;
            body.Children.Add(codeDisplay);

            TextBlock expiryTb = new TextBlock { Text = "Expires in —", Foreground = BrushWarn, FontSize = 13, HorizontalAlignment = HorizontalAlignment.Center, Margin = new Thickness(0, 0, 0, 20) };
            body.Children.Add(expiryTb);

            WrapPanel actions = new WrapPanel { HorizontalAlignment = HorizontalAlignment.Center, Margin = new Thickness(0, 4, 0, 0) };
            Style primaryStyle = TryStyle("PrimaryButton");
            Button btnOtpCopy = MakeButton("\uD83D\uDCCB  Copy Code");
            if (primaryStyle != null) btnOtpCopy.Style = primaryStyle;
            btnOtpCopy.Padding = new Thickness(18, 8, 18, 8);
            btnOtpCopy.Margin = new Thickness(0, 0, 8, 8);
            btnOtpCopy.Click += delegate { if (codeVal.Text != "------") try { Clipboard.SetText(codeVal.Text); Log("OTP copied: " + codeVal.Text, BrushSuccess); } catch { } };
            actions.Children.Add(btnOtpCopy);

            Button btnOtpDelete = MakeButton("\uD83D\uDDD1  Delete");
            Style danSty3 = TryStyle("DangerButton");
            if (danSty3 != null) btnOtpDelete.Style = danSty3;
            btnOtpDelete.Padding = new Thickness(18, 8, 18, 8);
            btnOtpDelete.Margin = new Thickness(0, 0, 0, 8);
            btnOtpDelete.Click += delegate { HubSelectCategory("codes"); HubShowWorkspace("chat"); };
            actions.Children.Add(btnOtpDelete);
            body.Children.Add(actions);
            Grid.SetRow(body, 1);
            g.Children.Add(body);

            // Wire up: when HubOpenOtp is called, update codeVal and fromVal
            // We do this by making codeVal/fromVal accessible via a closure
            // The grid tag carries a lambda
            g.Tag = new Action<SmsCode>(delegate(SmsCode sc2)
            {
                codeVal.Text = sc2.Code;
                fromVal.Text = sc2.From;
                expiryTb.Text = "Received at " + sc2.Time;
            });

            // Also show the banner
            if (_hubOtpCode != null && _hubOtpFrom != null)
            {
                _hubOtpCode.Tag = codeVal;    // keep in sync
                _hubOtpFrom.Tag = fromVal;
            }

            Grid.SetRow(new Border(), 2); // spacer
            g.RowDefinitions[2].Height = GridLength.Auto;
            return g;
        }

        private Grid BuildSimTab()
        {
            Grid g = new Grid { Margin = new Thickness(6) };
            g.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            g.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            g.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });

            StackPanel bar = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(8, 6, 8, 2) };
            bar.Children.Add(new TextBlock { Text = "SIM / MODEM INFORMATION (auto-detected & auto-configured on connect)",
                Foreground = BrushGray, FontWeight = FontWeights.Bold, VerticalAlignment = VerticalAlignment.Center });
            Button btnRefreshSim = MakeButton("Refresh Now");
            btnRefreshSim.Margin = new Thickness(16, 0, 0, 0);
            bar.Children.Add(btnRefreshSim);
            btnRefreshSim.Click += async delegate { await RefreshSimInfoAsync(false); };
            Button btnReconfig = MakeButton("Reconfigure Modem");
            btnReconfig.Margin = new Thickness(6, 0, 0, 0);
            bar.Children.Add(btnReconfig);
            btnReconfig.Click += async delegate { await ReconfigureModemAsync(); };
            Grid.SetRow(bar, 0);
            g.Children.Add(bar);

            Grid info = new Grid { Margin = new Thickness(12, 4, 12, 4) };
            info.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
            info.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            info.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
            info.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            for (int i = 0; i < 9; i++) info.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });

            int row = 0;
            AddInfoRow(info, ref row, 0, "SIM Status:", out _valPin);
            AddInfoRow(info, ref row, 0, "Operator:", out _valOp);
            AddInfoRow(info, ref row, 0, "Signal:", out _valSig);
            AddInfoRow(info, ref row, 0, "Network Reg:", out _valReg);
            AddInfoRow(info, ref row, 0, "Battery:", out _valBatt);
            AddInfoRow(info, ref row, 0, "Phonebook:", out _valPhonebook);
            int row2 = 0;
            AddInfoRow2Col(info, ref row2, "ICCID:", out _valIccid);
            AddInfoRow2Col(info, ref row2, "IMSI:", out _valImsi);
            AddInfoRow2Col(info, ref row2, "IMEI:", out _valImei);
            AddInfoRow2Col(info, ref row2, "SIM Type:", out _valSimType);
            AddInfoRow2Col(info, ref row2, "Carrier:", out _valCarrier);
            AddInfoRow2Col(info, ref row2, "SIM Slot:", out _valSlot);
            Grid.SetRow(info, 1);
            g.Children.Add(info);

            GroupBox log2 = MakeGroup("Auto-configuration");
            TextBlock autoInfo = new TextBlock
            {
                Foreground = BrushGray,
                TextWrapping = TextWrapping.Wrap,
                Margin = new Thickness(4),
                Text = "On connect the modem is initialized (echo off, text SMS mode, SMS notifications, caller ID) and the SIM is identified " +
                       "(ICCID/IMSI/IMEI/operator). Every 20 s the SIM is re-checked - if the SIM card changes, the modem is re-configured automatically. " +
                       "Incoming SMS are stored and verification codes extracted."
            };
            log2.Content = autoInfo;
            Grid.SetRow(log2, 2);
            g.Children.Add(log2);

            return g;
        }

        private void AddInfoRow(Grid info, ref int row, int colPair, string key, out TextBlock val)
        {
            Label l = MakeLabel(key);
            Grid.SetRow(l, row);
            Grid.SetColumn(l, colPair == 0 ? 0 : 2);
            info.Children.Add(l);
            val = MakeVal();
            Grid.SetRow(val, row);
            Grid.SetColumn(val, colPair == 0 ? 1 : 3);
            info.Children.Add(val);
            row++;
        }

        private void AddInfoRow2Col(Grid info, ref int row, string key, out TextBlock val)
        {
            Label l = MakeLabel(key);
            Grid.SetRow(l, row);
            Grid.SetColumn(l, 2);
            info.Children.Add(l);
            val = MakeVal();
            Grid.SetRow(val, row);
            Grid.SetColumn(val, 3);
            info.Children.Add(val);
            row++;
        }

        private Grid BuildUssdTab()
        {
            Grid g = new Grid { Margin = new Thickness(6) };
            for (int i = 0; i < 9; i++) g.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            g.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) });

            GroupBox modeGroup = MakeGroup("Connection Method");
            StackPanel modePanel = new StackPanel { Orientation = Orientation.Horizontal };
            _radioMifi = new RadioButton { Content = "Method 1: MiFi Web API (HTTP)", IsChecked = true, Margin = new Thickness(8, 2, 8, 2), Foreground = BrushFg };
            _radioSerial = new RadioButton { Content = "Method 2: USB Modem AT (connected modem)", Margin = new Thickness(8, 2, 8, 2), Foreground = BrushFg };
            _radioMifi.Checked += delegate { ToggleUssdPanels(); };
            _radioSerial.Checked += delegate { ToggleUssdPanels(); };
            modePanel.Children.Add(_radioMifi);
            modePanel.Children.Add(_radioSerial);
            modeGroup.Content = modePanel;
            Grid.SetRow(modeGroup, 0);
            g.Children.Add(modeGroup);

            _panelMifi = MakeGroup("MiFi Web API Settings");
            StackPanel mp = new StackPanel { Orientation = Orientation.Horizontal };
            mp.Children.Add(MakeLabel("MiFi IP:"));
            _txtMifiIp = MakeTextBox(220);
            _txtMifiIp.Text = "http://192.168.100.1";
            mp.Children.Add(_txtMifiIp);
            Button btnTestMifi = MakeButton("Test Connection");
            btnTestMifi.Margin = new Thickness(8, 0, 0, 0);
            btnTestMifi.Click += async delegate
            {
                string ip = _txtMifiIp.Text;
                Log("Testing " + ip + " ...", BrushAccent);
                try
                {
                    string probe = await Task.Run(delegate { return MifiApi.Probe(ip); });
                    _mifiProbe = probe;
                    _mifiProbeTime = DateTime.Now;
                    if (probe == "huawei-goform")
                    {
                        Log("MiFi online: Huawei/ZTE goform API detected - USSD supported via Method 1.", BrushSuccess);
                        SetStatus("MiFi: USSD capable", BrushSuccess);
                    }
                    else if (probe == "himi-spa")
                    {
                        Log("MiFi online: 4G MIFI (Himi-spa) - web API has no USSD command; USSD will use the USB modem automatically.", BrushWarn);
                        SetStatus("MiFi: auto-fallback to USB", BrushWarn);
                    }
                    else if (probe.StartsWith("unreachable:"))
                        Log("MiFi unreachable: " + probe.Substring("unreachable:".Length), BrushError);
                    else
                        Log("MiFi reachable but API unrecognized (" + probe + "). USSD will fall back to the USB modem.", BrushWarn);
                }
                catch (Exception ex) { Log("MiFi unreachable: " + ex.Message, BrushError); }
            };
            mp.Children.Add(btnTestMifi);
            _panelMifi.Content = mp;
            Grid.SetRow(_panelMifi, 1);
            g.Children.Add(_panelMifi);

            GroupBox serialNote = MakeGroup("USB Modem AT");
            serialNote.Content = new TextBlock
            {
                Foreground = BrushGray,
                TextWrapping = TextWrapping.Wrap,
                Margin = new Thickness(4),
                Text = "Uses the connected modem from the Connect bar. Connect first - USSD, SMS and calls then share the modem safely."
            };
            serialNote.Visibility = Visibility.Collapsed;
            Grid.SetRow(serialNote, 2);
            g.Children.Add(serialNote);
            _serialNotePanel = serialNote;

            // --- Carrier selector + preset library ---
            GroupBox carrierGroup = MakeGroup("Carrier Presets");
            StackPanel cp = new StackPanel { Orientation = Orientation.Horizontal };
            cp.Children.Add(MakeLabel("Carrier:"));
            _comboCarrier = new ComboBox
            {
                Width = 170,
                Background = BrushPanel,
                Foreground = BrushFg,
                BorderBrush = BrushBorder,
                Padding = new Thickness(4, 3, 4, 3),
                Margin = new Thickness(4, 0, 8, 0)
            };
            _comboCarrier.Items.Add("Auto (from SIM)");
            _comboCarrier.Items.Add("MTN");
            _comboCarrier.Items.Add("Telecel");
            _comboCarrier.Items.Add("AirtelTigo");
            _comboCarrier.Items.Add("Glo");
            _comboCarrier.Items.Add("Universal");
            _comboCarrier.SelectedIndex = 0;
            _comboCarrier.SelectionChanged += delegate { RebuildPresetChips(); };
            cp.Children.Add(_comboCarrier);
            WrapPanel presetsPanel = new WrapPanel { Margin = new Thickness(4, 2, 4, 2) };
            carrierGroup.Content = cp;
            Grid.SetRow(carrierGroup, 3);
            g.Children.Add(carrierGroup);

            // --- Preset chips (rebuilt per carrier) ---
            GroupBox presetGroup = MakeGroup("Quick Codes");
            presetGroup.Content = presetsPanel;
            Grid.SetRow(presetGroup, 4);
            g.Children.Add(presetGroup);
            _presetPanel = presetsPanel;

            // --- Send row ---
            GroupBox sendGroup = MakeGroup("Send USSD");
            Grid sg = new Grid();
            sg.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
            sg.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            sg.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });

            Label lblCode = MakeLabel("Code:");
            Grid.SetColumn(lblCode, 0); sg.Children.Add(lblCode);
            _txtCode = MakeTextBox(0);
            _txtCode.Text = "*124#";
            _txtCode.KeyDown += async delegate(object s, KeyEventArgs e)
            {
                if (e.Key == Key.Enter) { e.Handled = true; await SendUssdAsync(); }
            };
            Grid.SetColumn(_txtCode, 1); sg.Children.Add(_txtCode);

            Button btnSend = MakeButton("SEND");
            btnSend.Margin = new Thickness(12, 0, 0, 0);
            btnSend.Padding = new Thickness(18, 5, 18, 5);
            btnSend.FontWeight = FontWeights.Bold;
            btnSend.Background = BrushAccent;
            btnSend.Foreground = Brushes.White;
            btnSend.Click += async delegate { await SendUssdAsync(); };
            Grid.SetColumn(btnSend, 2);
            sg.Children.Add(btnSend);

            sendGroup.Content = sg;
            Grid.SetRow(sendGroup, 5);
            g.Children.Add(sendGroup);

            // --- Response panel ---
            GroupBox respGroup = MakeGroup("USSD Response");
            _txtUssdResp = MakeMultiBox();
            _txtUssdResp.IsReadOnly = true;
            _txtUssdResp.MinHeight = 110;
            _txtUssdResp.FontSize = 13;
            _txtUssdResp.Foreground = BrushFg;
            respGroup.Content = _txtUssdResp;
            Grid.SetRow(respGroup, 6);
            g.Children.Add(respGroup);

            // --- Reply row (multi-step session) ---
            GroupBox replyGroup = MakeGroup("Reply to Menu");
            Grid rg = new Grid();
            rg.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
            rg.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            rg.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
            rg.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
            Label lblReply = MakeLabel("Choice:");
            Grid.SetColumn(lblReply, 0); rg.Children.Add(lblReply);
            _txtUssdReply = MakeTextBox(0);
            _txtUssdReply.KeyDown += async delegate(object s, KeyEventArgs e)
            {
                if (e.Key == Key.Enter) { e.Handled = true; await SendUssdReplyAsync(); }
            };
            Grid.SetColumn(_txtUssdReply, 1); rg.Children.Add(_txtUssdReply);
            Button btnReply = MakeButton("REPLY");
            btnReply.Margin = new Thickness(8, 0, 0, 0);
            btnReply.Background = BrushAccent;
            btnReply.Foreground = Brushes.White;
            btnReply.Click += async delegate { await SendUssdReplyAsync(); };
            Grid.SetColumn(btnReply, 2); rg.Children.Add(btnReply);
            Button btnCancelUssd = MakeButton("Cancel");
            btnCancelUssd.Margin = new Thickness(6, 0, 0, 0);
            btnCancelUssd.Click += async delegate { await CancelUssdAsync(); };
            Grid.SetColumn(btnCancelUssd, 3); rg.Children.Add(btnCancelUssd);
            replyGroup.Content = rg;
            Grid.SetRow(replyGroup, 7);
            g.Children.Add(replyGroup);

            // --- Quick-reply chips (appear after a menu response) ---
            GroupBox chipGroup = MakeGroup("Menu Choices");
            _ussdChips = new WrapPanel { Margin = new Thickness(2) };
            chipGroup.Content = _ussdChips;
            Grid.SetRow(chipGroup, 8);
            g.Children.Add(chipGroup);

            // --- Quick-replay chips (recent USSD codes from previous sessions) ---
            GroupBox replayGroup = MakeGroup("\u23F1  Recent USSD — click to repeat");
            _ussdReplayChips = new WrapPanel { Margin = new Thickness(4, 2, 4, 4) };
            replayGroup.Content = _ussdReplayChips;
            g.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            int replayRow = g.RowDefinitions.Count - 1;
            Grid.SetRow(replayGroup, replayRow);
            g.Children.Add(replayGroup);
            RefreshUssdReplayChips();

            // --- Session history ---
            GroupBox histGroup = MakeGroup("Session History (double-click to reload)");
            _lvUssdHistory = MakeListView();
            _lvUssdHistory.MinHeight = 150;
            GridView hv = new GridView();
            hv.Columns.Add(new GridViewColumn { Header = "Time", DisplayMemberBinding = new Binding("Time"), Width = 70 });
            hv.Columns.Add(new GridViewColumn { Header = "Code", DisplayMemberBinding = new Binding("Code"), Width = 110 });
            hv.Columns.Add(new GridViewColumn { Header = "Response", DisplayMemberBinding = new Binding("Preview"), Width = 560 });
            _lvUssdHistory.View = hv;
            _lvUssdHistory.MouseDoubleClick += delegate
            {
                UssdSession sel = _lvUssdHistory.SelectedItem as UssdSession;
                if (sel == null) return;
                _txtCode.Text = sel.Code;
                _txtUssdResp.Text = sel.Response;
                _lastUssdCode = sel.Code;
                RebuildUssdChips(sel.Response);
                Log("History loaded: " + sel.Code, BrushGray);
            };
            histGroup.Content = _lvUssdHistory;
            Grid.SetRow(histGroup, 9);
            g.Children.Add(histGroup);

            RebuildPresetChips();
            return g;
        }

        // ---------- USSD presets ----------
        private WrapPanel _presetPanel;

        private class UssdPreset
        {
            public string Label;
            public string Code;
            public UssdPreset(string label, string code) { Label = label; Code = code; }
        }

        private static UssdPreset[] UssdPresetsFor(string carrier)
        {
            List<UssdPreset> list = new List<UssdPreset>();
            // Universal (every Ghana network)
            list.Add(new UssdPreset("Balance *124#", "*124#"));
            list.Add(new UssdPreset("Registration status *404#", "*404#"));
            list.Add(new UssdPreset("Verify registered *400#", "*400#"));
            list.Add(new UssdPreset("Customer care 100", "100"));
            list.Add(new UssdPreset("IMEI *#06#", "*#06#"));
            switch (carrier)
            {
                case "MTN":
                    list.Add(new UssdPreset("MoMo *170#", "*170#"));
                    list.Add(new UssdPreset("Data bundles *138#", "*138#"));
                    list.Add(new UssdPreset("My number *156#", "*156#"));
                    list.Add(new UssdPreset("Transfer *198#", "*198#"));
                    list.Add(new UssdPreset("Borrow *506#", "*506#"));
                    break;
                case "Telecel":
                    list.Add(new UssdPreset("Telecel Cash *110#", "*110#"));
                    list.Add(new UssdPreset("Data *480#", "*480#"));
                    list.Add(new UssdPreset("My number *127#", "*127#"));
                    list.Add(new UssdPreset("Services *151#", "*151#"));
                    list.Add(new UssdPreset("Manage *301#", "*301#"));
                    break;
                case "AirtelTigo":
                    list.Add(new UssdPreset("ATMoney *110#", "*110#"));
                    list.Add(new UssdPreset("Data *166#", "*166#"));
                    list.Add(new UssdPreset("My number *703#", "*703#"));
                    break;
                case "Glo":
                    list.Add(new UssdPreset("Data *776#", "*776#"));
                    list.Add(new UssdPreset("My number *135#", "*135#"));
                    break;
                case "Universal":
                default:
                    break;
            }
            return list.ToArray();
        }

        private string SelectedCarrier()
        {
            string sel = _comboCarrier.SelectedItem == null ? "Auto (from SIM)" : _comboCarrier.SelectedItem.ToString();
            if (sel.StartsWith("Auto"))
            {
                if (!string.IsNullOrEmpty(_simCarrierKey)) return _simCarrierKey;
                return "Universal";
            }
            return sel;
        }

        private void RebuildPresetChips()
        {
            if (_presetPanel == null || _comboCarrier == null) return;
            _presetPanel.Children.Clear();
            UssdPreset[] presets = UssdPresetsFor(SelectedCarrier());
            for (int i = 0; i < presets.Length; i++)
            {
                UssdPreset p = presets[i];
                Button b = MakeButton(p.Label);
                b.Margin = new Thickness(4, 3, 4, 3);
                b.Padding = new Thickness(8, 3, 8, 3);
                string code = p.Code;
                b.Click += delegate
                {
                    _txtCode.Text = code;
                    _txtCode.Focus();
                };
                _presetPanel.Children.Add(b);
            }
        }

        public class UssdSession
        {
            public string Time { get; set; }
            public string Code { get; set; }
            public string Response { get; set; }
            public string Preview
            {
                get
                {
                    if (Response == null) return "";
                    string t = Response.Replace("\r", " ").Replace("\n", " ");
                    return t.Length > 90 ? t.Substring(0, 90) + "..." : t;
                }
            }
        }

        // Called after every USSD exchange: show text, remember session, build chips.
        private void ShowUssdResponse(string code, string text, string raw)
        {
            _lastUssdCode = code;
            string display = text;
            if (!string.IsNullOrEmpty(raw) && raw != text && raw.Contains("+CUSD"))
                display = text + "\n\n[raw] " + raw.Trim();
            ShowUssdResponseTyped(display);
            _ussdSessionActive = text != null &&
                !text.Contains("ERROR") && !text.Contains("failed");
            UssdSession s = new UssdSession
            {
                Time = DateTime.Now.ToString("HH:mm:ss"),
                Code = code,
                Response = text
            };
            _ussdSessions.Insert(0, s);
            if (_ussdSessions.Count > 50) _ussdSessions.RemoveAt(_ussdSessions.Count - 1);
            _lvUssdHistory.ItemsSource = null;
            _lvUssdHistory.ItemsSource = _ussdSessions;
            _lvUssdHistory.SelectedIndex = 0;
            // Record in replay chips so user can one-click repeat
            RecordUssdSession(code, text);
            RebuildUssdChips(text);
        }

        // Parse "1. Balance" style menu lines into tappable chips.
        private void RebuildUssdChips(string response)
        {
            if (_ussdChips == null) return;
            _ussdChips.Children.Clear();
            if (response == null) return;
            System.Text.RegularExpressions.MatchCollection ms =
                Regex.Matches(response, @"(?m)^\s*(\d{1,2})[.)]\s+([^\r\n]+)");
            int n = 0;
            foreach (System.Text.RegularExpressions.Match m in ms)
            {
                string num = m.Groups[1].Value;
                string label = num + " " + m.Groups[2].Value.Trim();
                if (label.Length > 40) label = label.Substring(0, 40) + "...";
                Button chip = MakeButton(label);
                chip.Margin = new Thickness(3, 2, 3, 2);
                chip.Padding = new Thickness(8, 2, 8, 2);
                string replyVal = num;
                chip.Click += delegate
                {
                    _txtUssdReply.Text = replyVal;
                    _txtUssdReply.Focus();
                };
                chip.MouseDoubleClick += async delegate { await SendUssdReplyAsync(); };
                _ussdChips.Children.Add(chip);
                if (++n >= 12) break;
            }
            // Common no-reply-required hint
            if (n == 0 && _ussdSessionActive)
            {
                TextBlock hint = new TextBlock
                {
                    Text = "No menu detected - tap Send a new code above (this session is done).",
                    Foreground = BrushGray,
                    Margin = new Thickness(4, 6, 4, 6)
                };
                _ussdChips.Children.Add(hint);
            }
        }

        private async Task SendUssdReplyAsync()
        {
            string reply = _txtUssdReply.Text.Trim();
            if (reply.Length == 0) { Log("Type or tap a menu choice first.", BrushWarn); return; }
            await SendUssdRawAsync("AT+CUSD=1,\"" + reply + "\",15", "reply " + reply);
        }

        private async Task CancelUssdAsync()
        {
            if (!_modem.IsOpen) { Log("Connect the modem first.", BrushError); return; }
            _busy = true;
            try
            {
                Log("Cancelling USSD session...", BrushAccent);
                await Task.Run(delegate { _modem.SendCommand("AT+CUSD=2", "^(OK|ERROR)", 8000); });
                _ussdSessionActive = false;
                _ussdChips.Children.Clear();
                Log("USSD session cancelled.", BrushGray);
                SetStatus("USSD cancelled", BrushGray);
            }
            catch (Exception ex) { Log("Cancel error: " + ex.Message, BrushError); }
            finally { _busy = false; }
        }

        private async Task SendUssdRawAsync(string at, string what)
        {
            if (_busy) { Log("Busy - please wait...", BrushWarn); return; }
            if (!_modem.IsOpen) { Log("Connect the modem first (Connect bar).", BrushError); return; }
            _busy = true;
            try
            {
                Log("Sending USSD " + what + " ...", BrushAccent);
                string result = await Task.Run(delegate
                {
                    string[] r = _modem.SendCommand(at, "^(OK|ERROR|\\+CME ERROR|\\+CUSD)", 35000);
                    return string.Join("\n", r);
                });
                string parsed = SerialUssd.ExtractUssdText(result);
                ShowUssdResponse((_lastUssdCode ?? "") + " > " + what, parsed, result);
                Log("USSD response: " + parsed, BrushSuccess);
                SetStatus("USSD done", BrushSuccess);
            }
            catch (Exception ex) { Log("USSD error: " + ex.Message, BrushError); }
            finally { _busy = false; }
        }

        private void ToggleSidebar()
        {
            _sidebarOpen = !_sidebarOpen;
            if (_sidebarOpen)
            {
                // Restore full sidebar
                _sidebarIconOnly = false;
                _sidebarCol.Width = new GridLength(252);
                _sidebar.Visibility = Visibility.Visible;
                _sidebar.Padding = new Thickness(10, 12, 10, 10);
                if (_sidebarHeading != null) _sidebarHeading.Visibility = Visibility.Visible;
                if (_sidebarFooter != null) _sidebarFooter.Visibility = Visibility.Visible;
                for (int i = 0; i < _navSectionLabels.Count; i++)
                    _navSectionLabels[i].Visibility = Visibility.Visible;
                // Show full nav button text
                for (int i = 0; i < _navButtons.Count; i++)
                {
                    _navButtons[i].Content = _pageNames[i];
                    _navButtons[i].HorizontalContentAlignment = HorizontalAlignment.Left;
                    _navButtons[i].Padding = new Thickness(12, 9, 12, 9);
                }
            }
            else
            {
                // Collapse to icon-only strip (40px)
                _sidebarIconOnly = true;
                _sidebarCol.Width = new GridLength(58);
                _sidebar.Visibility = Visibility.Visible;
                _sidebar.Padding = new Thickness(4, 12, 4, 10);
                if (_sidebarHeading != null) _sidebarHeading.Visibility = Visibility.Collapsed;
                if (_sidebarFooter != null) _sidebarFooter.Visibility = Visibility.Collapsed;
                for (int i = 0; i < _navSectionLabels.Count; i++)
                    _navSectionLabels[i].Visibility = Visibility.Collapsed;
                // Show only emoji icon in each nav button
                for (int i = 0; i < _navButtons.Count; i++)
                {
                    _navButtons[i].Content = _pageIcons[i];
                    _navButtons[i].HorizontalContentAlignment = HorizontalAlignment.Center;
                    _navButtons[i].Padding = new Thickness(4, 9, 4, 9);
                    _navButtons[i].ToolTip = _pageLabels[i];
                }
            }
        }

        // Modem Setup popover — opened when the user clicks the COM pill in the header.
        private void ShowModemSetupPopover(UIElement anchor)
        {
            if (_modemPopup != null && _modemPopup.IsOpen)
            {
                _modemPopup.IsOpen = false;
                return;
            }
            Border card = new Border
            {
                Background = Theme.Card,
                BorderBrush = Theme.CardBorder,
                BorderThickness = new Thickness(1),
                CornerRadius = new CornerRadius(12),
                Padding = new Thickness(16, 14, 16, 14),
                Effect = (System.Windows.Media.Effects.Effect)Application.Current.TryFindResource("CardShadow")
            };
            StackPanel sp = new StackPanel { Width = 320 };

            TextBlock hdr = new TextBlock
            {
                Text = "Modem Setup",
                FontSize = 14,
                FontWeight = FontWeights.Bold,
                Foreground = BrushFg,
                Margin = new Thickness(0, 0, 0, 10)
            };
            sp.Children.Add(hdr);

            sp.Children.Add(MakeKey("COM PORT"));
            sp.Children.Add(_comboPort);
            _comboPort.Margin = new Thickness(0, 3, 0, 10);

            sp.Children.Add(MakeKey("BAUD RATE"));
            sp.Children.Add(_comboBaud);
            _comboBaud.Margin = new Thickness(0, 3, 0, 10);

            sp.Children.Add(_chkAuto);
            _chkAuto.Margin = new Thickness(0, 0, 0, 12);

            StackPanel btnRow = new StackPanel { Orientation = Orientation.Horizontal };
            _btnConnect.Padding = new Thickness(18, 7, 18, 7);
            _btnConnect.Margin = new Thickness(0, 0, 8, 0);
            btnRow.Children.Add(_btnConnect);

            Button btnRefreshPop = MakeButton("Refresh Ports");
            btnRefreshPop.Padding = new Thickness(12, 7, 12, 7);
            btnRefreshPop.Click += delegate { RefreshPorts(); };
            btnRow.Children.Add(btnRefreshPop);
            sp.Children.Add(btnRow);

            // SIM summary inside the popover too
            Border simRow = new Border
            {
                Background = Theme.Chrome,
                CornerRadius = new CornerRadius(8),
                Padding = new Thickness(10, 7, 10, 7),
                Margin = new Thickness(0, 12, 0, 0)
            };
            _simSummary.Margin = new Thickness(0);
            simRow.Child = _simSummary;
            sp.Children.Add(simRow);

            card.Child = sp;

            _modemPopup = new System.Windows.Controls.Primitives.Popup
            {
                Child = card,
                PlacementTarget = anchor,
                Placement = System.Windows.Controls.Primitives.PlacementMode.Bottom,
                StaysOpen = false,
                AllowsTransparency = true,
                PopupAnimation = System.Windows.Controls.Primitives.PopupAnimation.Fade,
                IsOpen = true,
                HorizontalOffset = -240  // align right edge of popup with pill
            };
        }

        private void ShowPage(int index)
        {
            if (index < 0 || index >= _pages.Count) return;
            _pages[_pageIndex].Visibility = Visibility.Collapsed;
            _pageIndex = index;
            _pages[_pageIndex].Visibility = Visibility.Visible;
            AnimateSlideIn(_pages[_pageIndex]);
            UpdateShellPageHeading();
            HighlightNav();
        }

        private void UpdateShellPageHeading()
        {
            if (_shellPageTitle == null || _shellPageDescription == null ||
                _pageIndex < 0 || _pageIndex >= _pageLabels.Count) return;
            _shellPageTitle.Text = _pageLabels[_pageIndex];
            _shellPageDescription.Text = _pageDescriptions[_pageIndex];
        }

        // Switch the dialer between Cellular and VoIP transport modes.
        // The right panel contents and the CALL button target change accordingly.
        private void SetDialerTransport(string mode)
        {
            _dialerTransport = mode;
            bool isCellular = mode == "cellular";

            if (_btnTransportCellular != null)
            {
                _btnTransportCellular.Background = isCellular ? Theme.Accent : Brushes.Transparent;
                _btnTransportCellular.Foreground = isCellular ? (Brush)Brushes.White : BrushGray;
                _btnTransportCellular.FontWeight = isCellular ? FontWeights.Bold : FontWeights.Normal;
            }
            if (_btnTransportVoip != null)
            {
                _btnTransportVoip.Background = !isCellular ? Theme.Accent : Brushes.Transparent;
                _btnTransportVoip.Foreground = !isCellular ? (Brush)Brushes.White : BrushGray;
                _btnTransportVoip.FontWeight = !isCellular ? FontWeights.Bold : FontWeights.Normal;
            }
            // When switching to VoIP, jump to the Video Call page if a call is active
            // so the user sees the full-bleed stage. When going back to cellular, stay.
            Log("Transport: " + (isCellular ? "Cellular (GSM modem)" : "VoIP / LAN"), BrushGray);
        }

        // ---------- responsive layout ----------
        private void ApplyResponsiveLayout()
        {
            if (_contentHost == null) return;
            double w = _contentHost.ActualWidth;
            if (w <= 0) return;
            bool stacked = w < 640;
            if (stacked != _stacked)
            {
                _stacked = stacked;
                SetPageStacked(_dialerGrid, 320, stacked);
                SetPageStacked(_smsGrid, 300, stacked);
            }
            ApplyLogHeight();
        }

        private static void SetPageStacked(Grid g, double wideColWidth, bool stacked)
        {
            if (g == null || g.ColumnDefinitions.Count < 2) return;
            if (g.RowDefinitions.Count == 0)
            {
                g.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
                g.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            }
            if (g.Children.Count < 2) return;
            // Children are added in build order: 0 = left column, 1 = right column.
            FrameworkElement left = g.Children[0] as FrameworkElement;
            FrameworkElement right = g.Children[1] as FrameworkElement;
            if (left == null || right == null) return;
            if (stacked)
            {
                g.ColumnDefinitions[0].Width = new GridLength(1, GridUnitType.Star);
                g.ColumnDefinitions[1].Width = GridLength.Auto;
                Grid.SetRow(left, 0); Grid.SetColumn(left, 0);
                Grid.SetRow(right, 1); Grid.SetColumn(right, 0);
            }
            else
            {
                g.ColumnDefinitions[0].Width = new GridLength(wideColWidth);
                g.ColumnDefinitions[1].Width = new GridLength(1, GridUnitType.Star);
                Grid.SetRow(left, 0); Grid.SetColumn(left, 0);
                Grid.SetRow(right, 0); Grid.SetColumn(right, 1);
            }
        }

        // Log panel scales with the window (clamped so it never dominates
        // or disappears); the status-bar toggle collapses it completely.
        private void ApplyLogHeight()
        {
            if (_logRow == null) return;
            if (_logCollapsed)
            {
                _logRow.Height = new GridLength(0);
                return;
            }
            double h = ActualHeight * 0.20;
            if (h < 110) h = 110;
            if (h > 220) h = 220;
            _logRow.Height = new GridLength(h);
        }

        // One-shot after first layout: the page-card ScrollViewer must not need
        // to scroll for the dialer (regression: dialer overflowed the card and
        // forced a page scrollbar). Reports into the Live Log.
        private bool _dialerLayoutChecked;
        private void VerifyDialerLayout()
        {
            if (_dialerLayoutChecked || _dialerGrid == null) return;
            if (_dialerGrid.ActualHeight <= 0 || _dialerGrid.ActualWidth <= 0) return;
            _dialerLayoutChecked = true;
            try
            {
                System.Windows.DependencyObject v = _dialerGrid;
                System.Windows.Controls.ScrollViewer cardScroll = null;
                while (v != null)
                {
                    System.Windows.Controls.ScrollViewer sv = v as System.Windows.Controls.ScrollViewer;
                    if (sv != null && sv.ScrollableHeight > 0.5) { cardScroll = sv; break; }
                    v = System.Windows.Media.VisualTreeHelper.GetParent(v);
                }
                if (cardScroll == null)
                    Log("Dialer layout: OK (fits card, no page scroll).", BrushGray);
                else
                    Log("Dialer layout: OVERFLOW card by " + ((int)cardScroll.ScrollableHeight) + "px - trim left column.", BrushWarn);
            }
            catch (Exception ex) { Log("Dialer layout check: " + ex.Message, BrushGray); }
        }

        private void HighlightNav()
        {
            for (int i = 0; i < _navButtons.Count; i++)
            {
                if (i == _pageIndex)
                {
                    // Local values sit on top of the NavItem style; clearing on
                    // deselect falls back to the transparent style state.
                    _navButtons[i].Background = Theme.AccentSoft;
                    _navButtons[i].Foreground = Theme.Accent;
                    _navButtons[i].FontWeight = FontWeights.Bold;
                }
                else
                {
                    _navButtons[i].ClearValue(Button.BackgroundProperty);
                    _navButtons[i].ClearValue(Button.ForegroundProperty);
                    _navButtons[i].FontWeight = FontWeights.Normal;
                }
            }
        }

        private GroupBox _serialNotePanel;

        private void ToggleUssdPanels()
        {
            bool serial = _radioSerial.IsChecked == true;
            _panelMifi.Visibility = serial ? Visibility.Collapsed : Visibility.Visible;
            if (_serialNotePanel != null)
                _serialNotePanel.Visibility = serial ? Visibility.Visible : Visibility.Collapsed;
            if (_sbMethod != null)
                _sbMethod.Text = serial ? "USSD via Serial"
                    : "USSD via MiFi" + (_mifiProbe == "himi-spa" ? " (auto-fallback)" : "");
        }

        // ---------- Logging / status ----------
        // Hang diagnosis: append-only breadcrumb file (thread-tagged).
        // A few lines per minute at idle; invaluable when the UI stops pumping
        // (Log marks each line "ui" or "bg" by which thread reached it).
        public static void HangTrace(string s) { Hang.Trace(s); }

        // A FlowDocument that only grows makes every later log line re-measure
        // thousands of paragraphs on the UI thread; this app is meant to stay
        // awake for days, so the visible log is bounded and old lines are
        // dropped (the breadcrumb file keeps everything).
        private const int MaxLogLines = 300;

        public void Log(string text, Brush color)
        {
            HangTrace("LOG " + (Dispatcher.CheckAccess() ? "ui" : "bg") + ": " + text);
            if (_logBox == null) return;
            if (!Dispatcher.CheckAccess())
            {
                // Non-blocking: a blocking Invoke from the media/receive thread
                // would stall audio while any modal dialog is open (and can
                // deadlock against a join). BeginInvoke keeps FIFO ordering.
                try { Dispatcher.BeginInvoke((Action)delegate { Log(text, color); }); }
                catch { }
                return;
            }
            Paragraph p = new Paragraph { Margin = new Thickness(0, 1, 0, 1) };
            Run ts = new Run("[" + DateTime.Now.ToString("HH:mm:ss") + "] ");
            ts.Foreground = BrushGray;
            p.Inlines.Add(ts);
            Run r = new Run(text);
            r.Foreground = color ?? BrushFg;
            p.Inlines.Add(r);
            _logBox.Document.Blocks.Add(p);
            while (_logBox.Document.Blocks.Count > MaxLogLines)
            {
                Block oldest = _logBox.Document.Blocks.FirstBlock;
                if (oldest == null) break;
                _logBox.Document.Blocks.Remove(oldest);
            }
            // Scrolling a collapsed drawer is pure layout cost on the UI thread.
            if (!_logCollapsed && (_chkAutoScroll == null || _chkAutoScroll.IsChecked == true))
                _logBox.ScrollToEnd();
            // Unread badge: bump the counter when the log drawer is collapsed
            // and the message is not a routine gray trace
            if (_logCollapsed && color != BrushGray && _logBadge != null)
            {
                _logUnread++;
                _logBadge.Text = _logUnread > 9 ? "9+" : _logUnread.ToString();
                _logBadge.Visibility = Visibility.Visible;
            }
        }

        private void SetStatus(string text, Brush color)
        {
            if (!Dispatcher.CheckAccess())
            {
                // Never block a modem/receive thread on the dispatcher: that is
                // how a background thread freezes the whole UI during a burst of
                // AT traffic, and this app has to keep answering calls then.
                Dispatcher.BeginInvoke((Action)delegate { SetStatus(text, color); });
                return;
            }
            _status.Text = text;
            _status.Foreground = color;
            StartLiveDot(color == BrushGreen || (text != null && text.IndexOf("Connected", StringComparison.OrdinalIgnoreCase) >= 0));
        }

        private void SetSimSummary(string text)
        {
            if (!Dispatcher.CheckAccess())
            {
                Dispatcher.BeginInvoke((Action)delegate { SetSimSummary(text); });
                return;
            }
            if (_simSummary != null) _simSummary.Text = text;
            if (_simPillText != null) _simPillText.Text = text == "no SIM" ? "no SIM" :
                (text.Length > 34 ? text.Substring(0, 34) + "..." : text);
        }

        private void OnModemLine(string line)
        {
            Log("<< " + line, BrushGray);
        }

        private void OnModemLost(string reason)
        {
            Dispatcher.BeginInvoke(new Action(delegate
            {
                Log("Connection lost: " + reason, BrushError);
                SetStatus("Disconnected", BrushError);
                _call = CallState.Idle;
                UpdateCallUi();
                StopOpsTimers();
                UpdateConnectButton();
            }));
        }

        // ---------- Ports / connect ----------
        private void RefreshPorts()
        {
            var t = RefreshPortsAsync();
        }

        private async Task RefreshPortsAsync()
        {
            string savedChoice = _pendingPort;
            _pendingPort = null;

            string[] plain = SerialPort.GetPortNames();
            _comboPort.Items.Clear();
            foreach (string p in plain) _comboPort.Items.Add(p);
            if (_comboPort.Items.Count == 0)
            {
                Log("No COM ports found. Plug in the modem / MiFi via USB data cable.", BrushError);
                return;
            }
            _comboPort.SelectedIndex = 0;
            Log("Found " + plain.Length + " COM port(s): " + string.Join(", ", plain), BrushGray);

            if (_modem.IsOpen)
            {
                SelectPortItem(_modem.PortName);
                return;
            }

            int baud = SelectedBaud();
            bool doProbe = Environment.GetEnvironmentVariable("USSD_NO_PROBE") != "1";
            List<PortInfo> ports = null;
            string verified = null;
            try
            {
                PortScanResult res = await Task.Run(delegate
                {
                    PortScanResult r = new PortScanResult();
                    r.Ports = PortDetector.GetPortsWithNames();
                    List<PortInfo> ranked = PortDetector.RankCandidates(r.Ports, savedChoice);
                    if (doProbe && ranked.Count > 0)
                        r.VerifiedPort = PortDetector.ProbeWorkingPort(ranked, baud, null);
                    return r;
                });
                ports = res.Ports;
                verified = res.VerifiedPort;
            }
            catch (Exception ex)
            {
                Log("Port detection error: " + ex.Message, BrushWarn);
                return;
            }

            string previous = savedChoice;
            _comboPort.Items.Clear();
            foreach (PortInfo pi in ports)
                _comboPort.Items.Add(pi.Port + " - " + pi.Caption);
            List<PortInfo> ranked2 = PortDetector.RankCandidates(ports, previous);
            if (ranked2.Count == 0) return;
            string chosen = verified ?? ranked2[0].Port;
            SelectPortItem(chosen);
            PortInfo chosenInfo = null;
            foreach (PortInfo pi in ranked2) if (pi.Port == chosen) { chosenInfo = pi; break; }
            Log("Selected: " + chosen + (chosenInfo != null ? " - " + chosenInfo.Caption : ""), BrushAccent);
            if (verified != null) Log("AT-verified port: " + verified, BrushSuccess);
            if (_sbPort != null) _sbPort.Text = "port: " + chosen;

            if (verified != null && _chkAuto.IsChecked == true)
                await ConnectModemAsync(verified);
        }

        private class PortScanResult
        {
            public List<PortInfo> Ports;
            public string VerifiedPort;
        }

        private string _pendingPort = null;

        private void SelectPortItem(string port)
        {
            for (int i = 0; i < _comboPort.Items.Count; i++)
            {
                string item = _comboPort.Items[i] as string;
                if (item != null && (item == port || item.StartsWith(port + " ") || item.StartsWith(port + "-")))
                {
                    _comboPort.SelectedIndex = i;
                    return;
                }
            }
        }

        private string SelectedPort()
        {
            string item = _comboPort.SelectedItem as string;
            if (string.IsNullOrEmpty(item)) return null;
            int i = item.IndexOf(' ');
            return i > 0 ? item.Substring(0, i) : item;
        }

        private int SelectedBaud()
        {
            int b;
            if (_comboBaud.SelectedItem != null && int.TryParse(_comboBaud.SelectedItem.ToString(), out b)) return b;
            return 115200;
        }

        private async Task ToggleConnectAsync()
        {
            if (_modem.IsOpen)
            {
                DisconnectModem();
                return;
            }
            string port = SelectedPort();
            if (port == null) { Log("Select a COM port first.", BrushError); return; }
            await ConnectModemAsync(port);
        }

        private async Task ConnectModemAsync(string port)
        {
            if (_modem.IsOpen) return;
            int baud = SelectedBaud();
            SetStatus("Connecting " + port + "...", BrushWarn);
            Log("Connecting to " + port + " @ " + baud + " ...", BrushAccent);
            try
            {
                string[] initResults = await Task.Run(delegate
                {
                    _modem.Open(port, baud);
                    return _modem.Init();
                });
                foreach (string r in initResults) Log(r, BrushGray);
                bool ok = false;
                foreach (string r in initResults) if (r.Contains("OK")) { ok = true; break; }
                if (!ok)
                {
                    Log("Modem init did not return OK - disconnecting.", BrushError);
                    _modem.Close();
                    SetStatus("Connect failed", BrushError);
                    UpdateConnectButton();
                    return;
                }
                Log("Modem connected: " + port, BrushSuccess);
                SetStatus("Connected (" + port + ")", BrushSuccess);
                UpdateConnectButton();
                StartOpsTimers();
                await RefreshSimInfoAsync(true);
                await RefreshInboxAsync();
            }
            catch (Exception ex)
            {
                Log("Connect error: " + ex.Message, BrushError);
                SetStatus("Connect failed", BrushError);
                try { _modem.Close(); } catch { }
                UpdateConnectButton();
            }
        }

        private void DisconnectModem()
        {
            StopOpsTimers();
            try { _modem.Close(); } catch { }
            _call = CallState.Idle;
            UpdateCallUi();
            SetStatus("Disconnected", BrushError);
            _sigText.Text = "signal --";
            SetSimSummary("no SIM");
            _sbPort.Text = "port: -";
            _sbCarrier.Text = "carrier: -";
            UpdateConnectButton();
            Log("Disconnected.", BrushGray);
        }

        private void UpdateConnectButton()
        {
            bool open = _modem.IsOpen;
            _btnConnect.Content = open ? "Disconnect" : "Connect";
            _btnConnect.Background = open ? BrushRed : BrushGreen;
        }

        // ---------- Timers ----------
        private void WireTimers()
        {
            _tickTimer = new DispatcherTimer();
            _tickTimer.Interval = TimeSpan.FromSeconds(1);
            _tickTimer.Tick += delegate
            {
                if (_call == CallState.Active)
                {
                    int sec = (int)(DateTime.Now - _callStart).TotalSeconds;
                    _callTimerText.Text = (sec / 60).ToString("00") + ":" + (sec % 60).ToString("00");
                }
                // VoIP call clock (drives the in-call overlay timer)
                if (_voip != null && _voip.InCall)
                {
                    if (_voipStart == DateTime.MinValue) _voipStart = DateTime.Now;
                    int sec = (int)(DateTime.Now - _voipStart).TotalSeconds;
                    string mmss = (sec / 60).ToString("00") + ":" + (sec % 60).ToString("00");
                    if (_ovTimer != null) _ovTimer.Text = mmss;
                    if (_call != CallState.Active && _callTimerText != null) _callTimerText.Text = mmss;
                    // Update hub voice call timer if open
                    if (_hubCallTimer != null) _hubCallTimer.Text = mmss;
                }
                else if (_voipStart != DateTime.MinValue)
                {
                    _voipStart = DateTime.MinValue;
                    if (_ovTimer != null) _ovTimer.Text = "00:00";
                    if (_hubCallTimer != null) _hubCallTimer.Text = "00:00";
                }
                // Network quality indicator — update every 5 seconds
                if (_tickCount % 5 == 0) UpdateNetworkQualityIndicator();
                _tickCount++;
                // Update nav badges (unread counts)
                UpdateNavBadges();
            };
            // The UI clock must run even with no modem connected (VoIP-only
            // machines) - otherwise the in-call timer never ticks.
            _tickTimer.Start();

            // UI-thread watchdog: a background thread watches the heartbeat;
            // if the dispatcher stalls past 20 s the hang trace records it so
            // window-freeze reports point at the frozen phase.
            DateTime[] beat = new DateTime[] { DateTime.Now };
            int[] beatN = new int[] { 0 };
            DispatcherTimer beatTimer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(1) };
            beatTimer.Tick += delegate
            {
                beat[0] = DateTime.Now;
                int n = ++beatN[0];
                if (n % 30 == 0) Hang.Trace("UI beat #" + n);
            };
            beatTimer.Start();
            Thread uiWatch = new Thread((ThreadStart)delegate
            {
                while (true)
                {
                    Thread.Sleep(3000);
                    double stall = (DateTime.Now - beat[0]).TotalSeconds;
                    if (stall > 20)
                    {
                        Hang.Trace("UI THREAD STALLED: no heartbeat for " + (int)stall + " s");
                        break;
                    }
                }
            });
            uiWatch.IsBackground = true;
            uiWatch.Start();

            _opsTimer = new DispatcherTimer();
            _opsTimer.Interval = TimeSpan.FromSeconds(10);
            _opsTimer.Tick += delegate { OpsTick(); };

            _clccTimer = new DispatcherTimer();
            _clccTimer.Interval = TimeSpan.FromSeconds(2);
            _clccTimer.Tick += delegate { ClccTick(); };
        }

        private void StartOpsTimers()
        {
            _opsTimer.Start();
        }

        private void StopOpsTimers()
        {
            _opsTimer.Stop();
            _clccTimer.Stop();
        }

        private void OpsTick()
        {
            if (!_modem.IsOpen || _opsRunning) return;
            _opsCount++;
            if (_opsCount % 12 == 0)
            {
                var t = RefreshSimInfoAsync(true);
            }
            else
            {
                var t2 = SignalTickAsync();
            }
        }

        private async Task SignalTickAsync()
        {
            if (_opsRunning) return;
            _opsRunning = true;
            try
            {
                string rssiLine = await Task.Run(delegate
                {
                    string[] r = _modem.SendCommand("AT+CSQ", ModemService.OkTerm, 8000);
                    return string.Join(" | ", r);
                });
                int rssi = ParseRssi(rssiLine);
                UpdateSignalUi(rssi);
            }
            catch { }
            finally { _opsRunning = false; }
        }

        private static int ParseRssi(string text)
        {
            Match m = Regex.Match(text, @"\+CSQ:\s*(\d+)");
            if (m.Success)
            {
                int v;
                if (int.TryParse(m.Groups[1].Value, out v)) return v;
            }
            return -1;
        }

        private static string SignalBars(int rssi)
        {
            if (rssi < 0 || rssi >= 99) return "--";
            if (rssi >= 20) return "?_?ï¿½";
            if (rssi >= 15) return "?_?";
            if (rssi >= 10) return "?_";
            if (rssi >= 1) return "?";
            return "no signal";
        }

        private void UpdateSignalUi(int rssi)
        {
            string bars = SignalBars(rssi);
            string dbm = (rssi >= 0 && rssi < 99) ? (" (" + (-113 + 2 * rssi) + " dBm)") : "";
            _sigText.Text = bars + dbm;
            if (_valSig != null)
                _valSig.Text = (rssi < 0 || rssi >= 99) ? "unknown" : (bars + "  RSSI " + rssi + dbm);
        }

        // ---------- Dialer ----------
        private void KeyPress(string digit)
        {
            if (_call == CallState.Active)
            {
                _dtmfEcho.Visibility = Visibility.Visible;
                _dtmfEcho.Text += digit;
                string d = digit;
                var t = Task.Run(delegate
                {
                    try { _modem.SendCommand("AT+VTS=\"" + d + "\"", ModemService.OkTerm, 5000); }
                    catch (Exception ex) { Log("DTMF error: " + ex.Message, BrushWarn); }
                });
                return;
            }
            if (_voip != null && _voip.InCall)
            {
                // VoIP call: hear the tone locally and deliver the digit to the
                // peer over the signaling channel (which replays it too).
                ToneSynth.PlayDtmf(digit);
                string d2 = digit;
                var t2 = Task.Run(delegate { try { _voip.SendDtmf(d2); } catch { } });
                return;
            }
            _txtNumber.Text += digit;
        }

        private void Backspace()
        {
            string t = _txtNumber.Text;
            if (t.Length > 0) _txtNumber.Text = t.Substring(0, t.Length - 1);
        }

        private static string SanitizeNumber(string num)
        {
            if (num == null) return "";
            return NormalizeNumber(num);
        }

        // Accepts any common format and returns a dialable number:
        //   "024 444 4444" -> "233244444444"   (local 0-prefix -> 233)
        //   "+23324444444" -> "23324444444"    (+ dropped: ATD wants no +)
        //   "00233..."     -> "233..."
        //   "*124#", "100"  -> untouched (USSD / short codes)
        public static string NormalizeNumber(string num)
        {
            if (num == null) return "";
            string s = Regex.Replace(num.Trim(), @"[\s\-()\.\u00A0]", "");
            if (s.Length == 0) return "";
            if (s[0] == '*' || s[0] == '#' || s[0] == '+')
            {
                if (s[0] == '+')
                {
                    s = s.Substring(1);
                    if (s.StartsWith("00")) s = s.Substring(2);
                }
                return s;
            }
            if (s.StartsWith("00")) s = s.Substring(2);
            if (s.StartsWith("233") && s.Length >= 12) return s;
            // Ghana mobile: 0 + 9 digits
            if (s.Length == 10 && s[0] == '0') return "233" + s.Substring(1);
            // generic local: 0 + subscriber digits of any length
            if (s.Length > 4 && s[0] == '0') return "233" + s.Substring(1);
            return s;
        }

        // One decision, from live state, about how a number should leave this
        // app. Fed by the cached SIM snapshot so dialling never waits on an AT
        // query, and shared by every place a call can be started.
        private EgressDecision BuildRoute(string number, bool wantVideo)
        {
            EgressRequest r = new EgressRequest();
            string norm = AppNum.NormalizeForCall(number);
            r.Number = norm;
            r.AppNumber = AppNum.IsApp(norm);
            r.Pref = _dialerTransport == "cellular" ? TransportPref.PreferCellular
                     : _dialerTransport == "voip" ? TransportPref.PreferApp
                     : TransportPref.Auto;
            r.RelayReady = _voip != null && _voip.RelayReady;
            try
            {
                if (_voip != null && _voip.Peers != null)
                    foreach (VoipPeer p in _voip.Peers)
                        if (p != null && (p.Status ?? "").StartsWith("\u25CF")) { r.LanPeerKnown = true; break; }
            }
            catch { }
            if (!r.AppNumber && _voip != null)
            {
                try { r.PeerOnMesh = _voip.IsRegisteredNumber(norm); } catch { }
            }
            r.ModemOpen = _modem != null && _modem.IsOpen;
            SimSnapshot s = _simSnap;
            if (s != null)
            {
                r.SimPresent = s.SimPresent;
                r.SimReady = s.PinReady;
                r.NetworkRegistered = s.Reg != null && s.Reg.StartsWith("Registered");
                r.Rssi = s.Rssi;
            }
            r.GatewayConfigured = _cfg != null && _cfg.gateway_enabled;
            r.GatewayName = _cfg != null ? _cfg.gateway_name : "";
            return CallRouter.Decide(r);
        }

        private async Task StartCallAsync()
        {
            string rawNum = _txtNumber.Text;
            string num = SanitizeNumber(rawNum);
            // ── APP CALLER-ID ROUTING ─────────────────────────────────────
            // Any 700-XXXXXXX number is an app virtual number. Calls to these
            // NEVER require a SIM card or modem — they route over the relay
            // (internet/WiFi/LTE) directly between app instances. This works
            // on any network type: WiFi, cellular (any carrier), or even
            // metered data, as long as the relay can be reached.
            if (AppNum.IsApp(num))
            {
                if (_voip == null)
                {
                    Log("App call: VoIP service not running.", BrushError);
                    return;
                }
                bool isVideo = _dialerTransport == "voip";
                Log("App call ➜ " + AppNum.Format(num) + " (no modem required — routing over relay/internet)", BrushAccent);
                StartVoipCallByNumber(num, isVideo);
                // Switch hub workspace to voice/video view
                if (isVideo) HubShowWorkspace("video");
                else { HubShowWorkspace("voice"); if (_hubCallState != null) _hubCallState.Text = "Calling " + AppNum.Format(num) + "..."; }
                return;
            }

            // ── RELAY DIRECTORY CHECK ─────────────────────────────────────
            // Non-700 numbers that are in the relay directory are also VoIP.
            if (num.Length >= 3 && _voip != null && _voip.IsRegisteredNumber(num))
            {
                StartVoipCallByNumber(num, false);
                return;
            }

            // Everything past this point is decided in one place, so the Dialer,
            // the chat hub and the contacts list cannot drift into three
            // different answers for the same number.
            EgressDecision route = BuildRoute(num, _dialerTransport == "voip");
            if (route.Path == EgressPath.AppMesh)
            {
                Log("Mesh call \u279C " + num + " - " + route.Why, BrushAccent);
                StartVoipCallByNumber(num, _dialerTransport == "voip");
                return;
            }
            if (route.Path == EgressPath.Gateway)
            {
                // The seam exists so a bridge can be added without reworking
                // routing; there is no built-in adapter in this build.
                Log("Would use " + route.Why + " - but no gateway adapter is implemented yet. " +
                    "See IEgressGateway in CallRouter.cs.", BrushWarn);
                return;
            }
            if (route.Path == EgressPath.None)
            {
                Log("Cannot dial: " + route.Why, BrushError);
                if (!string.IsNullOrEmpty(route.Fix)) Log("To fix it: " + route.Fix, BrushWarn);
                return;
            }
            // EgressPath.Cellular falls through to the modem dial below.

            // ── GSM MODEM CALL ────────────────────────────────────────────
            if (!_modem.IsOpen) { Log("Connect the modem first (or dial a 700-XXXXXXX app number for modem-free calls).", BrushError); return; }
            if (_call == CallState.Ringing) { await AnswerCallAsync(); return; }
            if (_call != CallState.Idle) { Log("A call is already in progress.", BrushWarn); return; }
            if (num.Length < 3) { Log("Enter a valid number.", BrushWarn); return; }
            _peer = num;
            _call = CallState.Dialing;
            _callDir = "out";
            _callAnswered = false;
            _callStart = DateTime.MinValue;
            if (_dtmfEcho != null) _dtmfEcho.Text = "";
            UpdateCallUi();
            if (num != rawNum.Trim())
                Log("Normalized \"" + rawNum.Trim() + "\" -> " + num, BrushGray);
            Log("Dialing " + num + " ...", BrushAccent);
            await Task.Run(delegate
            {
                try
                {
                    string[] r = _modem.SendCommand("ATD" + num + ";",
                        "^(OK|ERROR|BUSY|NO CARRIER|NO ANSWER|\\+CME ERROR)", 45000);
                    string joined = string.Join(" | ", r);
                    bool ok = false;
                    foreach (string l in r) if (Regex.IsMatch(l, @"(^|\s)OK(\s|$)")) ok = true;
                    Dispatcher.BeginInvoke(new Action(delegate
                    {
                        if (ok && (_call == CallState.Dialing))
                        {
                            _call = CallState.Active;
                            _callStart = DateTime.Now;
                            _clccTimer.Start();
                            UpdateCallUi();
                            Log("Call active.", BrushSuccess);
                        }
                        else if (_call == CallState.Dialing)
                        {
                            _call = CallState.Idle;
                            _clccTimer.Stop();
                            UpdateCallUi();
                            Log("Call failed: " + joined, BrushError);
                        }
                    }));
                }
                catch (Exception ex)
                {
                    Dispatcher.BeginInvoke(new Action(delegate
                    {
                        _call = CallState.Idle;
                        _clccTimer.Stop();
                        UpdateCallUi();
                        Log("Call error: " + ex.Message, BrushError);
                    }));
                }
            });
        }

        private async Task EndCallAsync()
        {
            if (!_modem.IsOpen) { _call = CallState.Idle; UpdateCallUi(); return; }
            Log("Ending call...", BrushAccent);
            await Task.Run(delegate
            {
                try { _modem.SendCommand("ATH", ModemService.OkTerm, 8000); }
                catch (Exception ex) { Log("End call error: " + ex.Message, BrushWarn); }
            });
            _call = CallState.Idle;
            _clccTimer.Stop();
            UpdateCallUi();
        }

        private async Task AnswerCallAsync()
        {
            if (!_modem.IsOpen) return;
            Log("Answering...", BrushAccent);
            await Task.Run(delegate
            {
                try { _modem.SendCommand("ATA", ModemService.OkTerm, 15000); }
                catch (Exception ex) { Log("Answer error: " + ex.Message, BrushWarn); }
            });
            _call = CallState.Active;
            _callStart = DateTime.Now;
            _callAnswered = true;
            _clccTimer.Start();
            UpdateCallUi();
        }

        private void ClccTick()
        {
            if (!_modem.IsOpen || _clccRunning) return;
            if (_call != CallState.Active && _call != CallState.Dialing) return;
            _clccRunning = true;
            var t = Task.Run(delegate
            {
                try
                {
                    string[] r = _modem.SendCommand("AT+CLCC", ModemService.OkTerm, 6000);
                    string stat = null, peer = null;
                    foreach (string line in r)
                    {
                        Match m = Regex.Match(line, "\\+CLCC:\\s*\\d+,\\d+,(\\d+),\\d+,[^,]*,\"([^\"]*)\"");
                        if (m.Success)
                        {
                            stat = m.Groups[1].Value;
                            peer = m.Groups[2].Value;
                        }
                    }
                    bool hasCall = stat != null;
                    Dispatcher.BeginInvoke(new Action(delegate
                    {
                        if (!hasCall && (_call == CallState.Active || _call == CallState.Dialing))
                        {
                            _call = CallState.Idle;
                            _clccTimer.Stop();
                            UpdateCallUi();
                            Log("Call ended.", BrushWarn);
                        }
                        else if (hasCall)
                        {
                            string s = stat;
                            if (s == "0" || s == "1")
                            {
                                if (_call != CallState.Active)
                                {
                                    _call = CallState.Active;
                                    _callStart = DateTime.Now;
                                    _callAnswered = true;
                                    UpdateCallUi();
                                    Log("Call active (CLCC).", BrushSuccess);
                                }
                            }
                            else if (s == "2" || s == "3")
                            {
                                if (_call == CallState.Idle)
                                {
                                    _call = CallState.Dialing;
                                    UpdateCallUi();
                                }
                            }
                            if (!string.IsNullOrEmpty(peer) && _peer != peer) { _peer = peer; UpdateCallUi(); }
                        }
                    }));
                }
                catch { }
                finally { _clccRunning = false; }
            });
        }

        private void UpdateCallUi()
        {
            // Call history: any transition out of a live call into Idle is a
            // completed SIM call - record it once (covers END, remote hangup,
            // CLCC loss, NO CARRIER and failed dial attempts).
            if (_call == CallState.Idle && _callPrev != CallState.Idle)
            {
                int secs = 0;
                if (_callPrev == CallState.Active && _callStart != DateTime.MinValue)
                    secs = (int)(DateTime.Now - _callStart).TotalSeconds;
                string dir = _callDir;
                if (dir == "in" && !_callAnswered) dir = "missed";
                AddCallHistory(_peer, dir, "sim", secs);
                _callStart = DateTime.MinValue;
                _callAnswered = false;
            }
            _callPrev = _call;
            if (_dtmfEcho != null && _call != CallState.Active)
            {
                _dtmfEcho.Text = "";
                _dtmfEcho.Visibility = Visibility.Collapsed;
            }
            switch (_call)
            {
                case CallState.Idle:
                    _callStateText.Text = "Ready";
                    _callStateText.Foreground = BrushGray;
                    if (_callTimerText != null) _callTimerText.Text = "";
                    _btnAnswer.Visibility = Visibility.Collapsed;
                    _btnDecline.Visibility = Visibility.Collapsed;
                    StopCallBreath();
                    CloseOverlayKeypad();
                    break;
                case CallState.Dialing:
                    _callStateText.Text = "Dialing...";
                    _callStateText.Foreground = BrushWarn;
                    _clipText.Text = _peer;
                    StartCallBreath();
                    break;
                case CallState.Ringing:
                    _callStateText.Text = "Incoming call";
                    _callStateText.Foreground = BrushAccent;
                    _btnAnswer.Visibility = Visibility.Visible;
                    _btnDecline.Visibility = Visibility.Visible;
                    StartCallBreath();
                    break;
                case CallState.Active:
                    _callStateText.Text = "In call";
                    _callStateText.Foreground = BrushSuccess;
                    _btnAnswer.Visibility = Visibility.Collapsed;
                    _btnDecline.Visibility = Visibility.Collapsed;
                    _clipText.Text = _peer;
                    StartCallBreath();
                    break;
            }
            if (_call == CallState.Idle && string.IsNullOrEmpty(_peer))
                _clipText.Text = "";
            UpdateCallOverlay();
        }

        // Close the overlay keypad if it is open.
        private void CloseOverlayKeypad()
        {
            if (_callOverlay != null && _ovKeypadOpen) ToggleOverlayKeypad();
        }

        private void OnModemUrc(string line)
        {
            if (line.StartsWith("RING"))
            {
                Dispatcher.BeginInvoke(new Action(delegate
                {
                    if (_call == CallState.Idle)
                    {
                        _call = CallState.Ringing;
                        _peer = "";
                        _callDir = "in";
                        _callAnswered = false;
                        _callStart = DateTime.MinValue;
                        UpdateCallUi();
                    }
                    Log("Incoming call (RING)", BrushAccent);
                }));
                return;
            }
            if (line.StartsWith("+CLIP:"))
            {
                Match m = Regex.Match(line, "\"([^\"]*)\"");
                if (m.Success)
                {
                    string caller = m.Groups[1].Value;
                    Dispatcher.BeginInvoke(new Action(delegate
                    {
                        _peer = caller;
                        _clipText.Text = "Caller ID: " + caller;
                        Log("Caller ID: " + caller, BrushAccent);
                        UpdateCallUi();
                    }));
                }
                return;
            }
            if (Regex.IsMatch(line, "^(NO CARRIER|NO ANSWER|BUSY)", RegexOptions.IgnoreCase))
            {
                Dispatcher.BeginInvoke(new Action(delegate
                {
                    if (_call != CallState.Idle)
                    {
                        _call = CallState.Idle;
                        _clccTimer.Stop();
                        UpdateCallUi();
                        Log("Call ended: " + line, BrushWarn);
                    }
                }));
                return;
            }
            if (line.StartsWith("+CMTI:"))
            {
                Match m = Regex.Match(line, "\\+CMTI:\\s*\"[^\"]*\"\\s*,\\s*(\\d+)");
                if (m.Success)
                {
                    int idx;
                    if (int.TryParse(m.Groups[1].Value, out idx))
                    {
                        Log("New SMS at index " + idx + " - reading...", BrushAccent);
                        var t = ReadSmsAtAsync(idx);
                    }
                }
                return;
            }
        }

        // ---------- Contacts ----------
        private void LoadContacts()
        {
            _contacts.Clear();
            try
            {
                string path = AppConfig.ContactsPath;
                if (File.Exists(path))
                {
                    foreach (string line in File.ReadAllLines(path))
                    {
                        string[] parts = line.Split('|');
                        if (parts.Length >= 2)
                            _contacts.Add(new Contact
                            {
                                Name = parts[0],
                                Number = parts[1],
                                Source = parts.Length >= 3 ? parts[2] : "Device",
                                Fav = parts.Length >= 4 && parts[3] == "1"
                            });
                    }
                }
            }
            catch (Exception ex) { Log("Contacts load error: " + ex.Message, BrushWarn); }
        }

        private void SaveContacts()
        {
            try
            {
                List<string> lines = new List<string>();
                foreach (Contact c in _contacts)
                    lines.Add(c.Name.Replace("|", " ") + "|" + c.Number + "|" + c.Source + "|" + (c.Fav ? "1" : "0"));
                File.WriteAllLines(AppConfig.ContactsPath, lines.ToArray());
            }
            catch (Exception ex) { Log("Contacts save error: " + ex.Message, BrushWarn); }
        }

        // ---------- Call history (Recents) ----------
        private void LoadCallHistory()
        {
            _callHistory.Clear();
            try
            {
                string path = AppConfig.HistoryPath;
                if (File.Exists(path))
                {
                    foreach (string line in File.ReadAllLines(path))
                    {
                        string[] parts = line.Split('|');
                        if (parts.Length >= 5)
                        {
                            CallRec r = new CallRec();
                            r.Number = parts[0];
                            r.Dir = parts[1];
                            r.Kind = parts[2];
                            r.When = parts[3];
                            int secs;
                            r.Secs = int.TryParse(parts[4], out secs) ? secs : 0;
                            _callHistory.Add(r);
                        }
                    }
                }
            }
            catch (Exception ex) { Log("History load error: " + ex.Message, BrushWarn); }
        }

        private void SaveCallHistory()
        {
            try
            {
                List<string> lines = new List<string>();
                foreach (CallRec r in _callHistory)
                    lines.Add(r.Number + "|" + r.Dir + "|" + r.Kind + "|" + r.When + "|" + r.Secs);
                File.WriteAllLines(AppConfig.HistoryPath, lines.ToArray());
            }
            catch (Exception ex) { Log("History save error: " + ex.Message, BrushWarn); }
        }

        // Append one entry (newest first), cap the file, persist, refresh UI.
        private void AddCallHistory(string number, string dir, string kind, int secs)
        {
            HangTrace("AddCallHistory " + number + " " + dir + " " + kind + " " + secs);
            if (string.IsNullOrEmpty(number)) number = "(unknown)";
            CallRec r = new CallRec();
            r.Number = number;
            r.Dir = dir;
            r.Kind = kind;
            r.Secs = secs < 0 ? 0 : secs;
            r.When = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss");
            _callHistory.Insert(0, r);
            while (_callHistory.Count > 100) _callHistory.RemoveAt(_callHistory.Count - 1);
            SaveCallHistory();
            RefreshRecentsView();
        }

        // 42 -> "0:42", 195 -> "3:15", 3725 -> "1:02:05"
        private static string FormatDur(int secs)
        {
            if (secs < 0) secs = 0;
            if (secs < 60) return "0:" + (secs < 10 ? "0" : "") + secs;
            if (secs < 3600)
            {
                int m = secs / 60, s = secs % 60;
                return m + ":" + (s < 10 ? "0" : "") + s;
            }
            int h = secs / 3600, mm = (secs % 3600) / 60, ss2 = secs % 60;
            return h + ":" + (mm < 10 ? "0" : "") + mm + ":" + (ss2 < 10 ? "0" : "") + ss2;
        }

        private void RefreshRecentsView()
        {
            if (_recentsPanel == null) return;
            _recentsPanel.Children.Clear();
            if (_recentsEmpty != null)
                _recentsEmpty.Visibility = _callHistory.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
            foreach (CallRec r in _callHistory)
            {
                string glyph, kind;
                Brush gb;
                if (r.Dir == "missed") { glyph = "\u2716"; gb = BrushRed; kind = "Missed"; }
                else if (r.Dir == "in") { glyph = "\u25BC"; gb = BrushGreen; kind = "Incoming"; }
                else { glyph = "\u25B2"; gb = BrushAccent; kind = "Placed"; }
                string kindName = r.Kind == "sim" ? "SIM" : (r.Kind == "video" ? "Video" : "VoIP");
                string time = r.When.Length >= 16 ? r.When.Substring(5, 11) : r.When;
                string meta = kind + " \u2022 " + kindName + " \u2022 " + time + " \u2022 " + FormatDur(r.Secs);

                Button row = new Button
                {
                    Cursor = Cursors.Hand,
                    HorizontalContentAlignment = HorizontalAlignment.Stretch,
                    Margin = new Thickness(0, 0, 0, 4),
                    Padding = new Thickness(10, 6, 10, 6),
                    ToolTip = "Click to dial " + r.Number
                };
                Grid rg = new Grid();
                rg.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
                rg.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
                TextBlock g = new TextBlock
                {
                    Text = glyph,
                    Foreground = gb,
                    FontSize = 14,
                    VerticalAlignment = VerticalAlignment.Center,
                    Margin = new Thickness(0, 0, 10, 0)
                };
                Grid.SetColumn(g, 0);
                rg.Children.Add(g);
                StackPanel lp = new StackPanel();
                lp.Children.Add(new TextBlock
                {
                    Text = r.Number,
                    Foreground = BrushFg,
                    FontWeight = FontWeights.SemiBold,
                    FontSize = 14
                });
                lp.Children.Add(new TextBlock
                {
                    Text = meta,
                    Foreground = BrushGray,
                    FontSize = 11,
                    Margin = new Thickness(0, 2, 0, 0)
                });
                Grid.SetColumn(lp, 1);
                rg.Children.Add(lp);
                row.Content = rg;
                string num = r.Number;
                row.Click += delegate
                {
                    _txtNumber.Text = num;
                    SelectDialerPane(true);
                    _txtNumber.Focus();
                };
                _recentsPanel.Children.Add(row);
            }
        }

        // Keypad <-> Recents pane switch with segmented highlight.
        private void SelectDialerPane(bool keypad)
        {
            if (_keypadPane == null || _recentsPane == null) return;
            _keypadPane.Visibility = keypad ? Visibility.Visible : Visibility.Collapsed;
            _recentsPane.Visibility = keypad ? Visibility.Collapsed : Visibility.Visible;
            if (_tabKeypad != null)
            {
                _tabKeypad.Background = keypad ? Theme.AccentSoft : BrushPanel;
                _tabKeypad.Foreground = keypad ? BrushAccent : BrushGray;
                _tabKeypad.BorderBrush = keypad ? BrushAccent : BrushBorder;
            }
            if (_tabRecents != null)
            {
                _tabRecents.Background = !keypad ? Theme.AccentSoft : BrushPanel;
                _tabRecents.Foreground = !keypad ? BrushAccent : BrushGray;
                _tabRecents.BorderBrush = !keypad ? BrushAccent : BrushBorder;
            }
        }

        private void RefreshContactsView()
        {
            if (_lvContacts == null) return;
            _peerSig = null;   // contact names feed the peer list - force a rebuild
            string keep = null;
            Contact sel = _lvContacts.SelectedItem as Contact;
            if (sel != null) keep = sel.Number;
            _lvContacts.Items.Clear();
            List<Contact> list = new List<Contact>();
            foreach (Contact c in _contacts)
            {
                if (_contactFilter == "Favorites" && !c.Fav) continue;
                if (_contactFilter == "SIM" && c.Source != "SIM") continue;
                if (_contactFilter == "Device" && c.Source == "SIM") continue;
                list.Add(c);
            }
            // favorites first, then alphabetical
            list.Sort(delegate(Contact a, Contact b)
            {
                if (a.Fav != b.Fav) return a.Fav ? -1 : 1;
                return string.Compare(a.Name, b.Name, StringComparison.OrdinalIgnoreCase);
            });
            foreach (Contact c in list) _lvContacts.Items.Add(c);
            if (keep != null)
                foreach (object o in _lvContacts.Items)
                {
                    Contact c = o as Contact;
                    if (c != null && c.Number == keep) { _lvContacts.SelectedItem = o; break; }
                }
            UpdateContactDetail();
        }

        // Keep the right-hand detail card in sync with the selection.
        private void UpdateContactDetail()
        {
            if (_ctDetailTitle == null) return;
            Contact c = _lvContacts != null ? _lvContacts.SelectedItem as Contact : null;
            bool has = c != null;
            _ctDetailTitle.Text = has ? c.Name : "No contact selected";
            _ctDetailNum.Text = has ? c.Number : "";
            _ctDetailSrc.Text = has ? ("Saved from " + c.Source) : "";
            _ctDetailFav.Text = has ? (c.Fav ? "\u2605 Favorite" : "\u2606 Not a favorite") : "";
            if (_ctBtnFav != null)
            {
                _ctBtnFav.Content = has && c.Fav ? "\u2605 Unfavorite" : "\u2606 Favorite";
                _ctBtnFav.IsEnabled = has;
            }
            if (_ctBtnCall != null) _ctBtnCall.IsEnabled = has;
            if (_ctBtnVideo != null) _ctBtnVideo.IsEnabled = has;
            if (_ctBtnSms != null) _ctBtnSms.IsEnabled = has;
            if (_ctBtnDel != null) _ctBtnDel.IsEnabled = has;
        }

        private void ToggleSelectedFavorite()
        {
            Contact c = _lvContacts != null ? _lvContacts.SelectedItem as Contact : null;
            if (c == null) { Log("Select a contact.", BrushWarn); return; }
            c.Fav = !c.Fav;
            SaveContacts();
            RefreshContactsView();
            Log(c.Name + (c.Fav ? " added to favorites" : " removed from favorites"), BrushSuccess);
        }

        // Video-call a contact that holds a registered internet number.
        private void VideoSelectedContact()
        {
            Contact c = _lvContacts != null ? _lvContacts.SelectedItem as Contact : null;
            if (c == null) { Log("Select a contact.", BrushWarn); return; }
            if (_voip != null && (_voip.IsRegisteredNumber(c.Number) || AppNum.IsApp(AppNum.NormalizeForCall(c.Number))))
            {
                GetTabByHeader("Dialer");
                StartVoipCallByNumber(c.Number, true);
                return;
            }
            Log("VoIP video needs an internet number - pick a peer on the Dialer instead.", BrushWarn);
        }

        private void AddContactFromFields()
        {
            string name = _txtCName.Text.Trim();
            string num = SanitizeNumber(_txtCNum.Text);
            if (name.Length == 0 || num.Length == 0) { Log("Enter name and number.", BrushWarn); return; }
            foreach (Contact c in _contacts)
                if (c.Number == num) { Log("Contact already exists: " + num, BrushWarn); return; }
            _contacts.Add(new Contact { Name = name, Number = num, Source = "Device" });
            SaveContacts();
            RefreshContactsView();
            _txtCName.Text = "";
            _txtCNum.Text = "";
            Log("Contact added: " + name + " (" + num + ")", BrushSuccess);
        }

        private void DeleteSelectedContact()
        {
            Contact c = _lvContacts.SelectedItem as Contact;
            if (c == null) { Log("Select a contact.", BrushWarn); return; }
            _contacts.Remove(c);
            SaveContacts();
            RefreshContactsView();
            Log("Contact deleted: " + c.Name, BrushGray);
        }

        private async Task ImportSimContactsAsync()
        {
            if (!_modem.IsOpen) { Log("Connect the modem first.", BrushError); return; }
            Log("Importing SIM phonebook ...", BrushAccent);
            await Task.Run(delegate
            {
                try
                {
                    string[] r = _modem.SendCommand("AT+CPBR=1,250", ModemService.OkTerm, 30000);
                    int count = 0;
                    List<Contact> imported = new List<Contact>();
                    foreach (string line in r)
                    {
                        Match m = Regex.Match(line, "\\+CPBR:\\s*\\d+,\\s*\"([^\"]*)\"\\s*,\\d+,\\s*\"([^\"]*)\"");
                        if (m.Success)
                        {
                            string num = m.Groups[1].Value;
                            string name = m.Groups[2].Value;
                            if (num.Length > 0)
                            {
                                imported.Add(new Contact { Name = name, Number = num, Source = "SIM" });
                                count++;
                            }
                        }
                    }
                    Dispatcher.BeginInvoke(new Action(delegate
                    {
                        int added = 0;
                        foreach (Contact ic in imported)
                        {
                            bool exists = false;
                            foreach (Contact c in _contacts) if (c.Number == ic.Number) { exists = true; break; }
                            if (!exists) { _contacts.Add(ic); added++; }
                        }
                        SaveContacts();
                        RefreshContactsView();
                        Log("SIM phonebook: " + count + " entries, " + added + " added.", BrushSuccess);
                    }));
                }
                catch (Exception ex)
                {
                    Log("SIM import error: " + ex.Message, BrushError);
                }
            });
        }

        private async Task DialSelectedContactAsync()
        {
            Contact c = _lvContacts.SelectedItem as Contact;
            if (c == null) { Log("Select a contact.", BrushWarn); return; }
            _txtNumber.Text = c.Number;
            GetTabByHeader("Dialer");
            await StartCallAsync();
        }

        private void SmsSelectedContact()
        {
            Contact c = _lvContacts.SelectedItem as Contact;
            if (c == null) { Log("Select a contact.", BrushWarn); return; }
            _txtSmsTo.Text = c.Number;
            SelectTab(3); // SMS page (Video Call page sits at index 2)
        }

        private void CallSelectedSmsSender()
        {
            SmsMessage m = _lvInbox.SelectedItem as SmsMessage;
            if (m == null) { Log("Select a message.", BrushWarn); return; }
            _txtNumber.Text = SanitizeNumber(m.From);
            SelectTab(0);
        }

        private void SelectTab(int index)
        {
            ShowPage(index);
        }

        private FrameworkElement GetTabByHeader(string header)
        {
            for (int i = 0; i < _pageNames.Count; i++)
            {
                if (string.Equals(_pageNames[i], header, StringComparison.OrdinalIgnoreCase) ||
                    (_pageNames[i] != null && _pageNames[i].EndsWith(header, StringComparison.OrdinalIgnoreCase)))
                {
                    ShowPage(i);
                    return _pages[i];
                }
            }
            return null;
        }

        // ---------- SMS ----------
        private async Task SendSmsAsync()
        {
            if (!_modem.IsOpen) { Log("Connect the modem first.", BrushError); return; }
            string to = SanitizeNumber(_txtSmsTo.Text);
            string body = _txtSmsBody.Text;
            if (to.Length < 3) { Log("Enter a recipient number.", BrushWarn); return; }
            if (body.Trim().Length == 0) { Log("Enter a message.", BrushWarn); return; }
            Log("Sending SMS to " + to + " ...", BrushAccent);
            _busy = true;
            try
            {
                string[] r = await Task.Run(delegate { return _modem.SendSms(to, body, 60000); });
                bool ok = false;
                foreach (string l in r) if (Regex.IsMatch(l, @"(^|\s)OK(\s|$)")) ok = true;
                foreach (string l in r) Log(l, ok ? BrushSuccess : BrushGray);
                if (ok)
                {
                    Log("SMS sent to " + to, BrushSuccess);
                    _txtSmsBody.Text = "";
                }
                else
                {
                    Log("SMS failed.", BrushError);
                }
            }
            catch (Exception ex) { Log("SMS error: " + ex.Message, BrushError); }
            finally { _busy = false; }
        }

        // ---------- chat (relay peer chat + SMS fallback) ----------
        private static string ChatPathFor(string number)
        {
            return Path.Combine(AppConfig.ChatsDir, "chat_" + number + ".txt");
        }

        // (Re)load the conversation for the number in the To field.
        // Resolve a typed recipient: a saved contact's name maps to its number.
        private string ResolveChatNumber(string text)
        {
            if (string.IsNullOrWhiteSpace(text)) return "";
            string t = text.Trim();
            if (_contacts != null)
                foreach (Contact c in _contacts)
                    if (c.Name != null && c.Name.Equals(t, StringComparison.OrdinalIgnoreCase))
                        return SanitizeNumber(c.Number);
            return SanitizeNumber(t);
        }

        private void UpdateChatPartner(string num)
        {
            if (_chatPartner == null) return;
            if (num.Length < 3) { _chatPartner.Text = ""; return; }
            string name = null;
            if (_contacts != null)
                foreach (Contact c in _contacts)
                    if (SanitizeNumber(c.Number) == num) { name = c.Name; break; }
            _chatPartner.Text = name != null ? ("chat with " + name + " (" + num + ")") : ("chat with #" + num);
        }

        private void ChatOpen()
        {
            if (_chatPanel == null) return;
            _chatPanel.Children.Clear();
            _chatMsgs.Clear();
            _lastBubbleDate = "";
            string num = ChatNumber();
            _chatOpenNum = num;
            CloseChatSecuritySheet();   // details belong to one conversation only
            _chatStickBottom = true;   // opening a conversation always starts at the newest message
            Log("Chat: opened #" + num, BrushGray);
            ChatSecurityChip(num);
            if (num.Length < 3)
            {
                ChatAddBubble("sys", "", "", "Enter a number to open a chat.", false, null);
                return;
            }
            try
            {
                string path = ChatPathFor(num);
                if (File.Exists(path))
                {
                    foreach (string line in File.ReadAllLines(path))
                    {
                        // v2 format: date|dir|time|text - legacy: dir|time|text
                        string[] p = line.Split(new char[] { '|' }, 4);
                        if (p.Length >= 4)
                            _chatMsgs.Add(new ChatMsg { Date = p[0], Dir = p[1], Time = p[2], Text = p[3], Delivered = true });
                        else if (p.Length >= 3)
                            _chatMsgs.Add(new ChatMsg { Dir = p[0], Time = p[1], Text = p[2], Delivered = true });
                    }
                }
                else ChatAddBubble("sys", "", "", "No messages with " + num + " yet.", false, null);
            }
            catch (Exception ex) { Log("Chat load error: " + ex.Message, BrushWarn); }
            foreach (ChatMsg m in _chatMsgs) ChatAddBubble(m.Dir, m.Date, m.Time, m.Text, m.Delivered, m);
            UpdateChatPartner(num);
            ChatRefreshRecent();
            ChatScrollEnd();
            ChatMarkUnreadSeen();
        }

        // Human day separator text for a stored yyyy-MM-dd stamp.
        private static string ChatDayLabel(string date)
        {
            if (date == null || date.Length != 10) return "";
            DateTime d;
            if (!DateTime.TryParseExact(date, "yyyy-MM-dd",
                System.Globalization.CultureInfo.InvariantCulture,
                System.Globalization.DateTimeStyles.None, out d)) return "";
            string today = DateTime.Now.ToString("yyyy-MM-dd");
            string yest = DateTime.Now.AddDays(-1).ToString("yyyy-MM-dd");
            if (date == today) return "Today";
            if (date == yest) return "Yesterday";
            return d.ToString("d MMM yyyy");
        }

        // Rebuild the open conversation from _chatMsgs (used after the peer's
        // delivery receipt arrives so pending ticks can turn into ticks-ticks).
        // Honors the search filter: only matching bubbles are shown.
        private void ChatReRender()
        {
            if (_chatPanel == null) return;
            _chatPanel.Children.Clear();
            _lastBubbleDate = "";
            int shown = 0;
            foreach (ChatMsg m in _chatMsgs)
            {
                if (_chatFilter.Length > 0)
                {
                    // Match what the user sees ("Voice note (7 s)") as well as
                    // the stored payload, so filters can find voice notes.
                    string hay = ChatPreview(m.Dir, m.Text);
                    bool hit = hay.IndexOf(_chatFilter, StringComparison.OrdinalIgnoreCase) >= 0
                        || (m.Text != null && m.Text.IndexOf(_chatFilter, StringComparison.OrdinalIgnoreCase) >= 0);
                    if (!hit) continue;
                }
                shown++;
                ChatAddBubble(m.Dir, m.Date, m.Time, m.Text, m.Delivered, m);
            }
            if (_chatFilter.Length > 0)
            {
                ChatAddBubble("sys", "", "", shown + " of " + _chatMsgs.Count + " messages match.", false, null);
                // Filtered view: read results from the top instead of the bottom.
                _chatStickBottom = false;
                try { _chatScroll.ScrollToTop(); } catch { }
                return;
            }
            _chatStickBottom = true;
            ChatScrollEnd();
        }

        // The peer confirmed receipt of our messages: upgrade pending ticks.
        private void ChatMarkDelivered(string from)
        {
            string num = SanitizeNumber(from);
            if (num != _chatOpenNum && num != ChatNumber()) return;
            bool changed = false;
            foreach (ChatMsg m in _chatMsgs)
                if (m.Dir == "out" && !m.Delivered) { m.Delivered = true; changed = true; }
            if (changed) ChatReRender();
        }

        private string ChatNumber()
        {
            if (_txtChatTo == null) return "";
            string t = _txtChatTo.Text.Trim();
            string viaName = ResolveChatNumber(t);
            if (viaName.Length >= 3) return viaName;
            return SanitizeNumber(t);
        }

        private static void AppendShared(string path, string line)
        {
            // shared-read append so trace/log polls never block or drop lines
            using (FileStream fs = new FileStream(path, FileMode.Append, FileAccess.Write, FileShare.ReadWrite))
            using (StreamWriter w = new StreamWriter(fs))
                w.WriteLine(line);
        }

        // Append one message to the per-number chat file AND (when that
        // conversation is open) to the visible panel. The file write is
        // unconditional: a message that arrives while another conversation is
        // open must still be in tomorrow's history.
        private void ChatPersist(string dir, string num, string text)
        {
            string date = DateTime.Now.ToString("yyyy-MM-dd");
            string time = DateTime.Now.ToString("HH:mm:ss");
            bool visible = num == _chatOpenNum || (num.Length >= 3 && num == ChatNumber());
            bool pending = dir == "out";   // out messages start as single tick
            if (visible)
            {
                ChatMsg nm = new ChatMsg { Dir = dir, Date = date, Time = time, Text = text, Delivered = !pending };
                _chatMsgs.Add(nm);
                ChatAddBubble(dir, date, time, text, !pending, nm);
                if (_chatStickBottom) ChatScrollEnd();   // don't fight a user reading history
            }
            try
            {
                Directory.CreateDirectory(AppConfig.ChatsDir);
                AppendShared(ChatPathFor(num),
                    date + "|" + dir + "|" + time + "|" +
                    text.Replace("\r", " ").Replace("\n", " "));   // one line per message
            }
            catch (Exception ex) { Log("Chat save error: " + ex.Message, BrushWarn); }
            ChatRefreshRecent();
        }

        private void ChatAddBubble(string dir, string date, string time, string text, bool delivered, ChatMsg owner)
        {
            if (_chatPanel == null || text == null) return;
            bool mine = dir == "out" || dir == "vout";
            bool voice = dir == "vin" || dir == "vout";   // voice-note bubble: text = "secs|path"
            bool sys = dir == "sys";

            // WhatsApp-style day separator between message days
            string day = ChatDayLabel(date);
            if (!sys && day.Length > 0 && day != _lastBubbleDate)
            {
                _lastBubbleDate = day;
                TextBlock sep = new TextBlock
                {
                    Text = day,
                    Foreground = new SolidColorBrush(Color.FromRgb(0xc7, 0xd2, 0xfe)),
                    FontSize = 11,
                    FontWeight = FontWeights.SemiBold,
                    HorizontalAlignment = System.Windows.HorizontalAlignment.Center,
                    Margin = new Thickness(0, 6, 0, 2)
                };
                Border sepB = new Border
                {
                    Background = new SolidColorBrush(Color.FromArgb(90, 0x4c, 0x1d, 0x95)),
                    CornerRadius = new CornerRadius(10),
                    Padding = new Thickness(14, 3, 14, 3),
                    HorizontalAlignment = System.Windows.HorizontalAlignment.Center,
                    Margin = new Thickness(0, 10, 0, 6),
                    Child = sep
                };
                _chatPanel.Children.Add(sepB);
            }

            Border b = new Border
            {
                Background = sys
                    ? new SolidColorBrush(Color.FromArgb(40, 120, 140, 180))
                    : (mine
                        ? new SolidColorBrush(Color.FromRgb(0x6d, 0x28, 0xd9))   // violet — matches image 3 outgoing
                        : new SolidColorBrush(Color.FromRgb(0x1e, 0x25, 0x33))), // dark card — incoming
                CornerRadius = mine ? new CornerRadius(18, 4, 18, 18) : new CornerRadius(4, 18, 18, 18),
                Padding = new Thickness(14, 9, 14, 9),
                Margin = mine ? new Thickness(64, 3, 10, 3) : new Thickness(10, 3, 64, 3),
                HorizontalAlignment = mine ? System.Windows.HorizontalAlignment.Right : System.Windows.HorizontalAlignment.Left,
                MaxWidth = 520
            };
            StackPanel sp = new StackPanel();
            if (voice)
            {
                // text = "<secs>|<wav path>"
                string[] vp = text.Split(new char[] { '|' }, 2);
                int secs = 0;
                int.TryParse(vp[0], out secs);
                string wavPath = vp.Length > 1 ? vp[1] : "";
                Button play = new Button
                {
                    Content = "\u25B6 Voice note (" + secs + " s)",
                    Background = System.Windows.Media.Brushes.Transparent,
                    BorderBrush = System.Windows.Media.Brushes.Transparent,
                    Foreground = System.Windows.Media.Brushes.White,
                    Padding = new Thickness(2, 0, 2, 0),
                    HorizontalAlignment = HorizontalAlignment.Left
                };
                string playPath = wavPath;
                play.SetValue(System.Windows.Automation.AutomationProperties.NameProperty, "Play voice note");
                play.Click += delegate { ChatPlayVoice(playPath); };
                sp.Children.Add(play);
            }
            else
            {
                // Attachment and card tokens travel as plain text so the sealed
                // payload stays simple; they must not *display* as plain text -
                // a local path means nothing to the peer and should not be
                // readable off somebody's screen.
                UIElement rich = ChatMessageContent(text, dir);
                if (rich != null) sp.Children.Add(rich);
                else
                {
                    sp.Children.Add(new TextBlock
                    {
                        Text = text,
                        TextWrapping = TextWrapping.Wrap,
                        FontSize = 13,
                        LineHeight = 19,
                        Foreground = sys
                            ? BrushGray
                            : (mine
                                ? Brushes.White
                                : new SolidColorBrush(Color.FromRgb(0xe2, 0xe8, 0xf0)))
                    });
                }
            }
            string footer = time;
            if (mine && footer.Length > 0)
                footer = footer + " " + (delivered ? "\u2713\u2713" : "\u2713");   // sent / delivered
            if (footer.Length > 0 || owner != null)
            {
                // Footer row: time/ticks plus a small delete affordance, so removing
                // one message does not require discovering a right-click menu.
                DockPanel footRow = new DockPanel
                {
                    Margin = new Thickness(0, 3, 0, 0),
                    LastChildFill = false,
                    HorizontalAlignment = mine ? HorizontalAlignment.Right : HorizontalAlignment.Left
                };
                if (owner != null)
                {
                    Button del = new Button
                    {
                        Content = "\uD83D\uDDD1",
                        FontSize = 9,
                        Opacity = 0.45,
                        Background = Brushes.Transparent,
                        BorderThickness = new Thickness(0),
                        Padding = new Thickness(3, 0, 3, 0),
                        Cursor = Cursors.Hand,
                        ToolTip = "Delete this message"
                    };
                    del.SetValue(System.Windows.Automation.AutomationProperties.NameProperty, "Delete message");
                    ChatMsg victim = owner;
                    del.Click += delegate { ChatDeleteMessage(victim); };
                    DockPanel.SetDock(del, mine ? Dock.Right : Dock.Left);
                    footRow.Children.Add(del);
                }
                if (footer.Length > 0)
                {
                    TextBlock tbFoot = new TextBlock
                    {
                        Text = footer,
                        FontSize = 10,
                        Foreground = sys
                            ? new SolidColorBrush(Color.FromRgb(0x64, 0x74, 0x8b))
                            : new SolidColorBrush(Color.FromArgb(180, 0xc7, 0xd2, 0xfe))
                    };
                    DockPanel.SetDock(tbFoot, mine ? Dock.Right : Dock.Left);
                    footRow.Children.Add(tbFoot);
                }
                sp.Children.Add(footRow);
            }
            b.Child = sp;
            // right-click menu: copy the text, delete this message, or the whole conversation
            System.Windows.Controls.ContextMenu cm = new System.Windows.Controls.ContextMenu();
            System.Windows.Controls.MenuItem miCopy = new System.Windows.Controls.MenuItem { Header = "\uD83D\uDCCB  Copy text" };
            string copyText = voice ? "(voice note)" : FormatChatAttachmentText(text);
            miCopy.Click += delegate { try { Clipboard.SetText(copyText); } catch { } };
            cm.Items.Add(miCopy);
            System.Windows.Controls.MenuItem miExport = new System.Windows.Controls.MenuItem { Header = "\u2B07  Export transcript" };
            miExport.Click += delegate { ChatExport(); };
            cm.Items.Add(miExport);
            // Reply to this message
            if (!sys && owner != null)
            {
                System.Windows.Controls.MenuItem miReply = new System.Windows.Controls.MenuItem { Header = "\u21A9  Reply" };
                ChatMsg replyTarget = owner;
                miReply.Click += delegate
                {
                    SetReplyTo(replyTarget);
                    if (_txtChatInput != null) _txtChatInput.Focus();
                };
                cm.Items.Add(miReply);
            }
            if (owner != null)
            {
                System.Windows.Controls.MenuItem miMsg = new System.Windows.Controls.MenuItem { Header = "\uD83D\uDDD1  Delete message" };
                ChatMsg victim = owner;
                miMsg.Click += delegate { ChatDeleteMessage(victim); };
                cm.Items.Add(miMsg);
            }
            System.Windows.Controls.MenuItem miDel = new System.Windows.Controls.MenuItem { Header = "\uD83D\uDDD1  Delete conversation" };
            miDel.Click += delegate { ChatDeleteConversation(); };
            cm.Items.Add(miDel);
            b.ContextMenu = cm;
            _chatPanel.Children.Add(b);
        }

        private void ChatPlayVoice(string path)
        {
            try
            {
                if (!File.Exists(path)) { Log("Voice note file missing.", BrushWarn); return; }
                System.Media.SoundPlayer p = new System.Media.SoundPlayer(path);
                p.Play();
            }
            catch (Exception ex) { Log("Voice note play error: " + ex.Message, BrushWarn); }
        }

        // Remove ONE message from the open conversation and rewrite its file.
        // ── Token rendering ───────────────────────────────────────────────
        // Legacy local-path tokens remain readable for old chat history.
        // New attachments use a path-free transfer reference.
        private UIElement TryRenderToken(string text)
        {
            string t = (text ?? "").Trim();
            if (t.Length == 0) return null;
            try
            {
                if (VCard.Is(t)) return VCardCard(VCard.Parse(t));
                if (t.StartsWith("[IMAGE:", StringComparison.Ordinal) && t.EndsWith("]"))
                    return MediaChip("\uD83D\uDDBC", "Photo", t.Substring(7, t.Length - 8), 240);
                if (t.StartsWith("[STICKER:", StringComparison.Ordinal) && t.EndsWith("]"))
                    return MediaChip("\uD83C\uDFA8", "Sticker", t.Substring(9, t.Length - 10), 120);
                if (t.StartsWith("[FILE:", StringComparison.Ordinal) && t.EndsWith("]"))
                {
                    string[] fp = t.Substring(6, t.Length - 7).Split(new char[] { '|' }, 3);
                    string path = fp.Length > 0 ? fp[0] : "";
                    string name = fp.Length > 1 && fp[1].Length > 0
                        ? fp[1] : System.IO.Path.GetFileName(path);
                    return FileChip(name, fp.Length > 2 ? fp[2] : "", path);
                }
                if (t.StartsWith("[LARGE_MSG:", StringComparison.Ordinal) && t.EndsWith("]"))
                {
                    string[] fp = t.Substring(11, t.Length - 12).Split(new char[] { '|' }, 3);
                    string path = fp.Length > 0 ? fp[0] : "";
                    return FileChip(fp.Length > 1 ? fp[1] : "message.txt", fp.Length > 2 ? fp[2] : "", path);
                }
            }
            catch { }
            return null;
        }

        private UIElement ChatMessageContent(string text, string dir)
        {
            MatchCollection matches = Regex.Matches(text ?? "",
                @"\[ATTACHMENT:([A-F0-9]{16})\|([A-Za-z0-9+/=]+)\|([0-9]+)\]");
            if (matches.Count == 0) return TryRenderToken(text);
            StackPanel content = new StackPanel();
            int offset = 0;
            foreach (Match match in matches)
            {
                if (match.Index > offset)
                    content.Children.Add(new TextBlock
                    {
                        Text = text.Substring(offset, match.Index - offset),
                        TextWrapping = TextWrapping.Wrap,
                        FontSize = 13,
                        LineHeight = 19,
                        Foreground = dir == "out" ? Brushes.White : new SolidColorBrush(Color.FromRgb(0xe2, 0xe8, 0xf0))
                    });
                string name;
                long size;
                try
                {
                    name = Encoding.UTF8.GetString(Convert.FromBase64String(match.Groups[2].Value));
                    if (!long.TryParse(match.Groups[3].Value, out size)) size = 0;
                }
                catch
                {
                    name = "Attachment";
                    size = 0;
                }
                content.Children.Add(ChatAttachmentChip(match.Groups[1].Value, name, size, dir));
                offset = match.Index + match.Length;
            }
            if (offset < text.Length)
                content.Children.Add(new TextBlock
                {
                    Text = text.Substring(offset),
                    TextWrapping = TextWrapping.Wrap,
                    FontSize = 13,
                    LineHeight = 19,
                    Foreground = dir == "out" ? Brushes.White : new SolidColorBrush(Color.FromRgb(0xe2, 0xe8, 0xf0))
                });
            return content;
        }

        private UIElement ChatAttachmentChip(string transferId, string name, long size, string dir)
        {
            StackPanel card = new StackPanel { Margin = new Thickness(0, 3, 0, 3) };
            card.Children.Add(new TextBlock
            {
                Text = "\uD83D\uDCCE  " + SafeReceivedFileName(name),
                FontSize = 13,
                FontWeight = FontWeights.SemiBold,
                Foreground = Brushes.White,
                TextWrapping = TextWrapping.Wrap
            });
            card.Children.Add(TokenLabel(FormatFileSize(size)));
            FileTransferSession session;
            if (_transfers.TryGetValue(transferId, out session))
            {
                if (session.State == "complete" && !string.IsNullOrEmpty(session.ReceivedPath) &&
                    File.Exists(session.ReceivedPath))
                    card.Children.Add(OpenPathLink(session.ReceivedPath, "Open"));
                else if (session.Direction == "in" && session.State == "offered" && dir == "in")
                {
                    Button download = MakeButton("Accept and download");
                    string id = transferId;
                    string peer = _chatOpenNum;
                    download.Margin = new Thickness(0, 4, 0, 0);
                    download.HorizontalAlignment = HorizontalAlignment.Left;
                    download.Click += delegate { AcceptFileTransfer(id, peer); };
                    card.Children.Add(download);
                    Button decline = MakeButton("Decline");
                    decline.Margin = new Thickness(0, 2, 0, 0);
                    decline.HorizontalAlignment = HorizontalAlignment.Left;
                    decline.Click += delegate { RejectFileTransfer(id, peer); };
                    card.Children.Add(decline);
                }
                else
                {
                    string state = session.State == "accepted" ? "Transfer in progress..."
                        : session.State == "complete" ? (session.Direction == "out" ? "Sent securely" : "Verified")
                        : session.State == "failed" ? "Transfer failed"
                        : session.Direction == "out" ? "Waiting for recipient"
                        : "Accept from the file offer notification";
                    card.Children.Add(TokenLabel(state));
                }
            }
            else card.Children.Add(TokenLabel("Secure transfer offer pending"));
            return card;
        }

        private static TextBlock TokenLabel(string s)
        {
            return new TextBlock
            {
                Text = s,
                FontSize = 12,
                Foreground = new SolidColorBrush(Color.FromRgb(0xc7, 0xd2, 0xfe)),
                TextWrapping = TextWrapping.Wrap
            };
        }

        private UIElement MediaChip(string glyph, string kind, string path, double maxW)
        {
            StackPanel card = new StackPanel();
            bool have = false;
            try { have = !string.IsNullOrEmpty(path) && System.IO.File.Exists(path); } catch { }
            if (have)
            {
                try
                {
                    BitmapImage bi = new BitmapImage();
                    bi.BeginInit();
                    // OnLoad: the alternative keeps the file handle open, which
                    // then blocks the sender from moving or deleting it.
                    bi.CacheOption = BitmapCacheOption.OnLoad;
                    bi.UriSource = new Uri(path, UriKind.Absolute);
                    bi.EndInit();
                    card.Children.Add(new Image
                    {
                        Source = bi,
                        MaxWidth = maxW,
                        MaxHeight = maxW * 0.8,
                        Stretch = Stretch.Uniform,
                        HorizontalAlignment = HorizontalAlignment.Left,
                        Margin = new Thickness(0, 0, 0, 4)
                    });
                }
                catch { have = false; }
            }
            card.Children.Add(TokenLabel(have
                ? glyph + "  " + kind
                : glyph + "  " + kind + " - not stored on this device"));
            if (have) card.Children.Add(OpenPathLink(path, "Open"));
            return card;
        }

        private UIElement FileChip(string name, string size, string path)
        {
            StackPanel sp = new StackPanel();
            sp.Children.Add(new TextBlock
            {
                Text = "\uD83D\uDCC4  " + name,
                FontSize = 13,
                FontWeight = FontWeights.SemiBold,
                Foreground = Brushes.White,
                TextWrapping = TextWrapping.Wrap
            });
            bool have = false;
            try { have = !string.IsNullOrEmpty(path) && System.IO.File.Exists(path); } catch { }
            if (size.Length > 0)
                sp.Children.Add(new TextBlock
                {
                    Text = have ? size : size + " - not stored on this device",
                    FontSize = 11,
                    Foreground = new SolidColorBrush(Color.FromRgb(0xc7, 0xd2, 0xfe))
                });
            if (have) sp.Children.Add(OpenPathLink(path, "Open"));
            return sp;
        }

        private UIElement OpenPathLink(string path, string label)
        {
            Button b = new Button
            {
                Content = label,
                FontSize = 11,
                Background = Brushes.Transparent,
                BorderThickness = new Thickness(0),
                Padding = new Thickness(0, 2, 0, 0),
                HorizontalAlignment = HorizontalAlignment.Left,
                Cursor = Cursors.Hand,
                Foreground = BrushAccent
            };
            string p = path;
            b.Click += delegate
            {
                try
                {
                    Process.Start(new ProcessStartInfo { FileName = p, UseShellExecute = true });
                }
                catch (Exception ex) { Log("Could not open " + System.IO.Path.GetFileName(p) + ": " + ex.Message, BrushError); }
            };
            return b;
        }

        private static string InitialOf(string s)
        {
            string t = (s ?? "").Trim();
            return t.Length == 0 ? "?" : t.Substring(0, 1).ToUpperInvariant();
        }

        // The rich contact bubble: avatar initial, name, organisation, number,
        // plus the one tap that makes a card worth receiving.
        private UIElement VCardCard(string[] c)
        {
            string name = c[0], number = c[1], org = c[2], note = c[3];
            if (name.Length == 0) name = number.Length > 0 ? number : "Contact card";

            DockPanel row = new DockPanel { LastChildFill = true };
            Border av = new Border
            {
                Width = 44,
                Height = 44,
                CornerRadius = new CornerRadius(22),
                Background = new SolidColorBrush(Color.FromRgb(0x4f, 0x8c, 0xff)),
                Margin = new Thickness(0, 0, 10, 0),
                VerticalAlignment = VerticalAlignment.Top,
                Child = new TextBlock
                {
                    Text = InitialOf(name),
                    Foreground = Brushes.White,
                    FontSize = 18,
                    FontWeight = FontWeights.Bold,
                    HorizontalAlignment = HorizontalAlignment.Center,
                    VerticalAlignment = VerticalAlignment.Center
                }
            };
            DockPanel.SetDock(av, Dock.Left);
            row.Children.Add(av);

            StackPanel txt = new StackPanel();
            txt.Children.Add(new TextBlock
            {
                Text = name,
                FontSize = 14,
                FontWeight = FontWeights.SemiBold,
                Foreground = Brushes.White,
                TextWrapping = TextWrapping.Wrap
            });
            if (org.Length > 0) txt.Children.Add(new TextBlock
            {
                Text = org,
                FontSize = 11,
                Foreground = new SolidColorBrush(Color.FromRgb(0xc7, 0xd2, 0xfe))
            });
            if (number.Length > 0) txt.Children.Add(new TextBlock
            {
                Text = number,
                FontSize = 12,
                FontFamily = new FontFamily("Consolas, Courier New"),
                Foreground = Brushes.White
            });
            if (note.Length > 0) txt.Children.Add(new TextBlock
            {
                Text = note,
                FontSize = 11,
                Foreground = new SolidColorBrush(Color.FromRgb(0xc7, 0xd2, 0xfe)),
                TextWrapping = TextWrapping.Wrap
            });
            row.Children.Add(txt);

            StackPanel acts = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 6, 0, 0) };
            if (number.Length > 0)
            {
                Button add = MakeButton("Add to contacts");
                add.FontSize = 11;
                add.Margin = new Thickness(0, 0, 8, 0);
                string nName = name, nNum = number, nOrg = org;
                add.Click += delegate { AddContactFromCard(nName, nNum, nOrg); };
                acts.Children.Add(add);
            }
            Button copy = MakeButton("Copy vCard");
            copy.FontSize = 11;
            string cc = number;
            copy.Click += delegate
            {
                try
                {
                    Clipboard.SetText(VCard.ToVcf(name, number, org, note));
                    Log("Contact card copied as vCard 3.0.", BrushGray);
                }
                catch (Exception ex) { Log("Copy failed: " + ex.Message, BrushError); }
            };
            acts.Children.Add(copy);

            StackPanel card = new StackPanel();
            card.Children.Add(row);
            card.Children.Add(acts);
            return card;
        }

        private void AddContactFromCard(string name, string number, string org)
        {
            string num = SanitizeNumber(number ?? "");
            if (num.Length == 0) { Log("That card has no usable number.", BrushWarn); return; }
            foreach (Contact c in _contacts) if (c.Number == num) { Log("Already in contacts: " + num, BrushWarn); return; }
            string nm = name.Length > 0 ? name : num;
            _contacts.Add(new Contact { Name = nm, Number = num, Source = org.Length > 0 ? org : "Card" });
            SaveContacts();
            RefreshContactsView();
            Log("Contact added from card: " + nm + " (" + num + ")", BrushSuccess);
        }

        // ── Share a contact as a card ─────────────────────────────────
        private void HubShareContact()
        {
            if (_txtChatInput == null) { Log("Open a conversation before sharing a card.", BrushWarn); return; }
            List<Contact> pool = new List<Contact>();
            foreach (Contact c in _contacts)
                if (c != null && !string.IsNullOrEmpty(c.Number)) pool.Add(c);
            if (pool.Count == 0)
            {
                Toast.Show("No contacts to share",
                    "Add a contact in the Contacts tab first - then you can send it as a card.", null);
                return;
            }

            Window pw = new Window
            {
                Title = "Share contact card",
                Width = 420,
                Height = 440,
                ResizeMode = ResizeMode.CanResize,
                WindowStartupLocation = WindowStartupLocation.CenterOwner,
                Owner = this,
                Background = Theme.Bg
            };
            Border pc = new Border { Background = Theme.Card, BorderBrush = Theme.CardBorder, BorderThickness = new Thickness(1), CornerRadius = new CornerRadius(12), Padding = new Thickness(14), Margin = new Thickness(10) };
            DockPanel dp = new DockPanel { LastChildFill = true };
            StackPanel prow = new StackPanel { Orientation = Orientation.Horizontal, HorizontalAlignment = HorizontalAlignment.Right, Margin = new Thickness(0, 10, 0, 0) };
            DockPanel.SetDock(prow, Dock.Bottom);
            Button cancel = MakeButton("Cancel");
            cancel.Click += delegate { pw.Close(); };
            prow.Children.Add(cancel);
            Button share = MakeButton("Share card");
            Style shs = TryStyle("PrimaryButton"); if (shs != null) share.Style = shs;
            share.Margin = new Thickness(8, 0, 0, 0);
            prow.Children.Add(share);

            ListBox lb = new ListBox { Background = Brushes.Transparent, BorderThickness = new Thickness(0), Foreground = BrushFg };
            List<string[]> rows = new List<string[]>();
            rows.Add(new string[] { _voip != null ? _voip.LocalName : Environment.UserName, _myNumber ?? "", "App", "My card" });
            lb.Items.Add(new TextBlock { Text = "My card \u00b7 " + (_myNumber ?? ""), Foreground = BrushFg, Padding = new Thickness(2, 4, 2, 4) });
            foreach (Contact c in pool)
            {
                rows.Add(new string[] { c.Name, c.Number, c.Source ?? "", "" });
                lb.Items.Add(new TextBlock { Text = c.Name + "  \u00b7  " + c.Number, Foreground = BrushFg, Padding = new Thickness(2, 4, 2, 4) });
            }
            share.Click += delegate
            {
                int i = lb.SelectedIndex;
                if (i < 0) i = 0;
                string[] r = rows[i];
                _txtChatInput.Text += VCard.Token(r[0], r[1], r[2], r[3]);
                Log("Contact card ready: " + r[0] + " - press Send.", BrushGray);
                pw.Close();
            };

            dp.Children.Add(prow);
            dp.Children.Add(new TextBlock
            {
                Text = "Pick a contact to send as a card",
                FontSize = 13,
                FontWeight = FontWeights.Bold,
                Foreground = BrushFg,
                Margin = new Thickness(0, 0, 0, 8)
            });
            DockPanel.SetDock(lb, Dock.Top);
            dp.Children.Add(lb);
            pc.Child = dp; pw.Content = pc; pw.ShowDialog();
        }

        private void ChatDeleteMessage(ChatMsg m)
        {
            if (m == null) return;
            _chatMsgs.Remove(m);
            ChatRewriteFile();
            ChatReRender();
            ChatRefreshRecent();
            Log("Chat: message deleted.", BrushGray);
        }

        // Rewrite the open conversation's file from _chatMsgs (used by
        // per-message delete; plain appends never call this).
        private void ChatRewriteFile()
        {
            try
            {
                if (_chatOpenNum.Length < 3) return;
                Directory.CreateDirectory(AppConfig.ChatsDir);
                StringBuilder sb = new StringBuilder();
                foreach (ChatMsg m in _chatMsgs)
                {
                    string date = m.Date == null || m.Date.Length == 0 ? DateTime.Now.ToString("yyyy-MM-dd") : m.Date;
                    string t = m.Text == null ? "" : m.Text;
                    sb.Append(date).Append('|').Append(m.Dir).Append('|').Append(m.Time == null ? "" : m.Time)
                      .Append('|').Append(t.Replace("\r", " ").Replace("\n", " ")).Append('\n');
                }
                File.WriteAllText(ChatPathFor(_chatOpenNum), sb.ToString(), Encoding.UTF8);
            }
            catch (Exception ex) { Log("Chat rewrite error: " + ex.Message, BrushWarn); }
        }

        // ---------- voice notes ----------
        // Toggle recording: first click starts (mic frames append to _vnBuf),
        // second click (or the 30 s cap) builds a WAV and sends it over the relay.
        private void ToggleVoiceNote()
        {
            if (_vnRecording) { VnStopSend(); return; }
            if (_chatOpenNum.Length < 3) { Log("Chat: open a conversation first. (open=" + _chatOpenNum + ")", BrushWarn); return; }
            if (_voip == null || !_voip.ChatRelayReady) { Log("Voice notes need the relay (internet number).", BrushWarn); return; }
            if (_voipAudio == null) { Log("Voice notes: audio device unavailable.", BrushWarn); return; }
            lock (_vnLock) _vnBuf.Clear();
            _vnSecs = 0;
            _vnRecording = true;
            if (_btnVoiceNote != null)
            {
                _btnVoiceNote.Content = "\u23F8 Stop (0 s)";
                _btnVoiceNote.SetValue(System.Windows.Automation.AutomationProperties.NameProperty, "Stop");
                // Visual + spoken state: red mic while capture is live.
                _btnVoiceNote.Foreground = new SolidColorBrush(Color.FromRgb(0xef, 0x44, 0x44));
                _btnVoiceNote.ToolTip = "Recording - tap to stop and send";
                _btnVoiceNote.SetValue(System.Windows.Automation.AutomationProperties.HelpTextProperty,
                    "Recording voice note - activate to stop and send");
            }
            if (_vnTimer == null)
            {
                _vnTimer = new System.Windows.Threading.DispatcherTimer { Interval = TimeSpan.FromSeconds(1) };
                _vnTimer.Tick += delegate
                {
                    _vnSecs++;
                    if (_btnVoiceNote != null) _btnVoiceNote.Content = "\u23F8 Stop (" + _vnSecs + " s)";
                    int n = 0;
                    lock (_vnLock) n = _vnBuf.Count;
                    if (_vnSecs == 2 && n == 0) OpenVoipMedia();   // retry a missed mic open
                    if (_vnSecs == 4 && n == 0) OpenVoipMedia();
                    if (_vnSecs == 3)
                        Log("Voice note: " + n + " frames buffered (" + (_vnRecording ? "rec" : "stopped") + ")", BrushGray);
                    if (_vnSecs >= 5 && n == 0) VnStopSend();   // no capture device: fail fast
                    if (_vnSecs >= VN_MAX_SECS) VnStopSend();
                };
            }
            OpenVoipMedia();   // idempotent: starts the 20 ms mic frame pump
            if (FakeMicEnabled()) StartFakeMic();
            _vnTimer.Stop();
            _vnTimer.Start();
            Log("Voice note: recording for #" + _chatOpenNum + " ...", BrushGray);
        }

        // ── Test hook: synthetic microphone ─────────────────────────────────
        // USSD_FAKE_MIC=1 feeds the voice-note recorder a 440 Hz tone instead of
        // the capture device, so the voice-note path is testable on machines
        // with no microphone (or with the device held by another app).
        private System.Windows.Threading.DispatcherTimer _fakeMicTimer;
        private double _fakeMicPhase;

        private static bool FakeMicEnabled()
        {
            return Environment.GetEnvironmentVariable("USSD_FAKE_MIC") == "1";
        }

        private void StartFakeMic()
        {
            if (_fakeMicTimer == null)
            {
                _fakeMicTimer = new System.Windows.Threading.DispatcherTimer { Interval = TimeSpan.FromMilliseconds(20) };
                _fakeMicTimer.Tick += delegate
                {
                    byte[] pcm = new byte[VoipAudio.FRAME_BYTES];
                    for (int i = 0; i < pcm.Length / 2; i++)
                    {
                        short s = (short)(9000 * Math.Sin(_fakeMicPhase));
                        _fakeMicPhase += 2 * Math.PI * 440 / VoipAudio.SAMPLE_RATE;
                        if (_fakeMicPhase > 2 * Math.PI) _fakeMicPhase -= 2 * Math.PI;
                        pcm[i * 2] = (byte)(s & 0xff);
                        pcm[i * 2 + 1] = (byte)((s >> 8) & 0xff);
                    }
                    OnMicFrame(pcm);
                };
            }
            _fakeMicTimer.Stop();
            _fakeMicTimer.Start();
        }

        private void StopFakeMic()
        {
            if (_fakeMicTimer != null) _fakeMicTimer.Stop();
        }

        private void VnStopSend()
        {
            if (!_vnRecording) return;
            _vnRecording = false;
            StopFakeMic();
            if (_vnTimer != null) _vnTimer.Stop();
            if (_btnVoiceNote != null)
            {
                _btnVoiceNote.Content = "\uD83C\uDFA4 Record";
                _btnVoiceNote.SetValue(System.Windows.Automation.AutomationProperties.NameProperty, "Record");
                _btnVoiceNote.Foreground = new SolidColorBrush(Color.FromRgb(0x94, 0xa3, 0xb8));
                _btnVoiceNote.ToolTip = "Record & send voice note (up to 30s)";
                _btnVoiceNote.SetValue(System.Windows.Automation.AutomationProperties.HelpTextProperty,
                    "Record and send a voice note");
            }
            List<byte[]> frames;
            lock (_vnLock) { frames = new List<byte[]>(_vnBuf); _vnBuf.Clear(); }
            int secs = _vnSecs;
            _vnSecs = 0;
            if (frames.Count == 0)
            {
                bool mic = _voipAudio != null && _voipAudio.MicOpen;
                Log(mic ? "Voice note: nothing recorded."
                        : "Voice note: microphone unavailable - no capture device, or Windows microphone access is blocked.",
                    BrushWarn);
                if (!mic)
                    Toast.Show("No microphone", "Voice notes need microphone access (Windows Settings > Privacy > Microphone).", null);
                return;
            }
            try
            {
                // build WAV: 16 kHz mono 16-bit header + raw PCM frames
                int total = 0;
                foreach (byte[] f in frames) total += f.Length;
                byte[] wav = new byte[44 + total];
                wav[0] = (byte)'R'; wav[1] = (byte)'I'; wav[2] = (byte)'F'; wav[3] = (byte)'F';
                PutU32(wav, 4, (uint)(36 + total));
                wav[8] = (byte)'W'; wav[9] = (byte)'A'; wav[10] = (byte)'V'; wav[11] = (byte)'E';
                wav[12] = (byte)'f'; wav[13] = (byte)'m'; wav[14] = (byte)'t'; wav[15] = (byte)' ';
                PutU32(wav, 16, 16);                       // fmt chunk size
                PutU16(wav, 20, 1);                        // PCM
                PutU16(wav, 22, 1);                        // mono
                PutU32(wav, 24, 16000);                    // sample rate
                PutU32(wav, 28, 32000);                    // byte rate
                PutU16(wav, 32, 2);                        // block align
                PutU16(wav, 34, 16);                       // bits per sample
                wav[36] = (byte)'d'; wav[37] = (byte)'a'; wav[38] = (byte)'t'; wav[39] = (byte)'a';
                PutU32(wav, 40, (uint)total);
                int off = 44;
                foreach (byte[] f in frames) { Buffer.BlockCopy(f, 0, wav, off, f.Length); off += f.Length; }

                string path = Path.Combine(AppConfig.ChatsDir, "vn_" + DateTime.Now.Ticks + ".wav");
                Directory.CreateDirectory(AppConfig.ChatsDir);
                File.WriteAllBytes(path, wav);
                if (_voip.SendVoiceNote(_chatOpenNum, wav))
                {
                    Log("Voice note sent (" + secs + " s).", BrushSuccess);
                    ChatPersist("vout", _chatOpenNum, secs + "|" + path);
                }
                else
                {
                    Log("Voice note failed: relay not connected.", BrushError);
                    try { File.Delete(path); } catch { }
                }
            }
            catch (Exception ex) { Log("Voice note error: " + ex.Message, BrushWarn); }
        }

        private static void PutU16(byte[] b, int off, ushort v)
        {
            b[off] = (byte)(v & 0xff); b[off + 1] = (byte)((v >> 8) & 0xff);
        }

        private static void PutU32(byte[] b, int off, uint v)
        {
            b[off] = (byte)(v & 0xff); b[off + 1] = (byte)((v >> 8) & 0xff);
            b[off + 2] = (byte)((v >> 16) & 0xff); b[off + 3] = (byte)((v >> 24) & 0xff);
        }

        // ---------- export / unread ----------
        // Save the open conversation as a readable transcript (.txt).
        private void ChatExport()
        {
            Log("Chat: export requested (open=" + _chatOpenNum + ", msgs=" + _chatMsgs.Count + ")", BrushGray);
            if (_chatOpenNum.Length < 3 || _chatMsgs.Count == 0)
            {
                Log("Chat: open a conversation with messages to export.", BrushWarn);
                return;
            }
            try
            {
                // One-click export: no modal dialog, so the transcript lands in a
                // predictable place (chats\exports) and works headless too.
                string dir = Path.Combine(AppConfig.ChatsDir, "exports");
                Directory.CreateDirectory(dir);
                string fileName = Path.Combine(dir,
                    "chat_" + _chatOpenNum + "_" + DateTime.Now.ToString("yyyyMMdd_HHmmss") + ".txt");
                StringBuilder sb = new StringBuilder();
                sb.AppendLine("USSD Manager Pro - chat with #" + _chatOpenNum);
                sb.AppendLine("Exported " + DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss"));
                sb.AppendLine();
                string lastDate = "";
                foreach (ChatMsg m in _chatMsgs)
                {
                    string date = m.Date == null ? "" : m.Date;
                    if (date.Length > 0 && date != lastDate)
                    {
                        lastDate = date;
                        sb.AppendLine("== " + ChatDayLabel(date) + " ==");
                    }
                    string who = m.Dir == "out" || m.Dir == "vout" ? "Me" : "#";
                    string body;
                    if (m.Dir == "vin" || m.Dir == "vout")
                    {
                        int secs = 0;
                        string[] vp = (m.Text ?? "").Split(new char[] { '|' }, 2);
                        int.TryParse(vp[0], out secs);
                        body = "[voice note: " + secs + " s]";   // never export local paths
                    }
                    else body = FormatChatAttachmentText(m.Text == null ? "" : m.Text.Replace("\r", " ").Replace("\n", " "));
                    sb.AppendLine((m.Time == null ? "" : m.Time) + "  " + who + ": " + body);
                }
                File.WriteAllText(fileName, sb.ToString(), Encoding.UTF8);
                Log("Chat exported to " + fileName, BrushSuccess);
                Toast.Show("Chat exported", fileName, null);
            }
            catch (Exception ex) { Log("Chat export error: " + ex.Message, BrushWarn); }
        }

        // Unread accounting: remembering which numbers have unseen messages.
        // Shown as a badge on the Pane 1 category and on the conversation row.
        private void ChatMarkUnreadSeen()
        {
            if (_chatOpenNum.Length < 3) return;
            if (_chatUnread.ContainsKey(_chatOpenNum))
            {
                _chatUnread.Remove(_chatOpenNum);
                ChatRefreshRecent();
                ChatUnreadRefresh();   // clear the rail + row badges immediately
            }
        }

        // One-line conversation preview for the list panes: voice notes and
        // large messages must never leak raw payloads or file paths into the UI.
        private static string FormatChatAttachmentText(string text)
        {
            return Regex.Replace(text ?? "", @"\[ATTACHMENT:([A-F0-9]{16})\|([A-Za-z0-9+/=]+)\|([0-9]+)\]",
                delegate(Match match)
                {
                    try
                    {
                        string name = Encoding.UTF8.GetString(Convert.FromBase64String(match.Groups[2].Value));
                        long size;
                        if (!long.TryParse(match.Groups[3].Value, out size)) size = 0;
                        return "\uD83D\uDCCE " + SafeReceivedFileName(name) + " (" + FormatFileSize(size) + ")";
                    }
                    catch { return "\uD83D\uDCCE Attachment"; }
                });
        }

        private static string ChatPreview(string dir, string text)
        {
            string t = text ?? "";
            if (dir == "vin" || dir == "vout")
            {
                int secs = 0;
                string[] vp = t.Split(new char[] { '|' }, 2);
                int.TryParse(vp[0], out secs);
                return "\uD83C\uDFA4 Voice note (" + secs + " s)";
            }
            if (t.StartsWith("[LARGE_MSG:", StringComparison.Ordinal))
            {
                int bar = t.IndexOf('|');
                int bar2 = bar > 0 ? t.IndexOf('|', bar + 1) : -1;
                if (bar2 > bar) return "\uD83D\uDCC4 " + t.Substring(bar + 1, bar2 - bar - 1);
            }
            if (VCard.Is(t))
            {
                string[] c = VCard.Parse(t);
                return "\uD83D\uDC64 " + (c[0].Length > 0 ? c[0] : "Contact card");
            }
            if (t.StartsWith("[IMAGE:", StringComparison.Ordinal)) return "\uD83D\uDDBC Photo";
            if (t.StartsWith("[STICKER:", StringComparison.Ordinal)) return "\uD83C\uDFA8 Sticker";
            if (t.StartsWith("[FILE:", StringComparison.Ordinal))
            {
                string[] fp = t.Substring(6, t.Length - 7).Split(new char[] { '|' }, 3);
                if (fp.Length >= 2 && fp[1].Length > 0) return "\uD83D\uDCC4 " + fp[1];
                return "\uD83D\uDCC4 Attachment";
            }
            return FormatChatAttachmentText(t);
        }

        // Header chip text for the open conversation. No string switch here: the
        // build is pinned to the C# 5 compiler.
        private void ChatSecurityChip(string num)
        {
            if (_secChip == null) return;
            string state = "n/a";
            if (_voip != null && !string.IsNullOrEmpty(num)) state = _voip.ChatSecurityState(num);
            string glyph, tip;
            if (state == "locked") { glyph = "\uD83D\uDD12"; tip = "End-to-end encrypted with #" + num + " - tap for the safety number"; }
            else if (state == "blocked") { glyph = "\u26A0"; tip = "Their identity key CHANGED - tap to review"; }
            else if (state == "handshaking") { glyph = "\u23F3"; tip = "Exchanging keys with #" + num; }
            else if (state == "plain") { glyph = "\uD83D\uDD13"; tip = "NOT encrypted"; }
            else { glyph = "\uD83D\uDD10"; tip = "Waiting for a key with #" + num + " - messages are held locally"; }
            _secChip.Content = glyph;
            _secChip.ToolTip = tip;
            _secChip.SetValue(System.Windows.Automation.AutomationProperties.NameProperty, "Chat encryption " + state);
            // Two leading groups in the header: enough to spot a swapped contact
            // at a glance, short enough to live beside the name. Only a session
            // that actually exists earns a place here.
            if (_hubSecDigest != null)
            {
                string sn = (state == "locked") ? _voip.SafetyNumberFor(num) : null;
                if (sn != null && sn.Length >= 11)
                {
                    _hubSecDigest.Text = "safety " + sn.Substring(0, 11);
                    _hubSecDigest.ToolTip = "First groups of the safety number - tap the lock for all twelve";
                    _hubSecDigest.Visibility = Visibility.Visible;
                }
                else
                {
                    _hubSecDigest.Text = "";
                    _hubSecDigest.Visibility = Visibility.Collapsed;
                }
            }
            if (_secSheet != null && _secSheet.Visibility == Visibility.Visible && _secSheetNum == num)
                FillChatSecuritySheet(num);      // keep open details truthful
        }

        // The sheet is built once with the conversation and only refilled, so the
        // UIA tree stays stable for tests and for a person using a reader.
        private void BuildChatSecuritySheet()
        {
            if (_hubPane3Chat == null) return;
            _secSheet = new Grid { Visibility = Visibility.Collapsed };
            _secSheet.Background = new SolidColorBrush(Color.FromArgb(0xD4, 0x06, 0x08, 0x14));
            Grid.SetRow(_secSheet, 0);
            Grid.SetRowSpan(_secSheet, 5);

            // Fixed dark card on purpose: the chat pane keeps its own navy background
            // in both themes, so theme brushes would land unreadable on it.
            Border card = new Border
            {
                MaxWidth = 540,
                Background = new SolidColorBrush(Color.FromRgb(0x16, 0x1A, 0x2C)),
                BorderBrush = new SolidColorBrush(Color.FromRgb(0x3A, 0x42, 0x66)),
                BorderThickness = new Thickness(1),
                CornerRadius = new CornerRadius(12),
                Padding = new Thickness(20, 16, 20, 12),
                HorizontalAlignment = HorizontalAlignment.Center,
                VerticalAlignment = VerticalAlignment.Center
            };
            card.SetValue(System.Windows.Automation.AutomationProperties.NameProperty, "Chat security card");
            StackPanel sp = new StackPanel();

            _secSheetHead = SheetText(15, FontWeights.Bold, Brushes.White, "");
            _secSheetState = SheetText(12, FontWeights.Normal, new SolidColorBrush(Color.FromRgb(0xC7, 0xD0, 0xF5)), "");
            _secSheetState.Margin = new Thickness(0, 8, 0, 0);
            _secSheetMine = SheetText(12, FontWeights.Normal, Brushes.White, "");
            _secSheetMine.FontFamily = new FontFamily("Consolas");
            _secSheetMine.Margin = new Thickness(0, 12, 0, 0);
            _secSheetPeer = SheetText(12, FontWeights.Normal, Brushes.White, "");
            _secSheetPeer.FontFamily = new FontFamily("Consolas");
            _secSheetPeer.Margin = new Thickness(0, 4, 0, 0);
            _secSheetSn = SheetText(15, FontWeights.Bold, new SolidColorBrush(Color.FromRgb(0x86, 0xEF, 0xAC)), "");
            _secSheetSn.FontFamily = new FontFamily("Consolas");
            _secSheetSn.Margin = new Thickness(0, 14, 0, 0);
            _secSheetNote = SheetText(11, FontWeights.Normal, new SolidColorBrush(Color.FromRgb(0x9A, 0xA4, 0xC4)), "");
            _secSheetNote.Margin = new Thickness(0, 12, 0, 0);
            sp.Children.Add(_secSheetHead);
            sp.Children.Add(_secSheetState);
            sp.Children.Add(_secSheetMine);
            sp.Children.Add(_secSheetPeer);
            sp.Children.Add(_secSheetSn);
            sp.Children.Add(_secSheetNote);

            StackPanel btns = new StackPanel
            {
                Orientation = Orientation.Horizontal,
                HorizontalAlignment = HorizontalAlignment.Right,
                Margin = new Thickness(0, 14, 0, 0)
            };
            Button bCopy = MakeOverlayButton("Copy", new SolidColorBrush(Color.FromRgb(0x2A, 0x32, 0x54)), Brushes.White);
            bCopy.SetValue(System.Windows.Automation.AutomationProperties.NameProperty, "Copy safety number");
            bCopy.Click += delegate
            {
                try
                {
                    // The digits only, never the label: this goes straight into a
                    // message to the other person for them to read out.
                    string digits = _secSheetSnValue ?? "";
                    if (digits.Length > 0) { Clipboard.SetText(digits); Log("Security: safety number copied.", BrushGray); }
                }
                catch (Exception ex) { Log("Security: could not copy - " + ex.Message, BrushWarn); }
            };
            _secSheetTrust = MakeOverlayButton("Trust this new key", Theme.Danger, Brushes.White);
            _secSheetTrust.SetValue(System.Windows.Automation.AutomationProperties.NameProperty, "Trust this new key");
            _secSheetTrust.Visibility = Visibility.Collapsed;
            _secSheetTrust.Click += delegate
            {
                string n = _secSheetNum;
                if (_voip == null || n == null || n.Length == 0) return;
                _voip.ForceTrustPeer(n);
                Log("Security: you accepted the new key for #" + n + ". Re-establishing the session.", BrushWarn);
                CloseChatSecuritySheet();
                ChatSecurityChip(n);
            };
            Button bClose = MakeOverlayButton("Close", new SolidColorBrush(Color.FromRgb(0x2A, 0x32, 0x54)), Brushes.White);
            bClose.SetValue(System.Windows.Automation.AutomationProperties.NameProperty, "Close security details");
            bClose.Click += delegate { CloseChatSecuritySheet(); };
            btns.Children.Add(bCopy);
            btns.Children.Add(_secSheetTrust);
            btns.Children.Add(bClose);
            sp.Children.Add(btns);

            card.Child = sp;
            // Clicking the dim area outside the card dismisses it, the way people
            // have learned to close an overlay - but only outside the card.
            _secSheet.MouseLeftButtonDown += delegate(object s, System.Windows.Input.MouseButtonEventArgs e)
            {
                if (ReferenceEquals(e.OriginalSource, _secSheet)) CloseChatSecuritySheet();
            };
            _secSheet.Children.Add(card);
            _hubPane3Chat.Children.Add(_secSheet);
        }

        private static TextBlock SheetText(double size, FontWeight weight, Brush fg, string uiaName)
        {
            TextBlock t = new TextBlock
            {
                Text = "",
                FontSize = size,
                FontWeight = weight,
                Foreground = fg,
                TextWrapping = TextWrapping.Wrap
            };
            // An empty name means "let the text be the accessible name", which is
            // what a value line wants: naming it after the field would hide the
            // very digits a person or a test came here to read.
            if (!string.IsNullOrEmpty(uiaName))
                t.SetValue(System.Windows.Automation.AutomationProperties.NameProperty, uiaName);
            return t;
        }

        private void CloseChatSecuritySheet()
        {
            if (_secSheet != null) _secSheet.Visibility = Visibility.Collapsed;
        }

        // What the sheet says, computed from the security layer rather than from
        // anything remembered: a stale promise of encryption is worse than none.
        private void FillChatSecuritySheet(string num)
        {
            string sn = _voip.SafetyNumberFor(num);
            string peer = _voip.SecPeers == null ? null : _voip.SecPeers.Lookup(num);
            string state = _voip.ChatSecurityState(num);
            string head, summ;
            if (state == "blocked")
            {
                head = "\u26A0  Identity key changed for #" + num;
                summ = "This contact now presents a DIFFERENT identity key from the one recorded on first use. " +
                       "Either they reinstalled on another device, or someone is standing between us. " +
                       "Nothing you send is being released to them until you decide.";
            }
            else if (state == "locked")
            {
                head = "\uD83D\uDD12  Encrypted to #" + num;
                summ = "Every message is sealed with a key derived on this device and never sent anywhere. " +
                       "The relay only carries opaque text it cannot open.";
            }
            else if (state == "handshaking" || state == "pending")
            {
                head = "\uD83D\uDD10  Exchanging keys with #" + num;
                summ = "No session key yet, so outgoing messages are held on this device instead of going out readable.";
            }
            else
            {
                head = "\uD83D\uDD13  Not encrypted";
                summ = "No session exists for this number, so it is not an end-to-end conversation.";
            }
            _secSheetHead.Text = head;
            _secSheetState.Text = summ;
            _secSheetMine.Text = "Your key:  " + _voip.MyFingerprint;
            _secSheetPeer.Text = "Their key: " + (peer == null ? "(not paired yet)" : Identity.FingerprintOf(peer));
            _secSheetSnValue = sn ?? "";
            _secSheetSn.Text = sn == null
                ? "No safety number yet - the key exchange has not completed."
                : "Safety number: " + sn;
            _secSheetNote.Text = (sn == null ? "" :
                "Read these twelve groups aloud with the person on the other end, over a channel the relay does not control. " +
                "Different digits mean something has been swapped in transit.\n") +
                "What the relay can still see: who messaged whom, how often, and the size and time of each line. " +
                "What it cannot see: the words, who read them, or what you named this contact.";
            if (_secSheetTrust != null)
                _secSheetTrust.Visibility = (state == "blocked") ? Visibility.Visible : Visibility.Collapsed;
        }

        private void OpenChatSecuritySheet(string num)
        {
            if (_secSheet == null) return;
            _secSheetNum = num;
            FillChatSecuritySheet(num);
            _secSheet.Visibility = Visibility.Visible;
        }

        // Show what the chip is standing for: both fingerprints plus the safety
        // number, and the only way through a changed key is an explicit yes.
        private void ShowChatSecurity()
        {
            string num = _chatOpenNum;
            if (string.IsNullOrEmpty(num)) { Log("Open a conversation to see its security details.", BrushGray); return; }
            if (_voip == null || _voip.SecIdentity == null) { Log("Security is not active yet - connect to a relay first.", BrushWarn); return; }
            string state = _voip.ChatSecurityState(num);
            string sn = _voip.SafetyNumberFor(num);
            Log("Security: " + state + " with #" + num + (sn == null ? "" : " - safety number " + sn), BrushGray);
            if (_secSheet != null)
            {
                OpenChatSecuritySheet(num);
                if (state == "blocked")
                    Log("Security: review the warning on screen - trusting the new key is a button here, not an assumption.", BrushWarn);
                return;
            }
            // Only reachable if the chat pane was never built; the modal stays as
            // that fallback so the details are never simply unavailable.
            string peer = _voip.SecPeers == null ? null : _voip.SecPeers.Lookup(num);
            string body = "Conversation #" + num + "\n\nState: " + state + "\n" +
                "Your key:  " + _voip.MyFingerprint + "\n" +
                "Their key: " + (peer == null ? "(not paired yet)" : Identity.FingerprintOf(peer)) + "\n" +
                (sn == null ? "\nNo safety number yet." : "\nSafety number:\n" + sn) +
                "\n\nThe relay can still see who messaged whom and when; it cannot read the content.";
            if (state == "blocked")
            {
                System.Windows.MessageBoxResult r = System.Windows.MessageBox.Show(
                    body + "\n\nTrust this NEW key and resume sending?",
                    "Identity key changed", System.Windows.MessageBoxButton.YesNo, System.Windows.MessageBoxImage.Warning);
                if (r == System.Windows.MessageBoxResult.Yes)
                {
                    _voip.ForceTrustPeer(num);
                    Log("Security: you accepted the new key for #" + num + ".", BrushWarn);
                }
            }
            else
                System.Windows.MessageBox.Show(body, "End-to-end encryption",
                    System.Windows.MessageBoxButton.OK, System.Windows.MessageBoxImage.Information);
            ChatSecurityChip(num);
        }

        // Hub search: does any stored line of a transcript match the query?
        // Voice notes are matched through their preview, exactly as the list shows them.
        private static bool ChatFileHasMatch(string[] lines, string q)
        {
            if (lines == null || q == null || q.Length == 0) return false;
            foreach (string ln in lines)
            {
                string[] p = ln.Split(new char[] { '|' }, 4);
                string dir = p.Length >= 2 ? p[1] : "";
                string body = p.Length >= 4 ? p[3] : ln;
                if (ChatPreview(dir, body).ToLowerInvariant().Contains(q)) return true;
            }
            return false;
        }

        // Recompute Pane 1 rail badges from the unread map and repaint the list.
        private void ChatUnreadRefresh()
        {
            int totalSms = 0, totalPeers = 0;
            foreach (KeyValuePair<string, int> kv in _chatUnread)
            {
                totalSms += kv.Value;
                if (_voip != null)
                {
                    foreach (VoipPeer p in _voip.Peers)
                    {
                        if (p.Number == null) continue;
                        if (SanitizeNumber(p.Number) != kv.Key) continue;
                        if ((DateTime.Now - p.LastSeen).TotalSeconds < 120) totalPeers += kv.Value;
                        break;
                    }
                }
            }
            if (_hubUnreadSms != null)
            {
                _hubUnreadSms.Text = totalSms > 9 ? "9+" : totalSms.ToString();
                _hubUnreadSms.Visibility = totalSms > 0 ? Visibility.Visible : Visibility.Collapsed;
            }
            if (_hubUnreadPeers != null)
            {
                _hubUnreadPeers.Text = totalPeers > 9 ? "9+" : totalPeers.ToString();
                _hubUnreadPeers.Visibility = totalPeers > 0 ? Visibility.Visible : Visibility.Collapsed;
            }
            if (_chatHubCategory == "peers" || _chatHubCategory == "sms") HubRefreshPane2();
        }

        private void ChatBumpUnread(string num)
        {
            int n = _chatUnread.ContainsKey(num) ? _chatUnread[num] + 1 : 1;
            _chatUnread[num] = n;
            ChatRefreshRecent();
            ChatUnreadRefresh();   // rail + row badges
        }

        // The relay stored our text because the peer was offline. WhatsApp-style
        // "clock" semantics: the message is saved and will arrive when they
        // next connect the app (even with the window closed, tray mode).
        private void ChatQueuedNotice(string num)
        {
            string disp = ChatLookupName(num);
            if (disp == null) disp = "#" + num;
            Log("Chat: " + disp + " is offline - message queued on the relay for delivery.", BrushWarn);
            Toast.Show("Message queued", disp + " is offline; it will be delivered when they reconnect.", null);
        }

        private void ChatOfflineNotice(string num)
        {
            string disp = ChatLookupName(num);
            if (disp == null) disp = "#" + num;
            Log("Chat: " + disp + " is offline (not stored).", BrushWarn);
            Toast.Show("Peer offline", disp + " is offline right now.", null);
        }

        private void ChatDeleteConversation()
        {
            try
            {
                string num = _chatOpenNum;
                if (num.Length >= 3)
                {
                    string path = ChatPathFor(num);
                    if (File.Exists(path)) File.Delete(path);
                }
                _chatMsgs.Clear();
                _chatUnread.Remove(_chatOpenNum);
                if (_chatPanel != null) _chatPanel.Children.Clear();
                ChatAddBubble("sys", "", "", "Conversation deleted.", false, null);
                ChatRefreshRecent();
                Log("Chat: conversation with #" + num + " deleted.", BrushGray);
            }
            catch (Exception ex) { Log("Chat delete error: " + ex.Message, BrushWarn); }
        }

        // Rebuild the "Recent" panel from the saved chat files, newest first.
        private void ChatRefreshRecent()
        {
            if (_lvChatRecent == null) return;
            try
            {
                if (!Directory.Exists(AppConfig.ChatsDir)) { _lvChatRecent.Items.Clear(); return; }
                List<ChatRecent> rows = new List<ChatRecent>();
                foreach (string f in Directory.GetFiles(AppConfig.ChatsDir, "chat_*.txt"))
                {
                    FileInfo fi = new FileInfo(f);
                    string num = fi.Name.Substring(5, fi.Name.Length - 9);   // chat_<num>.txt
                    string display = ChatLookupName(num);
                    if (display == null) display = "#" + num;
                    // unread badge is rendered in ToString; Display stays
                    // clean so clicking a row reopens the chat directly
                    int unread = _chatUnread.ContainsKey(num) ? _chatUnread[num] : 0;
                    string preview = "";
                    string[] lines = File.ReadAllLines(f);
                    if (lines.Length > 0)
                    {
                        string last = lines[lines.Length - 1];
                        string[] p = last.Split(new char[] { '|' }, 4);
                        preview = p.Length >= 4 ? ChatPreview(p[1], p[3]) : p[p.Length - 1];
                    }
                    rows.Add(new ChatRecent { Number = num, Display = display, Preview = preview, When = fi.LastWriteTime, Unread = unread });
                }
                rows.Sort(delegate(ChatRecent a, ChatRecent b) { return b.When.CompareTo(a.When); });
                _lvChatRecent.Items.Clear();
                foreach (ChatRecent cr in rows) _lvChatRecent.Items.Add(cr);
            }
            catch (Exception ex) { Log("Chat recent error: " + ex.Message, BrushWarn); }
        }

        // Peer typing indicator in the conversation header (auto-expiring).
        private void ChatShowPeerTyping(string from, bool on)
        {
            string num = SanitizeNumber(from);
            if (num != _chatOpenNum && num != ChatNumber()) return;
            if (on)
            {
                if (_chatPartner != null) _chatPartner.Text = "\u270D typing...";
                if (_peerTypTimer == null)
                {
                    _peerTypTimer = new System.Windows.Threading.DispatcherTimer { Interval = TimeSpan.FromSeconds(4) };
                    _peerTypTimer.Tick += delegate
                    {
                        _peerTypTimer.Stop();
                        _peerTyping = false;
                        UpdateChatPartner(_chatOpenNum);
                    };
                }
                _peerTyping = true;
                _peerTypTimer.Stop();
                _peerTypTimer.Start();
            }
            else if (_peerTyping)
            {
                _peerTyping = false;
                if (_peerTypTimer != null) _peerTypTimer.Stop();
                UpdateChatPartner(_chatOpenNum);
            }
        }

        // Throttled outbound typing indicator: one CTYP on the first keystroke
        // after an idle period, one "stop" pulse 2.5 s after the last keystroke.
        private void ChatTypingPulse()
        {
            if (_voip == null || _chatOpenNum.Length < 3) return;
            if (!_voip.ChatRelayReady) return;
            if (_chatTypTimer == null)
            {
                _chatTypTimer = new System.Windows.Threading.DispatcherTimer { Interval = TimeSpan.FromSeconds(2.5) };
                _chatTypTimer.Tick += delegate
                {
                    _chatTypTimer.Stop();
                    try { _voip.SendChatTyping(_chatOpenNum, false); } catch { }
                };
            }
            if (!_chatTypTimer.IsEnabled)
                try { _voip.SendChatTyping(_chatOpenNum, true); } catch { }
            _chatTypTimer.Stop();
            _chatTypTimer.Start();
        }

        private void ChatScrollEnd()
        {
            if (_chatScroll == null) return;
            // Force a layout pass first: new bubbles have no measured height
            // until then, so ScrollToEnd would clamp to the old extent.
            try
            {
                _chatScroll.UpdateLayout();
                _chatScroll.ScrollToEnd();
                _chatScroll.ScrollToVerticalOffset(_chatScroll.ScrollableHeight);
            }
            catch { }
            Dispatcher.BeginInvoke(new Action(delegate
            {
                try
                {
                    if (_chatScroll == null) return;
                    _chatScroll.UpdateLayout();
                    _chatScroll.ScrollToVerticalOffset(_chatScroll.ScrollableHeight);
                }
                catch { }
            }), System.Windows.Threading.DispatcherPriority.Loaded);
        }

        // Entry point for incoming chat text from VoipService (UI thread).
        private void ChatInbound(string from, string text)
        {
            // Intercept PRESENCE signals — not display in chat
            if (text != null && text.StartsWith("PRESENCE|"))
            {
                HandlePresenceMessage(from, text);
                return;
            }
            // Flush outbox when any message arrives (means peer is online)
            FlushOutbox();
            // mirror into the in-call chat panel whenever we are connected
            if (_voip != null && _voip.InCall && _lvVideoChat != null)
            {
                string stamp = DateTime.Now.ToString("HH:mm");
                _lvVideoChat.Items.Add(stamp + "  " + _voipPeerName + ": " + text);
                _lvVideoChat.ScrollIntoView(_lvVideoChat.Items[_lvVideoChat.Items.Count - 1]);
            }
            string num = SanitizeNumber(from);
            // ALWAYS write the file - even when this conversation is not the
            // open one (or none is open). A reply that lands while another
            // chat is open must still be in tomorrow's history.
            ChatPersist("in", num, text);
            if (num == _chatOpenNum || num == ChatNumber())
            {
                ChatScrollEnd();
                ChatMarkUnreadSeen();
                Toast.Show("Message from " + (_voipPeerName ?? ("#" + from)), text, null);
            }
            else
            {
                ChatBumpUnread(num);
                Log("Chat from #" + from + ": " + text + " (open chat to reply)", BrushAccent);
                string tgt = num;
                string dispName = ChatLookupName(num);
                string title = dispName != null ? dispName : ("#" + from);
                Toast.Show("Message from " + title, text, delegate
                {
                    GetTabByHeader("SMS");
                    if (_txtChatTo != null) _txtChatTo.Text = tgt;
                    ChatOpen();
                });
            }
        }

        private bool PrepareAttachmentMessage(string number, ref string text, out List<string> transferIds, out string error)
        {
            transferIds = new List<string>();
            error = null;
            MatchCollection matches = Regex.Matches(text ?? "", @"\[(IMAGE|FILE):([^\]\r\n]+)\]");
            if (matches.Count == 0) return true;
            if (matches.Count > 3)
            {
                error = "Send no more than three attachments in one message.";
                return false;
            }
            if (_voip == null || !_voip.ChatRelayReady || _voip.FindByNumber(number) == null)
            {
                error = "Secure attachments require the recipient to be online through the relay.";
                return false;
            }
            if (_voip.ChatSecurityState(number) != "locked")
            {
                error = "Send a text message first to establish the encrypted chat session, then retry the attachment.";
                return false;
            }

            StringBuilder updated = new StringBuilder();
            int offset = 0;
            foreach (Match match in matches)
            {
                string payload = match.Groups[2].Value;
                string filePath = payload;
                if (match.Groups[1].Value == "FILE")
                {
                    int separator = payload.IndexOf('|');
                    if (separator >= 0) filePath = payload.Substring(0, separator);
                }
                string id, name, failure;
                long size;
                if (!PrepareFileTransfer(number, filePath, out id, out name, out size, out failure))
                {
                    for (int i = 0; i < transferIds.Count; i++)
                    {
                        try { if (_voip != null) _voip.SendFileReject(number, transferIds[i]); }
                        catch (Exception ex) { Log("Could not cancel a partial file offer: " + ex.Message, BrushWarn); }
                        _transfers.Remove(transferIds[i]);
                    }
                    error = failure;
                    return false;
                }
                transferIds.Add(id);
                updated.Append(text.Substring(offset, match.Index - offset));
                updated.Append("[ATTACHMENT:");
                updated.Append(id);
                updated.Append("|");
                updated.Append(Convert.ToBase64String(Encoding.UTF8.GetBytes(SafeReceivedFileName(name))));
                updated.Append("|");
                updated.Append(size);
                updated.Append("]");
                offset = match.Index + match.Length;
            }
            updated.Append(text.Substring(offset));
            text = updated.ToString();
            return true;
        }

        private void CancelPreparedAttachments(string number, List<string> transferIds)
        {
            if (transferIds == null) return;
            foreach (string id in transferIds)
            {
                try { if (_voip != null) _voip.SendFileReject(number, id); }
                catch (Exception ex) { Log("Could not cancel file offer " + id + ": " + ex.Message, BrushWarn); }
                _transfers.Remove(id);
            }
        }

        private async Task ChatSendAsync()
        {
            if (_txtChatInput == null) return;
            string originalText = _txtChatInput.Text.Trim();
            string text = originalText;
            if (text.Length == 0) { Log("Chat: type a message.", BrushWarn); return; }
            string num = ChatNumber();
            if (num.Length < 3) { Log("Chat: enter a recipient number.", BrushWarn); return; }

            if (text.Length > 100000 && Regex.IsMatch(text, @"\[(IMAGE|FILE):[^\]\r\n]+\]"))
            {
                Log("Remove attachments or shorten the message below 100,000 characters before sending.", BrushWarn);
                return;
            }

            // ── 100k+ character compression ──────────────────────────────
            // Messages over 100,000 chars are saved to a .txt file and a
            // reference token is sent instead, keeping the chat protocol lean.
            if (text.Length > 100000)
            {
                try
                {
                    string dir = System.IO.Path.Combine(AppConfig.ChatsDir, "large");
                    System.IO.Directory.CreateDirectory(dir);
                    string fname = "msg_" + DateTime.Now.Ticks + ".txt";
                    string fpath = System.IO.Path.Combine(dir, fname);
                    System.IO.File.WriteAllText(fpath, text, System.Text.Encoding.UTF8);
                    long kb = text.Length / 1024;
                    text = "[LARGE_MSG:" + fpath + "|" + fname + "|" + kb + "KB — " + text.Length + " chars saved to file]";
                    Log("Message compressed to file: " + fname + " (" + kb + " KB)", BrushWarn);
                }
                catch (Exception ex)
                {
                    Log("Large-message compression failed: " + ex.Message, BrushError);
                    return;
                }
            }

            string realNum = ResolveChatNumber(_txtChatTo.Text);
            string target = realNum.Length >= 3 ? realNum : num;
            List<string> transferIds;
            string attachmentError;
            if (!PrepareAttachmentMessage(target, ref text, out transferIds, out attachmentError))
            {
                Log("Attachment not sent: " + attachmentError, BrushWarn);
                return;
            }
            bool hasAttachments = transferIds.Count > 0;
            _txtChatInput.Text = "";
            if (_hubCharCount != null) _hubCharCount.Text = "";

            // 1) saved-contact name typed? resolve it first
            if (realNum.Length >= 3 && realNum != num && _voip != null && _voip.RelayReady && _voip.SendChat(realNum, text))
            {
                Log("Chat sent to " + _txtChatTo.Text, BrushSuccess);
                ChatPersist("out", target, text);
                return;
            }

            // 2) registered peer with relay -> instant peer-to-peer chat
            if (_voip != null && _voip.RelayReady && _voip.SendChat(target, text))
            {
                Log("Chat sent to #" + target + " (relay)", BrushSuccess);
                HangTrace("chat: relay out -> #" + target);
                ChatPersist("out", target, text);
                return;
            }

            if (hasAttachments)
            {
                CancelPreparedAttachments(target, transferIds);
                _txtChatInput.Text = originalText;
                Log("Attachment not sent: the chat message could not be delivered.", BrushWarn);
                return;
            }

            // 3) Relay not ready or peer not found → queue for later delivery
            if (_voip != null && _voip.RelayReady)
            {
                // Relay is connected but peer is offline — queue for when they reconnect
                OutboxEnqueue(num, text);
                ChatPersist("out", num, "[queued] " + text);
                return;
            }

            // 3) SMS fallback through the modem
            _txtChatInput.Text = text;   // keep the text; we did not send it yet
            if (_modem.IsOpen)
            {
                Log("Chat -> SMS to " + num + " ...", BrushGray);
                _busy = true;
                try
                {
                    string[] r = await Task.Run(delegate { return _modem.SendSms(num, text, 60000); });
                    bool ok = false;
                    foreach (string l in r) if (Regex.IsMatch(l, @"(^|\s)OK(\s|$)")) ok = true;
                    if (ok)
                    {
                        _txtChatInput.Text = "";
                        Log("Chat SMS sent to " + num, BrushSuccess);
                        ChatPersist("out", num, text);
                    }
                    else Log("Chat SMS failed.", BrushError);
                }
                catch (Exception ex) { Log("Chat SMS error: " + ex.Message, BrushError); }
                finally { _busy = false; }
                return;
            }
            Log("Chat: no relay and no modem — message not sent.", BrushWarn);
        }

        private async Task RefreshInboxAsync()
        {
            if (!_modem.IsOpen) return;
            Log("Loading SMS inbox ...", BrushGray);
            await Task.Run(delegate
            {
                try
                {
                    string[] r = _modem.SendCommand("AT+CMGL=\"ALL\"", ModemService.OkTerm, 30000);
                    List<SmsMessage> msgs = ParseCmgl(r);
                    Dispatcher.BeginInvoke(new Action(delegate
                    {
                        _inbox.Clear();
                        foreach (SmsMessage m in msgs)
                        {
                            _inbox.Add(m);
                            ScanForCode(m);
                        }
                        RebuildInboxView();
                        RebuildCodesView();
                        Log("Inbox: " + msgs.Count + " message(s).", BrushGray);
                    }));
                }
                catch (Exception ex) { Log("Inbox error: " + ex.Message, BrushError); }
            });
        }

        private static List<SmsMessage> ParseCmgl(string[] lines)
        {
            List<SmsMessage> msgs = new List<SmsMessage>();
            SmsMessage cur = null;
            foreach (string raw in lines)
            {
                string line = raw.Trim();
                Match m = Regex.Match(line, "\\+CMGL:\\s*(\\d+)\\s*,\\s*\"([^\"]*)\"\\s*,\\s*\"([^\"]*)\"\\s*,[^,]*,\\s*\"([^\"]*)\"");
                if (m.Success)
                {
                    if (cur != null) msgs.Add(cur);
                    cur = new SmsMessage
                    {
                        Index = int.Parse(m.Groups[1].Value),
                        From = m.Groups[3].Value,
                        Time = m.Groups[4].Value
                    };
                }
                else if (cur != null && line.Length > 0 &&
                         !Regex.IsMatch(line, "^(OK|ERROR|\\+CMS|\\+CME)"))
                {
                    cur.Body = (cur.Body == null ? "" : cur.Body + "\n") + line;
                }
            }
            if (cur != null) msgs.Add(cur);
            return msgs;
        }

        private async Task ReadSmsAtAsync(int idx)
        {
            if (!_modem.IsOpen) return;
            await Task.Run(delegate
            {
                try
                {
                    string[] r = _modem.SendCommand("AT+CMGR=" + idx, ModemService.OkTerm, 15000);
                    SmsMessage msg = null;
                    foreach (string raw in r)
                    {
                        string line = raw.Trim();
                        Match m = Regex.Match(line, "\\+CMGR:\\s*\"([^\"]*)\"\\s*,\\s*\"([^\"]*)\"\\s*,[^,]*,\\s*\"([^\"]*)\"");
                        if (m.Success)
                        {
                            msg = new SmsMessage { Index = idx, From = m.Groups[2].Value, Time = m.Groups[3].Value };
                        }
                        else if (msg != null && line.Length > 0 && !Regex.IsMatch(line, "^(OK|ERROR|\\+CMS|\\+CME)"))
                        {
                            msg.Body = (msg.Body == null ? "" : msg.Body + "\n") + line;
                        }
                    }
                    if (msg != null && msg.Body != null)
                    {
                        Dispatcher.BeginInvoke(new Action(delegate
                        {
                            _inbox.Insert(0, msg);
                            ScanForCode(msg);
                            RebuildInboxView();
                            RebuildCodesView();
                            Log("SMS from " + msg.From + ": " + msg.Body, BrushSuccess);
                            // mirror into the open chat conversation
                            string fnum = SanitizeNumber(msg.From);
                            if (fnum.Length > 0 && fnum == ChatNumber())
                            {
                                foreach (string part in msg.Body.Split('\n'))
                                    if (part.Trim().Length > 0) ChatPersist("in", fnum, part.Trim());
                                Toast.Show("SMS from " + msg.From, msg.Body, null);
                            }
                            else
                            {
                                string tgt = fnum;
                                Toast.Show("SMS from " + msg.From, msg.Body, delegate
                                {
                                    GetTabByHeader("SMS");
                                    if (_txtChatTo != null) _txtChatTo.Text = tgt;
                                    ChatOpen();
                                });
                            }
                        }));
                    }
                }
                catch (Exception ex) { Log("Read SMS error: " + ex.Message, BrushError); }
            });
        }

        private void ScanForCode(SmsMessage m)
        {
            if (m == null || m.Body == null) return;
            MatchCollection ms = Regex.Matches(m.Body, @"(?<!\d)\d{4,8}(?!\d)");
            if (ms.Count == 0) return;
            string code = ms[0].Value;
            foreach (SmsCode c in _codes)
                if (c.Code == code && c.From == m.From) return;
            SmsCode sc = new SmsCode { Time = m.Time, From = m.From, Code = code };
            _codes.Insert(0, sc);
            while (_codes.Count > 100) _codes.RemoveAt(_codes.Count - 1);
            Log("Verification code detected: " + code + " (from " + m.From + ")", BrushWarn);

            // Update unread badge on the Codes category button
            if (_hubUnreadCodes != null)
            {
                int cnt = _codes.Count;
                _hubUnreadCodes.Text = cnt > 9 ? "9+" : cnt.ToString();
                _hubUnreadCodes.Visibility = Visibility.Visible;
            }
            // Show the OTP floating banner
            if (_hubOtpCode != null && _hubOtpFrom != null)
            {
                _hubOtpCode.Text = code;
                _hubOtpFrom.Text = "OTP from " + m.From;
                // Make the banner visible by finding it through the parent tree.
                // The banner is row 0 of the root SMS tab grid (_smsGrid).
                if (_smsGrid != null && _smsGrid.Children.Count > 0)
                {
                    Border banner = _smsGrid.Children[0] as Border;
                    if (banner != null)
                    {
                        banner.Visibility = Visibility.Visible;
                        // Start expiry countdown (4 min 59 sec)
                        _hubOtpSecsLeft = 299;
                        if (_hubOtpTimer == null)
                        {
                            _hubOtpTimer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(1) };
                            _hubOtpTimer.Tick += delegate
                            {
                                _hubOtpSecsLeft--;
                                if (_hubOtpExpiry != null)
                                    _hubOtpExpiry.Text = "Expires in " + (_hubOtpSecsLeft / 60).ToString("00") + ":" + (_hubOtpSecsLeft % 60).ToString("00");
                                if (_hubOtpSecsLeft <= 0)
                                {
                                    _hubOtpTimer.Stop();
                                    if (banner != null) banner.Visibility = Visibility.Collapsed;
                                }
                            };
                        }
                        _hubOtpTimer.Stop();
                        _hubOtpTimer.Start();
                    }
                }
            }
            // Refresh pane 2 if on codes category
            if (_chatHubCategory == "codes") HubRefreshPane2();
        }

        private void RebuildInboxView()
        {
            _lvInbox.Items.Clear();
            foreach (SmsMessage m in _inbox) _lvInbox.Items.Add(m);
        }

        private void RebuildCodesView()
        {
            _lvCodes.Items.Clear();
            foreach (SmsCode c in _codes) _lvCodes.Items.Add(c);
        }

        private async Task DeleteSelectedSmsAsync()
        {
            SmsMessage m = _lvInbox.SelectedItem as SmsMessage;
            if (m == null) { Log("Select a message.", BrushWarn); return; }
            if (!_modem.IsOpen) return;
            await Task.Run(delegate
            {
                try { _modem.SendCommand("AT+CMGD=" + m.Index, ModemService.OkTerm, 10000); }
                catch (Exception ex) { Log("Delete error: " + ex.Message, BrushError); }
            });
            _inbox.Remove(m);
            RebuildInboxView();
            Log("SMS deleted (index " + m.Index + ").", BrushGray);
        }

        private async Task DeleteAllSmsAsync()
        {
            if (!_modem.IsOpen) return;
            Log("Deleting all SMS ...", BrushAccent);
            await Task.Run(delegate
            {
                try { _modem.SendCommand("AT+CMGD=1,4", ModemService.OkTerm, 20000); }
                catch (Exception ex) { Log("Delete all error: " + ex.Message, BrushError); }
            });
            _inbox.Clear();
            RebuildInboxView();
            Log("All SMS deleted.", BrushGray);
        }

        // ---------- SIM manager ----------
        private async Task RefreshSimInfoAsync(bool quiet)
        {
            if (!_modem.IsOpen) return;
            if (_opsRunning && quiet) return;
            _opsRunning = true;
            try
            {
                SimSnapshot snap = await Task.Run(delegate { return QuerySimSnapshot(); });
                DispatcherOperation op = Dispatcher.BeginInvoke(new Action(delegate { ApplySimSnapshot(snap, quiet); }));
            }
            catch (Exception ex) { if (!quiet) Log("SIM refresh error: " + ex.Message, BrushError); }
            finally { _opsRunning = false; }
        }

        private class SimSnapshot
        {
            public string Pin;
            public string Iccid;
            public string Imsi;
            public string Imei;
            public string Operator;
            public int Rssi;
            public string Reg;
            public string Battery;
            public string Phonebook;
            public string SimType;
            public string Carrier;
            public string Country;
            public string Slot;
            public string SimFault;
            public bool SimPresent;
            // Usable for a call right now: CPIN said READY.
            public bool PinReady;
        }

        // The last SIM reading, kept so dialling can decide a route instantly.
        // Querying AT+CPIN at the moment of the call costs seconds and the user
        // would feel it as a dead button.
        private SimSnapshot _simSnap;

        private SimSnapshot QuerySimSnapshot()
        {
            SimSnapshot s = new SimSnapshot();

            // --- SIM slot reader: type, carrier, presence, ICCID/IMSI/IMEI ---
            try
            {
                SimSlotReader.SimCardInfo card = SimSlotReader.Read(_modem);
                s.Pin = card.PinStatus;
                s.Iccid = card.Iccid;
                s.Imsi = card.Imsi;
                s.Imei = card.Imei;
                s.SimType = card.SimType;
                s.Carrier = card.Carrier;
                s.Country = card.Country;
                s.SimPresent = card.Present;
                s.SimFault = card.Fault;
                // The one thing the dialler needs to know: can this SIM place a
                // call right now, or is it PIN/PUK locked or faulty.
                s.PinReady = card.Ready ||
                    (card.PinStatus != null && card.PinStatus.IndexOf("READY", StringComparison.OrdinalIgnoreCase) >= 0);
                s.Slot = card.Present
                    ? "occupied (" + (card.FormFactor ?? "unknown size") + ")"
                    : (card.Fault != null ? "FAULT: " + card.Fault : "empty (no SIM inserted)");
            }
            catch (Exception ex)
            {
                s.Slot = "reader error: " + ex.Message;
            }

            // --- network / modem side ---
            string cops = string.Join(" | ", _modem.SendCommand("AT+COPS?", ModemService.OkTerm, 15000));
            Match mc = Regex.Match(cops, "\"([^\"]+)\"");
            if (mc.Success) s.Operator = mc.Groups[1].Value;
            else if (!string.IsNullOrEmpty(s.Carrier)) s.Operator = s.Carrier;

            s.Rssi = ParseRssi(string.Join(" | ", _modem.SendCommand("AT+CSQ", ModemService.OkTerm, 8000)));
            string creg = string.Join(" | ", _modem.SendCommand("AT+CREG?", ModemService.OkTerm, 8000));
            Match mr = Regex.Match(creg, @"\+CREG:\s*\d+\s*,\s*(\d+)");
            if (mr.Success)
            {
                switch (mr.Groups[1].Value)
                {
                    case "0": s.Reg = "Not registered"; break;
                    case "1": s.Reg = "Registered (home)"; break;
                    case "2": s.Reg = "Searching..."; break;
                    case "3": s.Reg = "Denied"; break;
                    case "4": s.Reg = "Emergency only"; break;
                    case "5": s.Reg = "Registered (roaming)"; break;
                    default: s.Reg = "Unknown (" + mr.Groups[1].Value + ")"; break;
                }
            }
            string cbc = string.Join(" | ", _modem.SendCommand("AT+CBC", ModemService.OkTerm, 8000));
            Match mb = Regex.Match(cbc, @"\+CBC:\s*(\d+)\s*,\s*(\d+)\s*,\s*(\d+)");
            if (mb.Success)
            {
                int pct = int.Parse(mb.Groups[3].Value);
                int chg = int.Parse(mb.Groups[1].Value);
                s.Battery = pct + "%" + (chg == 1 ? " (charging)" : "");
            }
            string cpbs = string.Join(" | ", _modem.SendCommand("AT+CPBS?", ModemService.OkTerm, 8000));
            Match mp = Regex.Match(cpbs, "\\+CPBS:\\s*\"([^\"]*)\"\\s*,\\s*(\\d+)\\s*,\\s*(\\d+)");
            if (mp.Success) s.Phonebook = mp.Groups[1].Value + " - " + mp.Groups[2].Value + "/" + mp.Groups[3].Value + " used";
            return s;
        }

        private static string FirstData(string s)
        {
            if (s == null) return null;
            s = s.Trim();
            return s.Length == 0 ? null : s;
        }

        private void ApplySimSnapshot(SimSnapshot s, bool quiet)
        {
            _simSnap = s;   // read by CallRouter when a call is placed
            if (_valPin != null) _valPin.Text = s.Pin ?? "unknown";
            if (_valIccid != null) _valIccid.Text = s.Iccid ?? "not detected";
            if (_valImsi != null) _valImsi.Text = s.Imsi ?? "not detected";
            if (_valImei != null) _valImei.Text = s.Imei ?? "not detected";
            if (_valOp != null) _valOp.Text = s.Operator ?? "unknown";
            if (_valReg != null) _valReg.Text = s.Reg ?? "unknown";
            if (_valBatt != null) _valBatt.Text = s.Battery ?? "unknown";
            if (_valPhonebook != null) _valPhonebook.Text = s.Phonebook ?? "unknown";
            if (_valSimType != null) _valSimType.Text = s.SimType ?? "unknown";
            if (_valCarrier != null) _valCarrier.Text = (s.Carrier ?? "unknown") + (string.IsNullOrEmpty(s.Country) ? "" : " (" + s.Country + ")");
            if (_valSlot != null) _valSlot.Text = s.Slot ?? "unknown";
            UpdateSignalUi(s.Rssi);

            // Map SIM to a USSD preset group (Ghana carriers) for "Auto (from SIM)".
            string carrierName = (s.Carrier ?? "") + " " + (s.Operator ?? "");
            carrierName = carrierName.ToUpperInvariant();
            string key = null;
            if (carrierName.Contains("MTN")) key = "MTN";
            else if (carrierName.Contains("TELECEL") || carrierName.Contains("VODAFONE")) key = "Telecel";
            else if (carrierName.Contains("AIRTEL") || carrierName.Contains("TIGO") || carrierName.Contains("AT ")) key = "AirtelTigo";
            else if (carrierName.Contains("GLO")) key = "Glo";
            if (key != null && key != _simCarrierKey)
            {
                _simCarrierKey = key;
                if (!quiet) Log("USSD presets auto-set to " + key + " (from SIM).", BrushSuccess);
                RebuildPresetChips();
            }

            string summary;
            if (!s.SimPresent && s.SimFault != null)
                summary = "SIM READER FAULT - see slot field";
            else if (!s.SimPresent)
                summary = "SIM slot empty";
            else
                summary = (s.Carrier ?? s.Operator ?? "?") + "  |  " + (s.SimType ?? "SIM") +
                          (s.Iccid != null ? "  |  ..." + s.Iccid.Substring(Math.Max(0, s.Iccid.Length - 4)) : "");
            SetSimSummary(summary);
            _sbCarrier.Text = "carrier: " + (s.Carrier ?? s.Operator ?? "-");

            if (!quiet)
                Log("SIM slot: " + (s.Slot ?? "?") + " type=" + (s.SimType ?? "?") +
                    " carrier=" + (s.Carrier ?? "-") + " iccid=" + (s.Iccid ?? "-") +
                    " imsi=" + (s.Imsi ?? "-") + " op=" + (s.Operator ?? "-") + " reg=" + (s.Reg ?? "-"), BrushAccent);

            if (!quiet && s.SimFault != null)
                Log("HARDWARE: " + s.SimFault, Brushes.OrangeRed);

            string iccid = s.Iccid;
            if (!string.IsNullOrEmpty(iccid) && _prevIccid == null)
            {
                _prevIccid = iccid;
                Log("SIM detected: " + (s.SimType ?? "SIM") + " " + iccid +
                    (string.IsNullOrEmpty(s.Carrier) ? "" : " (" + s.Carrier + ")") +
                    (string.IsNullOrEmpty(s.Operator) ? "" : " / " + s.Operator), BrushSuccess);
            }
            else if (!string.IsNullOrEmpty(iccid) && _prevIccid != null && iccid != _prevIccid)
            {
                Log("SIM CHANGED (" + _prevIccid + " -> " + iccid + ") - re-configuring modem...", BrushWarn);
                _prevIccid = iccid;
                var t = ReconfigureModemAsync();
            }
            else if (string.IsNullOrEmpty(iccid) && _prevIccid != null)
            {
                Log("SIM removed from slot.", BrushWarn);
                _prevIccid = null;
            }
        }

        private async Task ReconfigureModemAsync()
        {
            if (!_modem.IsOpen) { Log("Not connected.", BrushError); return; }
            Log("Re-configuring modem (SMS mode, notifications, caller ID)...", BrushAccent);
            await Task.Run(delegate
            {
                try
                {
                    string[] res = _modem.Init();
                    foreach (string r in res) Log(r, BrushGray);
                    Log("Modem re-configured.", BrushSuccess);
                }
                catch (Exception ex) { Log("Reconfigure error: " + ex.Message, BrushError); }
            });
            await RefreshSimInfoAsync(true);
        }

        // ---------- USSD ----------
        private string _mifiProbeIp = null;

        private string EnsureMifiProbe(string ip)
        {
            if (_mifiProbe != null && (DateTime.Now - _mifiProbeTime).TotalSeconds < 120 &&
                _mifiProbeIp == ip)
                return _mifiProbe;
            _mifiProbe = MifiApi.Probe(ip);
            _mifiProbeTime = DateTime.Now;
            _mifiProbeIp = ip;
            return _mifiProbe;
        }

        private async Task SendUssdAsync()
        {
            if (_busy) { Log("Busy - please wait...", BrushWarn); return; }
            string code = _txtCode.Text.Trim();
            if (code.Length == 0) { Log("Enter a USSD code.", BrushWarn); return; }
            bool serial = _radioSerial.IsChecked == true;

            // Auto-fallback: if Method 1 is selected but the MiFi firmware has no
            // USSD command, route to the USB modem instead of spamming 404s.
            string fallbackNote = null;
            if (!serial)
            {
                string ip = _txtMifiIp.Text;
                string probe = await Task.Run(delegate { return EnsureMifiProbe(ip); });
                if (probe != "huawei-goform")
                {
                    serial = true;
                    fallbackNote = "MiFi web API has no USSD command" +
                        (probe == "himi-spa" ? " (Himi-spa firmware)" : " (" + probe + ")") +
                        " - auto-fallback to USB modem.";
                }
            }

            _busy = true;
            try
            {
                if (serial)
                {
                    if (fallbackNote != null) Log(fallbackNote, BrushWarn);
                    if (!_modem.IsOpen)
                    {
                        Log("Connect the modem first (Connect bar) - USSD needs the USB AT port.", BrushError);
                        return;
                    }
                    Log("Sending USSD " + code + " via modem ...", BrushAccent);
                    string result = await Task.Run(delegate
                    {
                        string[] r = _modem.SendCommand("AT+CUSD=1,\"" + code + "\",15",
                            "^(OK|ERROR|\\+CME ERROR|\\+CUSD)", 35000);
                        return string.Join("\n", r);
                    });
                    string parsed = SerialUssd.ExtractUssdText(result);
                    ShowUssdResponse(code, parsed, result);
                    Log("USSD response: " + parsed, BrushSuccess);
                    SetStatus("USSD done", BrushSuccess);
                }
                else
                {
                    string ip = _txtMifiIp.Text;
                    Log("Sending USSD " + code + " via MiFi " + ip + " ...", BrushAccent);
                    string result = await Task.Run(delegate { return MifiApi.Session(ip, code, null); });
                    ShowUssdResponse(code, result, result);
                    Log("USSD response: " + result, BrushSuccess);
                    SetStatus("USSD done (MiFi)", BrushSuccess);
                }
            }
            catch (WebException wex)
            {
                string msg = wex.Message;
                if (wex.Response != null) msg += " [" + (int)((HttpWebResponse)wex.Response).StatusCode + "]";
                Log("Network error: " + msg, BrushError);
            }
            catch (Exception ex) { Log("USSD error: " + ex.Message, BrushError); }
            finally { _busy = false; }
        }

        // ---------- State ----------
        private AppConfig _cfg;          // persisted config (identity never CLI-overridden)
        private string _myNumber;        // effective virtual number for this session

        // ---------- Settings dialog (gear in the header) ----------
        private void ShowSettingsDialog()
        {
            Window w = new Window
            {
                Title = "Settings — USSD Manager Pro",
                Width = 520,
                Height = 680,
                ResizeMode = ResizeMode.CanResize,
                MinWidth = 480,
                MinHeight = 520,
                WindowStartupLocation = WindowStartupLocation.CenterOwner,
                Owner = this,
                Background = Theme.Bg
            };

            // ── Tab control ───────────────────────────────────────────────
            TabControl tabs = new TabControl
            {
                Background = Theme.Card,
                BorderThickness = new Thickness(0),
                Margin = new Thickness(14)
            };

            // ── Tab 1: Identity & Network ──────────────────────────────────
            StackPanel t1 = new StackPanel { Margin = new Thickness(16, 12, 16, 12) };
            t1.Children.Add(new TextBlock { Text = "Identity & Network", FontSize = 15, FontWeight = FontWeights.Bold, Foreground = BrushFg, Margin = new Thickness(0, 0, 0, 12) });

            t1.Children.Add(MakeKey("DISPLAY NAME"));
            TextBox nameBox = MakeTextBox(0); nameBox.Text = _cfg != null ? _cfg.display_name : ""; nameBox.Margin = new Thickness(0, 2, 0, 10);
            t1.Children.Add(nameBox);

            t1.Children.Add(MakeKey("MY APP NUMBER (read-only)"));
            TextBox numBox = MakeTextBox(0); numBox.IsReadOnly = true; numBox.Text = AppNum.Format(_myNumber); numBox.Margin = new Thickness(0, 2, 0, 10);
            t1.Children.Add(numBox);

            t1.Children.Add(MakeKey("THEME"));
            ComboBox themeBox = new ComboBox { Margin = new Thickness(0, 2, 0, 10) };
            themeBox.Items.Add("Light"); themeBox.Items.Add("Dark");
            themeBox.SelectedIndex = (Theme.Current == "dark") ? 1 : 0;
            t1.Children.Add(themeBox);

            t1.Children.Add(MakeKey("RELAY / CALL SERVER  (host:port)"));
            TextBox relayBox = MakeTextBox(0); relayBox.Text = _cfg != null ? _cfg.relay_server : ""; relayBox.Margin = new Thickness(0, 2, 0, 10);
            t1.Children.Add(relayBox);

            t1.Children.Add(MakeKey("STUN SERVERS  (comma-separated)"));
            TextBox stunBox = MakeTextBox(0); stunBox.Text = _cfg != null ? _cfg.stun_servers : ""; stunBox.Margin = new Thickness(0, 2, 0, 10);
            t1.Children.Add(stunBox);

            // Identity key fingerprint + reset option (for when identity.key is lost)
            t1.Children.Add(MakeKey("IDENTITY KEY FINGERPRINT"));
            TextBlock fpLabel = new TextBlock
            {
                Text = _voip != null ? (_voip.MyFingerprint ?? "(not loaded)") : "(VoIP not started)",
                FontSize = 11, Foreground = BrushGray, TextWrapping = TextWrapping.Wrap,
                Margin = new Thickness(0, 2, 0, 4)
            };
            t1.Children.Add(fpLabel);
            Button btnResetId = MakeButton("Reset identity key (lost key recovery)");
            btnResetId.Margin = new Thickness(0, 0, 0, 10);
            btnResetId.Click += delegate { ShowIdentityRecovery(); };
            t1.Children.Add(btnResetId);

            // Connection card — one click to get a shareable invite
            t1.Children.Add(MakeKey("CONNECTION CARD — SHARE WITH YOUR MATE"));
            t1.Children.Add(new TextBlock
            {
                Text = "Copies everything your mate needs: relay address, fingerprint, your number. "
                     + "They paste the SEED LINE into their relays.seed and can call you immediately.",
                FontSize = 11, Foreground = BrushGray, TextWrapping = TextWrapping.Wrap,
                Margin = new Thickness(0, 0, 0, 6)
            });
            TextBox cardBox = new TextBox
            {
                IsReadOnly = true, TextWrapping = TextWrapping.Wrap,
                FontSize = 11, Foreground = BrushGray,
                Background = Theme.Card, BorderBrush = Theme.CardBorder, BorderThickness = new Thickness(1),
                Padding = new Thickness(8, 6, 8, 6), MaxHeight = 140,
                Margin = new Thickness(0, 0, 0, 6),
                VerticalScrollBarVisibility = ScrollBarVisibility.Auto
            };
            t1.Children.Add(cardBox);
            Button btnCard = MakeButton("Generate & Copy Connection Card");
            btnCard.Margin = new Thickness(0, 0, 0, 10);
            btnCard.Click += delegate
            {
                try
                {
                    string seedLine = "";
                    if (_callServer != null)
                    {
                        string adv = _callServer.AdvertiseAddress();
                        string fp2 = _voip != null ? (_voip.MyFingerprint ?? "-") : "-";
                        if (!string.IsNullOrEmpty(adv)) seedLine = adv + "|" + fp2;
                    }
                    string fp = _voip != null ? _voip.MyFingerprint : "";
                    string card = ConnectionHelper.MakeConnectCard(AppNum.Format(_myNumber), seedLine, fp);
                    cardBox.Text = card;
                    try { Clipboard.SetText(card); } catch { }
                    Log("Connection card copied to clipboard — send it to your mate!", BrushSuccess);
                    ConnectionHelper.EnsureFirewallRule(CallServer.DEFAULT_PORT);
                }
                catch (Exception ex) { Log("Card: " + ex.Message, BrushError); }
            };
            t1.Children.Add(btnCard);

            tabs.Items.Add(new TabItem { Header = "Identity & Network", Content = new ScrollViewer { Content = t1, VerticalScrollBarVisibility = ScrollBarVisibility.Auto } });

            // ── Tab: Relay & mesh (federation) ────────────────────
            // This is the "any peer can be a relay, nobody has to be" control
            // panel. It is on its own tab because carrying other people's
            // traffic is a decision, not a network detail.
            StackPanel tNet = new StackPanel { Margin = new Thickness(16, 12, 16, 12) };
            tNet.Children.Add(new TextBlock { Text = "Relay & mesh", FontSize = 15, FontWeight = FontWeights.Bold,
                Foreground = BrushFg, Margin = new Thickness(0, 0, 0, 6) });
            TextBlock fedStatus = new TextBlock
            {
                Text = FederationStatusLine(),
                FontSize = 11, Foreground = BrushGray, TextWrapping = TextWrapping.Wrap,
                Margin = new Thickness(0, 0, 0, 10)
            };
            tNet.Children.Add(fedStatus);
            tNet.Children.Add(new TextBlock
            {
                Text = "Linking two relays merges their directories, so a peer on somebody else's PC " +
                       "becomes reachable. The relay you register with is always yours to use; this " +
                       "page is only about whether YOU carry traffic for OTHER relays.",
                FontSize = 11, Foreground = BrushGray, TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 0, 0, 10)
            });
            CheckBox tlsRelay = new CheckBox
            {
                Content = "Require authenticated TLS 1.2 for this hosted relay",
                Foreground = BrushFg, FontSize = 12,
                IsChecked = _cfg != null && _cfg.relay_tls,
                Margin = new Thickness(0, 0, 0, 4)
            };
            tNet.Children.Add(tlsRelay);
            tNet.Children.Add(new TextBlock
            {
                Text = "Requires a trusted, hostname-matching relay_tls.pfx in the profile and " +
                       "USSD_RELAY_TLS_PFX_PASSWORD in the app environment. Changing this restarts " +
                       "the relay and reconnects its clients and links. Remote endpoints must use tls://.",
                FontSize = 11, Foreground = BrushGray, TextWrapping = TextWrapping.Wrap,
                Margin = new Thickness(0, 0, 0, 10)
            });
            tNet.Children.Add(MakeKey("CARRY TRAFFIC FOR OTHER RELAYS"));
            ComboBox polBox = new ComboBox { Margin = new Thickness(0, 2, 0, 8) };
            polBox.Items.Add("nobody  -  only serve my own clients");
            polBox.Items.Add("allowed  -  only relays on my list");
            polBox.Items.Add("everyone  -  link to anyone who asks");
            string curPol = _cfg != null ? _cfg.relay_policy : "allowed";
            polBox.SelectedIndex = curPol == "nobody" ? 0 : (curPol == "everyone" ? 2 : 1);
            tNet.Children.Add(polBox);
            tNet.Children.Add(MakeKey("RELAYS TO LINK TO  (host:port, comma separated)"));
            TextBox peersBox = MakeTextBox(0); peersBox.Margin = new Thickness(0, 2, 0, 8);
            peersBox.Text = _cfg != null ? _cfg.relay_peers : "";
            tNet.Children.Add(peersBox);
            tNet.Children.Add(MakeKey("ADVERTISE ME AS  (the address others dial; empty = guess this PC's LAN IP)"));
            TextBox advBox = MakeTextBox(0); advBox.Margin = new Thickness(0, 2, 0, 8);
            advBox.Text = _cfg != null ? _cfg.relay_advertise : "";
            tNet.Children.Add(advBox);
            CheckBox autoLink = new CheckBox
            {
                Content = "Link relays I discover (LAN probes and referrals)",
                Foreground = BrushFg, FontSize = 12,
                IsChecked = _cfg != null && _cfg.relay_autolink,
                Margin = new Thickness(0, 0, 0, 4)
            };
            tNet.Children.Add(autoLink);
            CheckBox autoMesh = new CheckBox
            {
                Content = "Self-forming mesh: dial relays a link tells me about",
                Foreground = BrushFg, FontSize = 12,
                IsChecked = _cfg != null && _cfg.relay_automesh,
                Margin = new Thickness(0, 0, 0, 4)
            };
            tNet.Children.Add(autoMesh);
            tNet.Children.Add(new TextBlock
            {
                Text = "With the mesh option on, two people who each linked to one common relay find " +
                       "each other automatically. It commits YOUR PC to carrying for whoever is out " +
                       "there, so it stays off until you choose it - and it can never make anyone " +
                       "else carry for you, because they still approve the inbound link.",
                FontSize = 11, Foreground = BrushGray, TextWrapping = TextWrapping.Wrap,
                Margin = new Thickness(0, 0, 0, 6)
            });
            tNet.Children.Add(MakeKey("HIDE THE PAIR FROM HOPS IN BETWEEN"));
            ComboBox onionBox = new ComboBox { Margin = new Thickness(0, 2, 0, 6) };
            onionBox.Items.Add("off  -  every relay on the route sees sender and target");
            onionBox.Items.Add("best  -  wrap it in layers when the keys are known, else forward plainly");
            onionBox.Items.Add("force  -  refuse the message rather than let a hop see the pair");
            string onionMode = CallServer.NormalizeOnion(_cfg != null ? _cfg.relay_onion : "off");
            onionBox.SelectedIndex = onionMode == "force" ? 2 : (onionMode == "best" ? 1 : 0);
            tNet.Children.Add(onionBox);
            tNet.Children.Add(new TextBlock
            {
                Text = "A relay has to route the message, so it always learns who sent it and who it is " +
                       "for - and with more than one relay in the chain, the middle one learns both too. " +
                       "Layering seals each hop's instruction to that hop alone, so an intermediate sees " +
                       "only the next hop. It costs about a kilobyte per hop per message, the first and " +
                       "last relays still see the pair, relay keys are trusted on first use exactly like " +
                       "peer keys are, and calls are not layered at all - the envelope would double a " +
                       "call's bandwidth. Only the relay that starts the message needs this switched on. " +
                       "It also hides nothing from the relay you chose yourself: for that you would need " +
                       "a route that starts somewhere else, which this app does not pretend to offer.",
                FontSize = 11, Foreground = BrushGray, TextWrapping = TextWrapping.Wrap,
                Margin = new Thickness(0, 0, 0, 6)
            });
            CheckBox carryMail = new CheckBox
            {
                Content = "Carry offline mail for other relays (store-and-forward)",
                Foreground = BrushFg, FontSize = 12,
                IsChecked = _cfg != null && _cfg.relay_carry_mail,
                Margin = new Thickness(0, 0, 0, 4)
            };
            tNet.Children.Add(carryMail);
            tNet.Children.Add(new TextBlock
            {
                Text = "Without this, a message to somebody who is off-line waits on ONE machine: \n" +
                       "*their* relay. If that PC is switched off, or they next connect somewhere else,\n" +
                       "the message never arrives. With it, your relay keeps a copy and hands it to\n" +
                       "the relays it is linked to, so it is waiting on whichever one they reach next.\n" +
                       "Only SEALED messages are handed on: mail for a recipient you have never had a\n" +
                       "session with is still plaintext, and plaintext is never spread to machines the\n" +
                       "sender did not choose. It spends YOUR disk and uplink on strangers' traffic, so\n" +
                       "it is off until you tick it, and it stays bounded: two hops, one week, 2000\n" +
                       "messages, and the queue cap below. Anything stored here is read back after a\n" +
                       "restart, so closing the lid no longer deletes what people left for you.",
                FontSize = 11, Foreground = BrushGray, TextWrapping = TextWrapping.Wrap,
                Margin = new Thickness(0, 0, 0, 6)
            });
            tNet.Children.Add(MakeKey("RELAYS THIS NODE HAS MET (kept across restarts)"));
            _relayLedgerList = new TextBlock
            {
                Text = "none yet",
                FontSize = 11, Foreground = BrushGray, TextWrapping = TextWrapping.Wrap,
                Margin = new Thickness(0, 2, 0, 8)
            };
            tNet.Children.Add(_relayLedgerList);
            RefreshLedgerView();
            StackPanel discRow = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 0, 0, 6) };
            Button btnDisc = MakeButton("Discover relays now");
            btnDisc.Click += delegate
            {
                if (_voip == null) { Log("VoIP service not running.", BrushWarn); return; }
                try { _voip.DiscoverRelays(); Log("Asking the LAN and my relay what other relays exist...", BrushGray); }
                catch (Exception ex) { Log("Discovery failed: " + ex.Message, BrushWarn); }
            };
            discRow.Children.Add(btnDisc);
            Button btnAddAll = MakeButton("Link all discovered");
            btnAddAll.Margin = new Thickness(8, 0, 0, 0);
            btnAddAll.Click += delegate
            {
                int n = _foundRelays.Count;
                foreach (string e in _foundRelays) AddRelayLink(e);
                Log(n == 0 ? "Nothing discovered yet." : "Linked " + n + " discovered relay(s).", n == 0 ? BrushWarn : BrushSuccess);
            };
            discRow.Children.Add(btnAddAll);
            tNet.Children.Add(discRow);
            tNet.Children.Add(MakeKey("DISCOVERED, NOT YET TRUSTED"));
            _relayFoundList = new TextBlock
            {
                Text = _foundRelays.Count == 0 ? "nothing yet" : string.Join("\n", _foundRelays.ToArray()),
                FontSize = 11, Foreground = BrushGray, TextWrapping = TextWrapping.Wrap,
                Margin = new Thickness(0, 2, 0, 8)
            };
            tNet.Children.Add(_relayFoundList);
            tNet.Children.Add(MakeKey("ALLOWED TO LINK TO ME  (hosts, host:port or relay names)"));
            TextBox allowBox = MakeTextBox(0); allowBox.Margin = new Thickness(0, 2, 0, 8);
            allowBox.Text = _cfg != null ? _cfg.relay_allow : "";
            tNet.Children.Add(allowBox);
            tNet.Children.Add(MakeKey("QUEUE SPACE FOR OTHER RELAYS' MAIL  (KB)"));
            TextBox storeBox = MakeTextBox(0); storeBox.Margin = new Thickness(0, 2, 0, 8);
            storeBox.Text = (_cfg != null ? _cfg.relay_store_kb : 2048).ToString();
            tNet.Children.Add(storeBox);
            tNet.Children.Add(MakeKey("BANDWIDTH CAP  (KB/s, 0 = uncapped)"));
            TextBox bwBox = MakeTextBox(0); bwBox.Margin = new Thickness(0, 2, 0, 10);
            bwBox.Text = (_cfg != null ? _cfg.relay_bandwidth_kbps : 0).ToString();
            tNet.Children.Add(bwBox);

            tNet.Children.Add(new Separator { Margin = new Thickness(0, 8, 0, 8) });
            tNet.Children.Add(new TextBlock
            {
                Text = "Radio link (KISS: LoRa RNode, TNC, Reticulum modem)",
                FontSize = 12, FontWeight = FontWeights.SemiBold, Foreground = BrushGray, Margin = new Thickness(0, 0, 0, 6)
            });
            tNet.Children.Add(new TextBlock
            {
                Text = "Text, presence and OTP codes over the air - no cell tower, no ISP, no cost per message. " +
                       "Voice cannot fit: a call needs ~64-256 kbit/s and these links do a few hundred. " +
                       "Needs hardware you already own, and it has not been tested on the air from here.",
                FontSize = 11, Foreground = BrushGray, TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 0, 0, 6)
            });
            tNet.Children.Add(MakeKey("KISS MODEM PORT  (blank = no radio, e.g. COM7)"));
            TextBox radioPortBox = MakeTextBox(0); radioPortBox.Margin = new Thickness(0, 2, 0, 8);
            radioPortBox.Text = _cfg != null ? _cfg.radio_port : "";
            tNet.Children.Add(radioPortBox);
            tNet.Children.Add(MakeKey("MY CALLSIGN  (blank = derived from my app number)"));
            TextBox radioCallBox = MakeTextBox(0); radioCallBox.Margin = new Thickness(0, 2, 0, 8);
            radioCallBox.Text = _cfg != null ? _cfg.radio_callsign : "";
            tNet.Children.Add(radioCallBox);
            CheckBox radioCarries = new CheckBox
            {
                Content = "This node repeats traffic for other stations",
                Foreground = BrushFg, FontSize = 12,
                IsChecked = _cfg != null && _cfg.radio_carries,
                Margin = new Thickness(0, 0, 0, 6)
            };
            tNet.Children.Add(radioCarries);

            tNet.Children.Add(new Separator { Margin = new Thickness(0, 8, 0, 8) });
            tNet.Children.Add(new TextBlock
            {
                Text = "Bridging to a phone number",
                FontSize = 12, FontWeight = FontWeights.SemiBold, Foreground = BrushGray, Margin = new Thickness(0, 0, 0, 6)
            });
            CheckBox gwChk = new CheckBox
            {
                Content = "Use a bridging provider when no SIM can place the call",
                Foreground = BrushFg, FontSize = 12,
                IsChecked = _cfg != null && _cfg.gateway_enabled,
                Margin = new Thickness(0, 0, 0, 4)
            };
            tNet.Children.Add(gwChk);
            tNet.Children.Add(new TextBlock
            {
                Text = "Calls over the mesh cost nothing and need no SIM. A bridge to the phone network " +
                       "is only used when the SIM cannot dial, and this build defines the interface " +
                       "(IEgressGateway) without shipping an adapter for it.",
                FontSize = 11, Foreground = BrushGray, TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 0, 0, 6)
            });
            TextBox gwName = MakeTextBox(0); gwName.Margin = new Thickness(0, 2, 0, 8);
            gwName.Text = _cfg != null ? _cfg.gateway_name : "";
            gwName.ToolTip = "A label for the bridge, shown in the log when it would be used";
            tNet.Children.Add(gwName);
            Button btnRelayHelp = MakeButton("How do I set this up?");
            btnRelayHelp.Click += delegate
            {
                Log("Federation: both relays tick Host server, then each adds the other as " +
                    "host:45675 under Relays to link to. Keep the policy on 'allowed' and list the " +
                    "other side's address under Allowed to link to me.", BrushGray);
            };
            tNet.Children.Add(btnRelayHelp);

            tabs.Items.Add(new TabItem { Header = "Relay & Mesh", Content = new ScrollViewer { Content = tNet, VerticalScrollBarVisibility = ScrollBarVisibility.Auto } });

            // ── Tab 2: Chat Appearance ────────────────────────────────────
            StackPanel t2 = new StackPanel { Margin = new Thickness(16, 12, 16, 12) };
            t2.Children.Add(new TextBlock { Text = "Chat Appearance", FontSize = 15, FontWeight = FontWeights.Bold, Foreground = BrushFg, Margin = new Thickness(0, 0, 0, 12) });

            t2.Children.Add(MakeKey("BACKGROUND COLOUR  (hex, e.g. #101624)"));
            TextBox bgColorBox = MakeTextBox(0);
            bgColorBox.Text = (_cfg != null && !string.IsNullOrEmpty(_cfg.chat_bg_color)) ? _cfg.chat_bg_color : "#101624";
            bgColorBox.Margin = new Thickness(0, 2, 0, 4);
            t2.Children.Add(bgColorBox);

            Border colorPreview = new Border { Height = 32, CornerRadius = new CornerRadius(8), Margin = new Thickness(0, 0, 0, 10), Background = _chatBgBrush };
            t2.Children.Add(colorPreview);
            bgColorBox.TextChanged += delegate
            {
                try
                {
                    Color c2 = (Color)ColorConverter.ConvertFromString(bgColorBox.Text.Trim());
                    colorPreview.Background = new SolidColorBrush(c2);
                }
                catch { }
            };

            // Preset palette
            t2.Children.Add(MakeKey("QUICK PRESETS"));
            WrapPanel palette = new WrapPanel { Margin = new Thickness(0, 4, 0, 12) };
            string[] presets = { "#101624", "#0d1117", "#1a1a2e", "#0f2027", "#1b2838", "#2d1b33", "#1a2e1a", "#2e2014" };
            string[] presetNames = { "Navy Dark", "GitHub Dark", "Purple Night", "Deep Teal", "Steam", "Grape", "Forest", "Mocha" };
            for (int pi = 0; pi < presets.Length; pi++)
            {
                string hex = presets[pi]; string pName = presetNames[pi];
                Border pb = new Border { Width = 36, Height = 36, CornerRadius = new CornerRadius(6), Margin = new Thickness(3), Cursor = Cursors.Hand, ToolTip = pName };
                try { pb.Background = new SolidColorBrush((Color)ColorConverter.ConvertFromString(hex)); } catch { }
                pb.MouseLeftButtonUp += delegate { bgColorBox.Text = hex; };
                palette.Children.Add(pb);
            }
            t2.Children.Add(palette);

            t2.Children.Add(MakeKey("BACKGROUND IMAGE  (PNG / JPG — shown at 25% opacity)"));
            TextBox bgImgBox = MakeTextBox(0); bgImgBox.Text = _chatBgImagePath; bgImgBox.Margin = new Thickness(0, 2, 0, 4);
            t2.Children.Add(bgImgBox);
            Button btnBrowseBg = MakeButton("Browse...");
            btnBrowseBg.Margin = new Thickness(0, 0, 0, 10);
            btnBrowseBg.Click += delegate
            {
                Microsoft.Win32.OpenFileDialog fd = new Microsoft.Win32.OpenFileDialog { Filter = "Images|*.png;*.jpg;*.jpeg;*.bmp;*.webp|All|*.*" };
                if (fd.ShowDialog(w) == true) bgImgBox.Text = fd.FileName;
            };
            t2.Children.Add(btnBrowseBg);

            Button btnClearBg = MakeButton("Clear Background Image");
            btnClearBg.Margin = new Thickness(0, 0, 0, 4);
            btnClearBg.Click += delegate { bgImgBox.Text = ""; };
            t2.Children.Add(btnClearBg);

            tabs.Items.Add(new TabItem { Header = "Chat Theme", Content = new ScrollViewer { Content = t2, VerticalScrollBarVisibility = ScrollBarVisibility.Auto } });

            // ── Tab 3: AI Integration ─────────────────────────────────────
            StackPanel t3 = new StackPanel { Margin = new Thickness(16, 12, 16, 12) };
            t3.Children.Add(new TextBlock { Text = "AI Integration", FontSize = 15, FontWeight = FontWeights.Bold, Foreground = BrushFg, Margin = new Thickness(0, 0, 0, 4) });
            t3.Children.Add(new TextBlock { Text = "Add an API key to use the 🤖 AI button in the chat input bar. Supports OpenAI, Gemini, Groq, Ollama (local) and any OpenAI-compatible endpoint.", Foreground = BrushGray, FontSize = 12, TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 0, 0, 12) });

            CheckBox chkAiEnabled = new CheckBox { Content = "Enable AI assistant", Foreground = BrushFg, IsChecked = _aiEnabled, Margin = new Thickness(0, 0, 0, 10) };
            t3.Children.Add(chkAiEnabled);

            t3.Children.Add(MakeKey("MODEL PROVIDER"));
            ComboBox providerBox = new ComboBox { Margin = new Thickness(0, 2, 0, 10) };
            providerBox.Items.Add("OpenAI (gpt-4o-mini)");
            providerBox.Items.Add("OpenAI (gpt-4o)");
            providerBox.Items.Add("OpenAI (gpt-3.5-turbo)");
            providerBox.Items.Add("Gemini (gemini-1.5-flash)");
            providerBox.Items.Add("Groq (llama-3.1-70b-versatile)");
            providerBox.Items.Add("Ollama — local (llama3)");
            providerBox.Items.Add("Custom");
            providerBox.SelectedIndex = 0;
            t3.Children.Add(providerBox);

            t3.Children.Add(MakeKey("API ENDPOINT URL"));
            TextBox endpointBox = MakeTextBox(0); endpointBox.Text = _aiEndpoint; endpointBox.Margin = new Thickness(0, 2, 0, 10);
            t3.Children.Add(endpointBox);

            t3.Children.Add(MakeKey("MODEL ID"));
            TextBox modelBox = MakeTextBox(0); modelBox.Text = _aiModel; modelBox.Margin = new Thickness(0, 2, 0, 10);
            t3.Children.Add(modelBox);

            t3.Children.Add(MakeKey("API KEY  (stored locally — never transmitted except to the endpoint above)"));
            PasswordBox apiKeyBox = new PasswordBox { Margin = new Thickness(0, 2, 0, 4), Background = Theme.Chrome, Foreground = BrushFg, BorderBrush = Theme.CardBorder, Padding = new Thickness(8, 6, 8, 6) };
            if (!string.IsNullOrEmpty(_aiApiKey)) apiKeyBox.Password = _aiApiKey;
            t3.Children.Add(apiKeyBox);

            Button btnTestAi = MakeButton("Test Connection");
            btnTestAi.Margin = new Thickness(0, 4, 0, 10);
            btnTestAi.Click += async delegate
            {
                string testKey = apiKeyBox.Password;
                string testEp = endpointBox.Text.Trim();
                string testModel = modelBox.Text.Trim();
                if (string.IsNullOrEmpty(testKey) || string.IsNullOrEmpty(testEp)) { Log("AI: fill endpoint and key before testing.", BrushWarn); return; }
                Log("AI: testing connection to " + testEp + " ...", BrushGray);
                try
                {
                    string old = _aiApiKey; string oldEp = _aiEndpoint; string oldMod = _aiModel;
                    _aiApiKey = testKey; _aiEndpoint = testEp; _aiModel = testModel;
                    string result = await Task.Run(delegate { return CallAiApi("Say: OK"); });
                    _aiApiKey = old; _aiEndpoint = oldEp; _aiModel = oldMod;
                    Log("AI test OK: " + result.Substring(0, Math.Min(80, result.Length)), BrushSuccess);
                }
                catch (Exception ex) { Log("AI test failed: " + ex.Message, BrushError); }
            };
            t3.Children.Add(btnTestAi);

            // Provider preset wiring
            providerBox.SelectionChanged += delegate
            {
                int idx = providerBox.SelectedIndex;
                string[] endpoints = {
                    "https://api.openai.com/v1/chat/completions",
                    "https://api.openai.com/v1/chat/completions",
                    "https://api.openai.com/v1/chat/completions",
                    "https://generativelanguage.googleapis.com/v1beta/openai/chat/completions",
                    "https://api.groq.com/openai/v1/chat/completions",
                    "http://localhost:11434/v1/chat/completions",
                    endpointBox.Text
                };
                string[] models = { "gpt-4o-mini", "gpt-4o", "gpt-3.5-turbo", "gemini-1.5-flash", "llama-3.1-70b-versatile", "llama3", modelBox.Text };
                if (idx >= 0 && idx < endpoints.Length) { endpointBox.Text = endpoints[idx]; modelBox.Text = models[idx]; }
            };

            tabs.Items.Add(new TabItem { Header = "AI", Content = new ScrollViewer { Content = t3, VerticalScrollBarVisibility = ScrollBarVisibility.Auto } });

            // ── Tab 4: Communication ──────────────────────────────────────
            StackPanel t4 = new StackPanel { Margin = new Thickness(16, 12, 16, 12) };
            t4.Children.Add(new TextBlock { Text = "Communication", FontSize = 15, FontWeight = FontWeights.Bold, Foreground = BrushFg, Margin = new Thickness(0, 0, 0, 12) });

            t4.Children.Add(new TextBlock { Text = "Call & Audio", FontSize = 12, FontWeight = FontWeights.SemiBold, Foreground = BrushGray, Margin = new Thickness(0, 0, 0, 6) });
            CheckBox chkNoise = new CheckBox { Content = "Noise filter (mic gate + AGC + echo cancel)", Foreground = BrushFg, IsChecked = _chkNoiseFilter != null && _chkNoiseFilter.IsChecked == true, Margin = new Thickness(0, 0, 0, 6) };
            CheckBox chkRec = new CheckBox { Content = "Record calls to recordings\\ folder", Foreground = BrushFg, IsChecked = _chkRecordCalls != null && _chkRecordCalls.IsChecked == true, Margin = new Thickness(0, 0, 0, 10) };
            t4.Children.Add(chkNoise); t4.Children.Add(chkRec);

            // ── Call transcription (local whisper.cpp) ────────────────────
            t4.Children.Add(new Separator { Margin = new Thickness(0, 8, 0, 8) });
            t4.Children.Add(new TextBlock
            {
                Text = "Call transcription - whisper.cpp on this PC",
                FontSize = 12, FontWeight = FontWeights.SemiBold, Foreground = BrushGray,
                Margin = new Thickness(0, 0, 0, 6)
            });
            CheckBox chkTr = new CheckBox
            {
                Content = "Subtitle the remote voice during calls",
                Foreground = BrushFg,
                IsChecked = _cfg != null && _cfg.transcribe_calls,
                Margin = new Thickness(0, 0, 0, 4)
            };
            t4.Children.Add(chkTr);
            t4.Children.Add(new TextBlock
            {
                Text = "Nothing is downloaded or sent anywhere. whisper.cpp and its model must already " +
                       "be on this machine; until both are found this stays off, and the call audio " +
                       "never leaves the PC.",
                FontSize = 11, Foreground = BrushGray, TextWrapping = TextWrapping.Wrap,
                Margin = new Thickness(0, 0, 0, 8)
            });
            t4.Children.Add(MakeKey("WHISPER BINARY  (whisper-cli.exe / main.exe)"));
            TextBox whExeBox = MakeTextBox(0); whExeBox.Margin = new Thickness(0, 2, 0, 4);
            whExeBox.Text = _cfg != null ? _cfg.whisper_exe : "";
            Button btnWhExe = MakeButton("Browse..."); btnWhExe.Margin = new Thickness(0, 0, 0, 8);
            btnWhExe.Click += delegate
            {
                Microsoft.Win32.OpenFileDialog fd = new Microsoft.Win32.OpenFileDialog
                {
                    Filter = "Whisper executable|*.exe|All files|*.*",
                    Title = "Select whisper-cli.exe or main.exe"
                };
                if (fd.ShowDialog(w) == true) whExeBox.Text = fd.FileName;
            };
            t4.Children.Add(btnWhExe);
            t4.Children.Add(MakeKey("MODEL  (ggml-*.bin)"));
            TextBox whModelBox = MakeTextBox(0); whModelBox.Margin = new Thickness(0, 2, 0, 4);
            whModelBox.Text = _cfg != null ? _cfg.whisper_model : "";
            Button btnWhModel = MakeButton("Browse..."); btnWhModel.Margin = new Thickness(0, 0, 0, 8);
            btnWhModel.Click += delegate
            {
                Microsoft.Win32.OpenFileDialog fd = new Microsoft.Win32.OpenFileDialog
                {
                    Filter = "whisper model|*.bin|All files|*.*",
                    Title = "Select a ggml model"
                };
                if (fd.ShowDialog(w) == true) whModelBox.Text = fd.FileName;
            };
            t4.Children.Add(btnWhModel);
            StackPanel trBtnRow = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 0, 0, 6) };
            Button btnWhDetect = MakeButton("Detect installed");
            btnWhDetect.Margin = new Thickness(0, 0, 8, 0);
            btnWhDetect.Click += delegate
            {
                string ex = Transcriber.FindExe(whExeBox.Text);
                string md = Transcriber.FindModel(whModelBox.Text);
                if (ex.Length > 0) whExeBox.Text = ex;
                if (md.Length > 0) whModelBox.Text = md;
                Log("whisper detect: " + (ex.Length > 0 ? ex : "no binary") + " / " +
                    (md.Length > 0 ? md : "no model"), ex.Length > 0 && md.Length > 0 ? BrushSuccess : BrushWarn);
            };
            trBtnRow.Children.Add(btnWhDetect);
            Button btnWhTest = MakeButton("Test transcription");
            btnWhTest.Click += async delegate
            {
                Transcriber probe = new Transcriber(Transcriber.FindExe(whExeBox.Text),
                                                    Transcriber.FindModel(whModelBox.Text),
                                                    "auto");
                string result = await Task.Run(delegate { return probe.SelfTest(); });
                Log("Transcription test: " + result, result.StartsWith("OK") ? BrushSuccess : BrushWarn);
            };
            trBtnRow.Children.Add(btnWhTest);
            t4.Children.Add(trBtnRow);

            t4.Children.Add(new Separator { Margin = new Thickness(0, 8, 0, 8) });
            t4.Children.Add(new TextBlock { Text = "Quick SMS Broadcast", FontSize = 12, FontWeight = FontWeights.SemiBold, Foreground = BrushGray, Margin = new Thickness(0, 0, 0, 6) });
            t4.Children.Add(new TextBlock { Text = "Send one message to multiple numbers (one per line).", Foreground = BrushGray, FontSize = 11, Margin = new Thickness(0, 0, 0, 6) });
            TextBox broadcastNums = new TextBox { Height = 80, AcceptsReturn = true, TextWrapping = TextWrapping.Wrap, Background = Theme.Chrome, Foreground = BrushFg, BorderBrush = Theme.CardBorder, Padding = new Thickness(6), VerticalScrollBarVisibility = ScrollBarVisibility.Auto };
            TextBox broadcastMsg = MakeTextBox(0); broadcastMsg.Margin = new Thickness(0, 6, 0, 6);
            broadcastMsg.SetValue(System.Windows.Automation.AutomationProperties.NameProperty, "Broadcast message");
            t4.Children.Add(broadcastNums); t4.Children.Add(broadcastMsg);
            Button btnBroadcast = MakeButton("Send Broadcast SMS");
            btnBroadcast.Margin = new Thickness(0, 0, 0, 0);
            btnBroadcast.Click += async delegate
            {
                if (!_modem.IsOpen) { Log("Broadcast: modem not connected.", BrushWarn); return; }
                string msg2 = broadcastMsg.Text.Trim();
                if (msg2.Length == 0) { Log("Broadcast: type a message.", BrushWarn); return; }
                string[] nums = broadcastNums.Text.Split(new char[] { '\n', '\r', ',' }, StringSplitOptions.RemoveEmptyEntries);
                if (nums.Length == 0) { Log("Broadcast: add at least one number.", BrushWarn); return; }
                Log("Broadcast: sending to " + nums.Length + " recipient(s)...", BrushAccent);
                int sent = 0, fail = 0;
                foreach (string n in nums)
                {
                    string num2 = n.Trim();
                    if (num2.Length < 3) continue;
                    try
                    {
                        string[] r = await Task.Run(delegate { return _modem.SendSms(num2, msg2, 30000); });
                        bool ok2 = false;
                        foreach (string l in r) if (Regex.IsMatch(l, @"(^|\s)OK(\s|$)")) ok2 = true;
                        if (ok2) { sent++; Log("Broadcast OK: " + num2, BrushSuccess); }
                        else { fail++; Log("Broadcast FAIL: " + num2, BrushError); }
                    }
                    catch { fail++; }
                }
                Log("Broadcast complete: " + sent + " sent, " + fail + " failed.", sent > 0 ? BrushSuccess : BrushError);
            };
            t4.Children.Add(btnBroadcast);

            tabs.Items.Add(new TabItem { Header = "Communication", Content = new ScrollViewer { Content = t4, VerticalScrollBarVisibility = ScrollBarVisibility.Auto } });

            // ── Save / Cancel bar ─────────────────────────────────────────
            Border footerBorder = new Border { Background = Theme.Panel, BorderBrush = Theme.CardBorder, BorderThickness = new Thickness(0, 1, 0, 0), Padding = new Thickness(14, 8, 14, 8) };
            DockPanel footerDp = new DockPanel { LastChildFill = false };
            Button btnCancel = MakeButton("Cancel"); btnCancel.Padding = new Thickness(16, 6, 16, 6); btnCancel.Margin = new Thickness(0, 0, 8, 0); btnCancel.Click += delegate { w.Close(); };
            Button btnSave = MakeButton("Save & Apply");
            Style primary = TryStyle("PrimaryButton"); if (primary != null) btnSave.Style = primary;
            btnSave.Padding = new Thickness(22, 6, 22, 6);
            btnSave.Click += delegate
            {
                if (_cfg == null) _cfg = AppConfig.Load();
                _cfg.display_name = (nameBox.Text ?? "").Trim();
                if (_cfg.display_name.Length == 0) _cfg.display_name = Environment.UserName;
                _cfg.relay_server = (relayBox.Text ?? "").Trim();
                _cfg.stun_servers = (stunBox.Text ?? "").Trim();
                // Theme
                string newTheme = themeBox.SelectedIndex == 1 ? "dark" : "light";
                bool themeChanged = newTheme != Theme.Current;
                _cfg.theme = newTheme;
                // Chat bg
                _cfg.chat_bg_color = (bgColorBox.Text ?? "").Trim();
                _chatBgImagePath = (bgImgBox.Text ?? "").Trim();
                _cfg.chat_bg_image = _chatBgImagePath;
                if (!string.IsNullOrEmpty(_cfg.chat_bg_color))
                    try { Color bgc = (Color)ColorConverter.ConvertFromString(_cfg.chat_bg_color); if (_chatBgBrush != null) _chatBgBrush.Color = bgc; } catch { }
                // AI
                _aiEnabled = chkAiEnabled.IsChecked == true;
                _aiApiKey = apiKeyBox.Password;
                _aiModel = modelBox.Text.Trim();
                _aiEndpoint = endpointBox.Text.Trim();
                _cfg.ai_enabled = _aiEnabled;
                _cfg.ai_api_key = _aiApiKey;
                _cfg.ai_model = _aiModel;
                _cfg.ai_endpoint = _aiEndpoint;
                // Comms
                if (_chkNoiseFilter != null) { _chkNoiseFilter.IsChecked = chkNoise.IsChecked; _audioFilter.Enabled = chkNoise.IsChecked == true; }
                if (_chkRecordCalls != null) _chkRecordCalls.IsChecked = chkRec.IsChecked;
                _cfg.noise_filter = chkNoise.IsChecked == true;
                _cfg.record_calls = chkRec.IsChecked == true;
                _cfg.transcribe_calls = chkTr.IsChecked == true;
                _cfg.whisper_exe = (whExeBox.Text ?? "").Trim();
                _cfg.whisper_model = (whModelBox.Text ?? "").Trim();

                // Relay & mesh: save, then push it onto the running relay so the
                // user does not have to restart hosting for a policy change.
                _cfg.relay_policy = polBox.SelectedIndex == 0 ? "nobody"
                                    : (polBox.SelectedIndex == 2 ? "everyone" : "allowed");
                _cfg.relay_tls = tlsRelay.IsChecked == true;
                _cfg.relay_peers = (peersBox.Text ?? "").Trim();
                _cfg.relay_advertise = (advBox.Text ?? "").Trim();
                _cfg.relay_autolink = autoLink.IsChecked == true;
                _cfg.relay_automesh = autoMesh.IsChecked == true;
                _cfg.relay_onion = onionBox.SelectedIndex == 2 ? "force"
                                 : (onionBox.SelectedIndex == 1 ? "best" : "off");
                _cfg.relay_carry_mail = carryMail.IsChecked == true;
                _cfg.relay_allow = (allowBox.Text ?? "").Trim();
                int storeKb = _cfg.relay_store_kb;
                if (int.TryParse((storeBox.Text ?? "").Trim(), out storeKb) && storeKb > 0) _cfg.relay_store_kb = storeKb;
                int bwKbps = 0;
                if (int.TryParse((bwBox.Text ?? "").Trim(), out bwKbps) && bwKbps >= 0) _cfg.relay_bandwidth_kbps = bwKbps;
                _cfg.gateway_enabled = gwChk.IsChecked == true;
                _cfg.gateway_name = (gwName.Text ?? "").Trim();
                string wantPort = (radioPortBox.Text ?? "").Trim();
                if (wantPort != (_cfg.radio_port ?? "").Trim())
                {
                    // Re-opening a link the user just changed the name of beats
                    // leaving a port held by a transport nobody asked for.
                    _cfg.radio_port = wantPort;
                    DetachRadio();
                    TryAttachRadio();
                }
                _cfg.radio_callsign = (radioCallBox.Text ?? "").Trim();
                _cfg.radio_carries = radioCarries.IsChecked == true;
                ApplyFederationLive();
                fedStatus.Text = FederationStatusLine();

                if (_txtRelay != null) _txtRelay.Text = _cfg.relay_server;
                SaveState();
                ApplyChatBackground();
                if (themeChanged) { Theme.Apply(newTheme); Log("Theme: " + newTheme, BrushAccent); }
                ApplyCallSettings();
                Log("Settings saved.", BrushSuccess);
                w.Close();
            };
            DockPanel.SetDock(btnCancel, Dock.Right);
            DockPanel.SetDock(btnSave, Dock.Right);
            footerDp.Children.Add(btnSave);
            footerDp.Children.Add(btnCancel);
            footerBorder.Child = footerDp;

            Grid wGrid = new Grid();
            wGrid.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) });
            wGrid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            Grid.SetRow(tabs, 0);
            Grid.SetRow(footerBorder, 1);
            wGrid.Children.Add(tabs);
            wGrid.Children.Add(footerBorder);
            w.Content = wGrid;
            w.ShowDialog();
        }

        private void LoadState()
        {
            AppConfig c = AppConfig.Load();
            c.EnsureIdentity();
            try { c.Save(); } catch { }   // persist minted identity on first run
            _cfg = c;
            _myNumber = (Cli.NumberOverride != null && Cli.NumberOverride.Length > 0)
                ? Cli.NumberOverride : c.virtual_number;
            if (Cli.RelayOverride != null) c.relay_server = Cli.RelayOverride;
            if (Cli.HostOverride.HasValue) c.host_calls = Cli.HostOverride.Value;

            _txtMifiIp.Text = c.mifi_ip;
            _pendingPort = c.com_port;
            _comboBaud.SelectedItem = c.baud;
            if (c.use_serial) _radioSerial.IsChecked = true;
            _chkAuto.IsChecked = c.auto_connect;
            if (_txtRelay != null) _txtRelay.Text = c.relay_server;
            if (_trackerServerBox != null) _trackerServerBox.Text = c.tracker_server;
            if (_trackerPairBox != null) _trackerPairBox.Text = "";
            if (_trackerDeviceBox != null) _trackerDeviceBox.Text = c.tracker_device_id;
            if (_chkHostCalls != null) _chkHostCalls.IsChecked = c.host_calls;
            if (_chkRelayMedia != null) _chkRelayMedia.IsChecked = c.relay_media;
            if (_chkPortMap != null) _chkPortMap.IsChecked = c.relay_port_map;
            if (_chkNoiseFilter != null) _chkNoiseFilter.IsChecked = c.noise_filter;
            if (_chkRecordCalls != null) _chkRecordCalls.IsChecked = c.record_calls;
            if (_chkAlwaysAwake != null)
            {
                // Restoring the saved tick must not rewrite the config or the
                // sign-in entry: those are the effect of a click, not of a load.
                _suppressWakeAgentToggle = true;
                _chkAlwaysAwake.IsChecked = c.always_awake;
                _suppressWakeAgentToggle = false;
                Log("Wake agent: " + (c.always_awake
                        ? "armed - it takes the relay when this window closes."
                        : "off: nothing will catch traffic while this window is shut."),
                    c.always_awake ? BrushGray : BrushWarn);
            }
            if (_txtMyNumber != null) _txtMyNumber.Text = AppNum.Format(_myNumber);
            if (_chkCarryPeers != null)
            {
                // Same rule as the wake agent tick: loading a setting restores the
                // control, it does not perform the click.
                _suppressCarryToggle = true;
                _chkCarryPeers.IsChecked = c.carry_for_peers;
                _suppressCarryToggle = false;
            }
            RefreshRouteTable();
            // Chat background + AI
            _chatBgImagePath = c.chat_bg_image ?? "";
            _aiApiKey = c.ai_api_key ?? "";
            _aiModel = string.IsNullOrEmpty(c.ai_model) ? "gpt-4o-mini" : c.ai_model;
            _aiEndpoint = string.IsNullOrEmpty(c.ai_endpoint) ? "https://api.openai.com/v1/chat/completions" : c.ai_endpoint;
            _aiEnabled = c.ai_enabled;
            if (!string.IsNullOrEmpty(c.chat_bg_color))
            {
                try
                {
                    Color bgColor = (Color)ColorConverter.ConvertFromString(c.chat_bg_color);
                    if (_chatBgBrush != null) _chatBgBrush.Color = bgColor;
                }
                catch { }
            }
            ApplyChatBackground();
            ToggleUssdPanels();
            Log("App number: " + AppNum.Format(_myNumber) + (Cli.NumberOverride != null ? " (CLI override)" : ""), BrushAccent);
            // A brand-new install has just been handed the one thing the whole app turns
            // on, and until now all it got was a line among several. Say what it is, that
            // it is theirs and permanent, and the two things they now have to do - tell
            // somebody, and get onto a relay, without which the number is only reachable
            // by people on the same network. Deliberately log lines rather than a modal:
            // this app has already been criticised for first-run walls that pop up, and a
            // box you must dismiss before you can do anything is the wrong shape here.
            if (_cfg != null && _cfg.FirstRunIdentity)
            {
                Log("This is YOUR app number - it is yours to keep, on this device. Anyone "
                    + "with it can call or message you without your IP, your SIM or your carrier.", BrushSuccess);
                Log("Tell it to somebody: " + AppNum.Format(_myNumber) +
                    " (it is also in Settings, and in " + Home.Dir + "\\ussd_config.json).", BrushAccent);
                Log("To reach anyone off this network, a relay is needed: paste a friend's "
                    + "relays.seed line, or host one in Settings and send them the SEED LINE "
                    + "it prints.", BrushWarn);
                // Auto-configure background agent and probe capabilities — runs on
                // a background thread so the UI stays responsive.
                Thread autoConf = new Thread((ThreadStart)delegate
                {
                    string agentExe = null;
                    try { agentExe = AgentExePath(); } catch { }
                    string relayAddr = _cfg != null ? (_cfg.relay_server ?? "") : "";
                    ConnectionHelper.AutoConfigureFirstRun(
                        agentExe ?? "", Home.Dir, relayAddr,
                        delegate(string msg, bool ok)
                        {
                            string m = msg; bool g = ok;
                            Dispatcher.BeginInvoke((Action)delegate { Log(m, g ? BrushGray : BrushWarn); });
                        });
                });
                autoConf.IsBackground = true;
                autoConf.Name = "UssdAutoConf";
                autoConf.Start();
                // Show a non-blocking welcome overlay so the first-timer has
                // something to act on, not just log lines they might miss.
                Dispatcher.BeginInvoke((Action)delegate
                {
                    ShowFirstRunWelcome(AppNum.Format(_myNumber));
                }, System.Windows.Threading.DispatcherPriority.ContextIdle);
            }
            Log("USSD Manager Pro ready - Dialer, Contacts, Video Call, SMS, SIM, USSD.", BrushAccent);
        }

        private void SaveState()
        {
            if (_cfg == null) _cfg = AppConfig.Load();
            _cfg.mifi_ip = _txtMifiIp.Text;
            _cfg.com_port = SelectedPort() ?? "";
            _cfg.baud = SelectedBaud().ToString();
            _cfg.use_serial = _radioSerial.IsChecked == true;
            _cfg.auto_connect = _chkAuto.IsChecked == true;
            if (_txtRelay != null) _cfg.relay_server = _txtRelay.Text.Trim();
            if (_chkHostCalls != null) _cfg.host_calls = _chkHostCalls.IsChecked == true;
            if (_chkRelayMedia != null) _cfg.relay_media = _chkRelayMedia.IsChecked == true;
            if (_chkPortMap != null) _cfg.relay_port_map = _chkPortMap.IsChecked == true;
            if (_chkNoiseFilter != null) _cfg.noise_filter = _chkNoiseFilter.IsChecked == true;
            if (_chkRecordCalls != null) _cfg.record_calls = _chkRecordCalls.IsChecked == true;
            _cfg.chat_bg_image = _chatBgImagePath ?? "";
            _cfg.ai_api_key = _aiApiKey ?? "";
            _cfg.ai_model = _aiModel ?? "gpt-4o-mini";
            _cfg.ai_endpoint = _aiEndpoint ?? "https://api.openai.com/v1/chat/completions";
            _cfg.ai_enabled = _aiEnabled;
            _cfg.laptop_tracker_exe = _laptopTrackerExe ?? "";
            _cfg.Save();
        }

        // ---------- wake agent (C1) ----------
        private bool _suppressWakeAgentToggle;
        private const string WakeAgentRunKey = "Software\\Microsoft\\Windows\\CurrentVersion\\Run";
        private const string WakeAgentRunValue = "UssdWakeAgent";

        // The listener is a separate exe (Csharp\build_agent.bat) because a
        // process meant to run for days cannot afford this window's cold start.
        private static string AgentExePath()
        {
            foreach (string d in new string[] { AppDomain.CurrentDomain.BaseDirectory, Home.Dir })
            {
                string p = Path.Combine(d, "UssdAgent.exe");
                if (File.Exists(p)) { try { return Path.GetFullPath(p); } catch { return p; } }
            }
            try
            {
                string self = Process.GetCurrentProcess().MainModule.FileName;
                string p = Path.Combine(Path.GetDirectoryName(self), "UssdAgent.exe");
                if (File.Exists(p)) { try { return Path.GetFullPath(p); } catch { return p; } }
            }
            catch { }
            return null;
        }

        private static bool WakeAgentRunning()
        {
            // One profile per machine is the supported shape, so any listener is
            // our listener; two agents for one number would only fight.
            try
            {
                Process[] ps = Process.GetProcessesByName("UssdAgent");
                bool any = ps.Length > 0;
                foreach (Process p in ps) { try { p.Dispose(); } catch { } }
                return any;
            }
            catch { return false; }
        }

        // "Always awake" has to be true before the user opens anything, which
        // means sign-in. The toggle therefore owns exactly one HKCU Run value
        // and says out loud when Windows refuses it.
        private void RegisterWakeAgentAtLogin(bool on)
        {
            string exe = AgentExePath();
            if (exe == null)
            {
                Log("Wake agent: UssdAgent.exe is not beside this exe - build it with Csharp\\build_agent.bat.", BrushWarn);
                return;
            }
            string addr = (_cfg != null && _cfg.relay_server != null) ? _cfg.relay_server.Trim() : "";
            if (on && addr.Length == 0)
            {
                Log("Wake agent: no relay server is set, so there is nothing to listen on. Set one first.", BrushWarn);
                return;
            }
            try
            {
                using (Microsoft.Win32.RegistryKey k =
                    Microsoft.Win32.Registry.CurrentUser.OpenSubKey(WakeAgentRunKey, true))
                {
                    if (k == null) { Log("Wake agent: could not open the sign-in Run key.", BrushWarn); return; }
                    if (on)
                        k.SetValue(WakeAgentRunValue,
                            "\"" + exe + "\" --agent --home=\"" + Home.Dir.TrimEnd('\\') + "\" --relay=" + addr,
                            Microsoft.Win32.RegistryValueKind.String);
                    else if (k.GetValue(WakeAgentRunValue) != null) k.DeleteValue(WakeAgentRunValue, false);
                }
                Log("Wake agent: " + (on
                        ? "will start at sign-in (per-user Run entry written)."
                        : "no longer starts at sign-in (Run entry removed)."), BrushGray);
            }
            catch (Exception ex)
            {
                Log("Wake agent: " + (on ? "could not register at sign-in: "
                                         : "could not remove the sign-in entry: ") + ex.Message, BrushWarn);
            }
        }

        // D1b: the route table, drawn from the router's own view of its links.
        // An empty table would look like a broken app, so an unregistered state
        // gets its own row instead of blank space.
        private void RefreshRouteTable()
        {
            if (_lvRoutes == null) return;
            try
            {
                List<RouteRow> rows = _voip != null ? _voip.RouteRows() : new List<RouteRow>();
                _lvRoutes.Items.Clear();
                if (rows.Count == 0)
                {
                    RouteRow idle = new RouteRow();
                    idle.Name = "no link yet";
                    idle.IsReady = false;
                    _lvRoutes.Items.Add(idle);
                    return;
                }
                foreach (RouteRow r in rows) _lvRoutes.Items.Add(r);
            }
            catch (Exception ex) { Log("Routes: " + ex.Message, BrushGray); }
        }

        // Consent is not a decoration: the tick has to reach the router, or the
        // table would promise a route the code refuses.
        private void SetCarryConsent(bool allowed)
        {
            if (_suppressCarryToggle || _cfg == null) return;
            _cfg.carry_for_peers = allowed;
            try { _cfg.Save(); } catch { }
            if (_voip != null) _voip.SetCarryForPeers(allowed);
            Log("Routes: " + (allowed
                    ? "this node will carry traffic for other peers over links that ask for it."
                    : "this node carries only its own traffic."), allowed ? BrushWarn : BrushGray);
            RefreshRouteTable();
        }

        // On the way out, hand the slot to the listener. It registers with the
        // same number token, so the relay replaces this session rather than
        // refusing the number as "in use", and nothing depends on a server we
        // control holding the traffic.
        private void HandOffToAgent()
        {
            try
            {
                if (_cfg == null || !_cfg.always_awake) return;
                string exe = AgentExePath();
                if (exe == null)
                {
                    Log("Wake agent: UssdAgent.exe not found - traffic while closed will be refused by the relay.", BrushWarn);
                    return;
                }
                if (WakeAgentRunning()) return;
                string addr = (_cfg.relay_server != null) ? _cfg.relay_server.Trim() : "";
                if (addr.Length == 0) return;
                ProcessStartInfo psi = new ProcessStartInfo(exe);
                psi.Arguments = "--agent --home=\"" + Home.Dir.TrimEnd('\\') + "\" --number=" + _myNumber +
                                " --relay=" + addr;
                psi.WorkingDirectory = Path.GetDirectoryName(exe);
                psi.UseShellExecute = false;
                psi.CreateNoWindow = true;
                Process.Start(psi);
                Log("Wake agent started: it holds " + AppNum.Format(_myNumber) +
                    " until this window opens again. It writes wake_agent.log in its folder.", BrushAccent);
            }
            catch (Exception ex) { Log("Wake agent could not start: " + ex.Message, BrushWarn); }
        }

        protected override void OnClosing(System.ComponentModel.CancelEventArgs e)
        {
            // ── System Tray: minimize to tray instead of exiting ──────────
            if (_trayIcon != null && !_trayMinimized)
            {
                e.Cancel = true;      // don't close
                _trayMinimized = true;
                Hide();               // hide the window
                _trayIcon.Visible = true;
                _trayIcon.ShowBalloonTip(2500, "USSD Manager Pro",
                    "Still running in the background — receiving calls & messages.",
                    System.Windows.Forms.ToolTipIcon.Info);
                return;
            }
            // ── Actual exit ───────────────────────────────────────────────
            try { if (_trayStateTimer != null) _trayStateTimer.Stop(); } catch { }
            try { if (_trayIcon != null) { _trayIcon.Visible = false; _trayIcon.Dispose(); } } catch { }
            try { ToneSynth.StopRing(); } catch { }
            if (_agentSpeech != null)
            {
                _agentSpeech.SpeakAsyncCancelAll();
                _agentSpeech.Dispose();
                _agentSpeech = null;
            }
            try { StopRecording(); } catch { }
            try { StopCamera(); } catch { }
            try { _bgRunning = false; if (_bgReconnectThread != null) _bgReconnectThread.Interrupt(); } catch { }
            try { if (_voip != null) _voip.Dispose(); } catch { }
            try
            {
                VoipAudio va = _voipAudio;
                _voipAudio = null;
                if (va != null)
                {
                    Thread t = new Thread((ThreadStart)delegate { try { va.Dispose(); } catch { } });
                    t.IsBackground = true;
                    t.Start();
                }
            }
            catch { }
            try { if (_callServer != null) _callServer.Stop(); } catch { }
            try { SaveState(); } catch { }
            HandOffToAgent();
            try { SaveContacts(); } catch { }
            try { _modem.Dispose(); } catch { }
            base.OnClosing(e);
        }

        // ── System Tray setup ─────────────────────────────────────────────
        private void InitTrayIcon()
        {
            try
            {
                _trayIcon = new System.Windows.Forms.NotifyIcon();
                // Try to load the app icon; fall back to a system stock icon
                try
                {
                    string icoPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "UssdApp.ico");
                    if (File.Exists(icoPath))
                        _trayIcon.Icon = new System.Drawing.Icon(icoPath);
                    else
                        _trayIcon.Icon = System.Drawing.SystemIcons.Application;
                }
                catch { _trayIcon.Icon = System.Drawing.SystemIcons.Application; }

                _trayIcon.Text = "USSD Manager Pro";
                _trayIcon.Visible = false;

                System.Windows.Forms.ContextMenuStrip cms = new System.Windows.Forms.ContextMenuStrip();
                cms.Items.Add("Open", null, delegate { TrayRestore(); });
                cms.Items.Add("-");
                cms.Items.Add("New Call…", null, delegate { TrayRestore(); ShowPage(0); });
                cms.Items.Add("SMS / Chat", null, delegate { TrayRestore(); ShowPage(3); });
                cms.Items.Add("Settings…", null, delegate { TrayRestore(); ShowSettingsDialog(); });
                cms.Items.Add("-");
                System.Windows.Forms.ToolStripMenuItem presMenu = new System.Windows.Forms.ToolStripMenuItem("Presence");
                string[] presStates = { "available", "busy", "dnd", "away" };
                string[] presLabels = { "🟢 Available", "🔴 Busy", "⛔ Do Not Disturb", "🟡 Away" };
                for (int pi = 0; pi < presStates.Length; pi++)
                {
                    string ps = presStates[pi]; string pl = presLabels[pi];
                    presMenu.DropDownItems.Add(pl, null, delegate { SetPresence(ps, ""); });
                }
                cms.Items.Add(presMenu);
                cms.Items.Add("-");
                cms.Items.Add("Exit", null, delegate
                {
                    _trayMinimized = false;   // allow actual close
                    Close();
                });
                _trayIcon.ContextMenuStrip = cms;
                _trayIcon.DoubleClick += delegate { TrayRestore(); };
                StartTrayStatusTimer();
                UpdateTrayStatus();
            }
            catch (Exception ex) { Log("Tray: " + ex.Message, BrushGray); }
        }

        // ── Tray status colour ────────────────────────────────────────────
        // Green dot = relay connected, amber = reachable on the LAN only,
        // red = nothing reachable. The dot is composited over the app icon at
        // runtime and encoded by hand as a 32-bit BGRA icon: going through
        // Icon.FromHandle(bitmap.GetHicon()) throws the alpha channel away and
        // the result reads as a black square in the notification area.
        private string _trayState = "";
        private DispatcherTimer _trayStateTimer;
        private System.Drawing.Bitmap _trayBase;

        private void StartTrayStatusTimer()
        {
            if (_trayStateTimer != null) return;
            _trayStateTimer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(3) };
            _trayStateTimer.Tick += delegate { UpdateTrayStatus(); };
            _trayStateTimer.Start();
        }

        private void UpdateTrayStatus()
        {
            if (_trayIcon == null) return;
            string state;
            if (_voip != null && _voip.RelayReady) state = "relay";
            else if (LanPeersPresent()) state = "lan";
            else state = "down";
            string label = state == "relay" ? "online (relay)"
                         : state == "lan" ? "LAN only"
                         : "disconnected";
            _trayIcon.Text = "USSD Manager Pro \u2014 " + label +
                (_myPresence == "available" ? "" : " \u00b7 " + _myPresence.ToUpper());
            if (state == _trayState) return;      // an icon swap costs a GDI object
            _trayState = state;
            try
            {
                System.Drawing.Bitmap baseBmp = TrayBaseBitmap();
                if (baseBmp == null) return;
                System.Drawing.Color dot = state == "relay"
                    ? System.Drawing.Color.FromArgb(0x22, 0xc5, 0x5e)
                    : state == "lan"
                        ? System.Drawing.Color.FromArgb(0xf5, 0xa6, 0x23)
                        : System.Drawing.Color.FromArgb(0xef, 0x44, 0x44);
                System.Drawing.Bitmap badged = StatusIcons.Badge(baseBmp, dot, 32);
                System.Drawing.Icon ico = StatusIcons.IconFromBitmap(badged, 32);
                badged.Dispose();
                if (ico != null)
                {
                    System.Drawing.Icon old = _trayIcon.Icon;
                    _trayIcon.Icon = ico;
                    if (old != null && old != System.Drawing.SystemIcons.Application) old.Dispose();
                }
            }
            catch { }
        }

        private bool LanPeersPresent()
        {
            if (_voip == null) return false;
            foreach (VoipPeer p in _voip.Peers)
                if (p != null && p.Status.StartsWith("\u25CF")) return true;
            return false;
        }

        private System.Drawing.Bitmap TrayBaseBitmap()
        {
            if (_trayBase != null) return _trayBase;
            try
            {
                string icoPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "UssdApp.ico");
                System.Drawing.Icon baseIco = File.Exists(icoPath)
                    ? new System.Drawing.Icon(icoPath, 32, 32)
                    : System.Drawing.SystemIcons.Application;
                _trayBase = baseIco.ToBitmap();
                if (baseIco != System.Drawing.SystemIcons.Application) baseIco.Dispose();
            }
            catch { _trayBase = null; }
            return _trayBase;
        }

        private void TrayRestore()
        {
            Show();
            WindowState = WindowState.Normal;
            Activate();
            _trayMinimized = false;
            if (_trayIcon != null) _trayIcon.Visible = false;
        }

        // ── Presence broadcasting ─────────────────────────────────────────
        private void SetPresence(string state, string statusText)
        {
            _myPresence = state;
            _myStatusText = statusText ?? "";
            // Update tray tooltip
            if (_trayIcon != null)
                _trayIcon.Text = "USSD Manager Pro — " + state.ToUpper();
            // Update header presence button
            UpdatePresenceButton();
            // Broadcast to peers
            BroadcastPresence();
            Log("Presence: " + state + (statusText.Length > 0 ? " — " + statusText : ""), BrushGray);
        }

        private void UpdatePresenceButton()
        {
            if (_btnPresence == null) return;
            string icon;
            switch (_myPresence)
            {
                case "busy":   icon = "🔴"; break;
                case "dnd":    icon = "⛔"; break;
                case "away":   icon = "🟡"; break;
                case "incall": icon = "📞"; break;
                default:       icon = "🟢"; break;
            }
            _btnPresence.Content = icon;
            _btnPresence.ToolTip = "Status: " + _myPresence + (_myStatusText.Length > 0 ? " — " + _myStatusText : "") + "\nClick to change";
        }

        private void BroadcastPresence()
        {
            if (_voip == null || !_voip.RelayReady) return;
            try
            {
                string msg = "PRESENCE|" + _myPresence + "|" + _myStatusText;
                // Send to all known peers
                foreach (VoipPeer p in _voip.Peers)
                    if (p.Number != null && p.Number.Length >= 3 && p.Number != _myNumber)
                        try { _voip.SendChat(p.Number, msg); } catch { }
            }
            catch { }
        }

        private void StartPresenceBroadcast()
        {
            _presenceBroadcastTimer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(60) };
            _presenceBroadcastTimer.Tick += delegate { BroadcastPresence(); };
            _presenceBroadcastTimer.Start();
        }

        private void HandlePresenceMessage(string from, string payload)
        {
            // payload = "PRESENCE|state|statusText"
            string[] parts = payload.Split(new char[] { '|' }, 3);
            if (parts.Length < 2) return;
            string state = parts[1];
            string text = parts.Length >= 3 ? parts[2] : "";
            _peerPresence[from] = state + "|" + text;
            // If this peer is the open contact, refresh the meta line
            if (_hubPane3ContactMeta != null && _txtChatTo != null &&
                SanitizeNumber(_txtChatTo.Text) == SanitizeNumber(from))
            {
                string icon2;
                switch (state)
                {
                    case "busy":   icon2 = "🔴 Busy"; break;
                    case "dnd":    icon2 = "⛔ DND"; break;
                    case "away":   icon2 = "🟡 Away"; break;
                    case "incall": icon2 = "📞 In call"; break;
                    default:       icon2 = "🟢 Online"; break;
                }
                _hubPane3ContactMeta.Text = icon2 + (text.Length > 0 ? " — " + text : "");
            }
            // Refresh peer list badge in pane 2
            HubRefreshPane2();
        }

        // ── Offline message queue ─────────────────────────────────────────
        private void OutboxEnqueue(string num, string text)
        {
            _outbox.Add(new OutboxMsg { Number = num, Text = text, When = DateTime.Now, Attempts = 0 });
            SaveOutbox();
            Log("Outbox: queued for " + num + " (offline)", BrushWarn);
        }

        private void SaveOutbox()
        {
            try
            {
                string dir = AppConfig.ChatsDir;
                Directory.CreateDirectory(dir);
                StringBuilder sb = new StringBuilder();
                foreach (OutboxMsg m in _outbox)
                    sb.AppendLine(m.Number + "|" + m.When.ToString("o") + "|" + m.Attempts + "|" + m.Text.Replace("\n", "\\n"));
                File.WriteAllText(Path.Combine(dir, "outbox.txt"), sb.ToString(), Encoding.UTF8);
            }
            catch { }
        }

        private void LoadOutbox()
        {
            try
            {
                string path = Path.Combine(AppConfig.ChatsDir, "outbox.txt");
                if (!File.Exists(path)) return;
                foreach (string line in File.ReadAllLines(path))
                {
                    string[] p = line.Split(new char[] { '|' }, 4);
                    if (p.Length < 4) continue;
                    DateTime when;
                    if (!DateTime.TryParse(p[1], out when)) when = DateTime.Now;
                    int attempts;
                    if (!int.TryParse(p[2], out attempts)) attempts = 0;
                    _outbox.Add(new OutboxMsg { Number = p[0], When = when, Attempts = attempts, Text = p[3].Replace("\\n", "\n") });
                }
                if (_outbox.Count > 0)
                    Log("Outbox: loaded " + _outbox.Count + " queued message(s).", BrushWarn);
            }
            catch { }
        }

        private void FlushOutbox()
        {
            if (_outbox.Count == 0) return;
            if (_voip == null || !_voip.RelayReady) return;
            List<OutboxMsg> sent = new List<OutboxMsg>();
            foreach (OutboxMsg m in _outbox)
            {
                if (m.Attempts > 5) { sent.Add(m); continue; }  // give up after 5 attempts
                if (_voip.SendChat(m.Number, m.Text))
                {
                    Log("Outbox: delivered to " + m.Number + " — " + m.Text.Substring(0, Math.Min(40, m.Text.Length)), BrushSuccess);
                    ChatPersist("out", m.Number, m.Text);
                    sent.Add(m);
                }
                else m.Attempts++;
            }
            foreach (OutboxMsg m in sent) _outbox.Remove(m);
            if (sent.Count > 0) SaveOutbox();
        }

        private void StartOutboxTimer()
        {
            _outboxFlushTimer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(15) };
            _outboxFlushTimer.Tick += delegate { FlushOutbox(); };
            _outboxFlushTimer.Start();
        }

        // ── Message Reply / Quote ─────────────────────────────────────────
        private void SetReplyTo(ChatMsg m)
        {
            _replyToMsg = m;
            if (_replyPreview != null)
                UpdateReplyPreview();
        }

        private void ClearReplyTo()
        {
            _replyToMsg = null;
            if (_replyPreview != null)
                _replyPreview.Visibility = Visibility.Collapsed;
        }

        private void UpdateReplyPreview()
        {
            if (_replyPreview == null || _replyToMsg == null) return;
            // Find the TextBlock inside the preview border
            StackPanel sp = _replyPreview.Child as StackPanel;
            if (sp == null) return;
            if (sp.Children.Count >= 2)
            {
                (sp.Children[0] as TextBlock).Text = _replyToMsg.Dir == "out" ? "You" : (_voipPeerName ?? "Peer");
                string reply = _replyToMsg.Dir == "vin" || _replyToMsg.Dir == "vout"
                    ? "(voice note)" : FormatChatAttachmentText(_replyToMsg.Text ?? "");
                (sp.Children[1] as TextBlock).Text = reply.Length > 60
                    ? reply.Substring(0, 60) + "…" : reply;
            }
            _replyPreview.Visibility = Visibility.Visible;
        }

        // ── AT command retry queue ────────────────────────────────────────
        private void AtRetryEnqueue(string command, string expected, int timeoutMs, Action<string[]> onSuccess)
        {
            _atRetryQueue.Add(new AtRetryItem
            {
                Command = command,
                Expected = expected,
                TimeoutMs = timeoutMs,
                OnSuccess = onSuccess,
                NextAttempt = DateTime.Now.AddSeconds(2),
                Attempts = 0
            });
        }

        private void StartAtRetryTimer()
        {
            _atRetryTimer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(3) };
            _atRetryTimer.Tick += delegate { ProcessAtRetryQueue(); };
            _atRetryTimer.Start();
        }

        private void ProcessAtRetryQueue()
        {
            if (_atRetryQueue.Count == 0 || !_modem.IsOpen || _busy) return;
            List<AtRetryItem> done = new List<AtRetryItem>();
            foreach (AtRetryItem item in _atRetryQueue)
            {
                if (DateTime.Now < item.NextAttempt) continue;
                if (item.Attempts >= 3) { done.Add(item); Log("AT retry: gave up on " + item.Command, BrushWarn); continue; }
                item.Attempts++;
                AtRetryItem captured = item;
                System.Threading.Tasks.Task.Run(delegate
                {
                    try
                    {
                        string[] r = _modem.SendCommand(captured.Command, captured.Expected, captured.TimeoutMs);
                        bool ok = false;
                        foreach (string l in r) if (Regex.IsMatch(l, @"(^|\s)OK(\s|$)")) ok = true;
                        if (ok)
                        {
                            Dispatcher.BeginInvoke((Action)delegate { if (captured.OnSuccess != null) captured.OnSuccess(r); });
                            _atRetryQueue.Remove(captured);
                        }
                        else
                        {
                            // Exponential backoff: 2s, 8s, 20s
                            captured.NextAttempt = DateTime.Now.AddSeconds(Math.Pow(4, captured.Attempts));
                        }
                    }
                    catch { captured.NextAttempt = DateTime.Now.AddSeconds(10); }
                });
                break;  // one at a time
            }
            foreach (AtRetryItem item in done) _atRetryQueue.Remove(item);
        }
    }

    // ── Supporting data classes ───────────────────────────────────────────

    internal sealed class OutboxMsg
    {
        public string Number;
        public string Text;
        public DateTime When;
        public int Attempts;
    }

    internal sealed class AtRetryItem
    {
        public string Command;
        public string Expected;
        public int TimeoutMs;
        public Action<string[]> OnSuccess;
        public DateTime NextAttempt;
        public int Attempts;
    }

    internal sealed class FileTransferSession
    {
        public string Id;
        public string PeerNumber;
        public string FilePath;
        public string FileName;
        public long SizeBytes;
        public string Direction;   // "in" | "out"
        public string State;       // "offered" | "accepted" | "rejected" | "complete"
        public ChatKey TransferKey;
        public string Sha256;
        public string ReceivedPath;
    }

    internal sealed class UssdReplayItem
    {
        public string Code;
        public DateTime When;
        public string LastResponse;
    }

}
