using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Threading;

namespace UssdApp
{
    // =====================================================================
    // Radio transports: KISS framing, an AX.25-shaped header, and
    // fragment/reassembly.
    //
    // Why KISS rather than a vendor SDK: it is a two-page protocol that every
    // modern TNC speaks - a packet radio controller, an RNode in KISS mode (the
    // usual LoRa board), and Reticulum's own KISS modem interface. Writing to it
    // means one adapter can serve licence-free LoRa, licence HAM packet radio and
    // Reticulum alike, and nothing here is tied to a manufacturer's library.
    //
    // Two honesty caveats, stated where the code can be read:
    //   - Nothing in this file has been on the air. Framing, the checksum and
    //     fragmentation are verified in-process; whether a particular board
    //     keys its PTT on a given port is hardware, and only the operator with
    //     the radio can find that out.
    //   - The header is AX.25-shaped but carries our own CRC, so a frame is
    //     provably intact between two instances of this app. It is NOT claimed
    //     to interoperate with third-party AX.25 software.
    //
    // Capability declaration is the part the rest of the app depends on: a radio
    // link states its frame ceiling and its bit rate, and TransportRouter then
    // refuses media over it instead of quietly turning a call into noise. Text,
    // presence and OTP codes fit; voice does not.
    // =====================================================================

    // ---- KISS: byte-stuffed framing -------------------------------------
    // A frame is FEND, payload with escapes, FEND. FEND inside the payload
    // becomes FESC TFEND, and FESC itself becomes FESC TFESC.
    public static class Kiss
    {
        public const byte FEND = 0xC0;
        public const byte FESC = 0xDB;
        public const byte TFEND = 0xDC;
        public const byte TFESC = 0xDD;

        public static byte[] Encode(byte[] payload)
        {
            List<byte> outp = new List<byte>(payload.Length + 8);
            outp.Add(FEND);
            foreach (byte b in payload)
            {
                if (b == FEND) { outp.Add(FESC); outp.Add(TFEND); }
                else if (b == FESC) { outp.Add(FESC); outp.Add(TFESC); }
                else outp.Add(b);
            }
            outp.Add(FEND);
            return outp.ToArray();
        }

        // Incremental decoder: feed it whatever bytes arrived and take back the
        // frames that completed. Serial data arrives in arbitrary chunks, so a
        // one-shot parse of a buffer would either lose a split frame or decode
        // garbage across two frames.
        public sealed class Stream
        {
            readonly List<byte> _cur = new List<byte>();
            bool _escaped;
            bool _open;
            readonly List<byte[]> _complete = new List<byte[]>();

            public void Feed(byte[] data, int count)
            {
                for (int i = 0; i < count; i++)
                {
                    byte b = data[i];
                    if (b == FEND)
                    {
                        // FEND closes a frame; a second FEND with nothing between
                        // is the filler TNCs emit between frames, not an empty frame.
                        if (_open && _cur.Count > 0 && !_escaped) _complete.Add(_cur.ToArray());
                        _cur.Clear();
                        _escaped = false;
                        _open = true;
                        continue;
                    }
                    if (!_open) continue;                       // bytes before the first FEND
                    if (b == FESC) { _escaped = true; continue; }
                    if (_escaped)
                    {
                        if (b == TFEND) _cur.Add(FEND);
                        else if (b == TFESC) _cur.Add(FESC);
                        else _open = false;                     // invalid escape: resynchronise
                        _escaped = false;
                        continue;
                    }
                    // A radio link is lossy. Without a ceiling one corrupted
                    // length byte lets one frame eat the buffer for minutes.
                    if (_cur.Count > 8192) { _cur.Clear(); _open = false; continue; }
                    _cur.Add(b);
                }
            }

            public bool TryNext(out byte[] frame)
            {
                if (_complete.Count == 0) { frame = null; return false; }
                frame = _complete[0];
                _complete.RemoveAt(0);
                return true;
            }

            public void Reset() { _cur.Clear(); _escaped = false; _open = false; _complete.Clear(); }
        }
    }

    // ---- AX.25 UI frames -------------------------------------------------
    public static class Axa25
    {
        const byte PidNoLayer3 = 0xF0;
        const byte ControlUi = 0x03;

        // Callsigns are 6 characters, space-padded, shifted left one bit, then an
        // SSID byte. Digits are legal, which is what lets an app number stand in
        // for a callsign on a private mesh.
        public static byte[] Addr(string call, byte ssid)
        {
            string c = (call ?? "").Trim().ToUpperInvariant();
            if (c.Length > 6) c = c.Substring(0, 6);
            byte[] b = new byte[7];
            for (int i = 0; i < 6; i++)
            {
                char ch = i < c.Length ? c[i] : ' ';
                b[i] = (byte)((ch << 1) & 0xFE);                // bit 0 clear on every address byte
            }
            b[5] |= 1;                                          // ...except the last, which terminates
            b[6] = (byte)(0x60 | (ssid & 0x0F));
            return b;
        }

        public static string ReadAddr(byte[] f, int off)
        {
            StringBuilder sb = new StringBuilder(6);
            for (int i = 0; i < 6; i++) sb.Append((char)((f[off + i] >> 1) & 0x7F));
            return sb.ToString().Trim();
        }

        public static byte[] Build(string from, string to, byte[] info)
        {
            byte[] dst = Addr(to, 0);
            byte[] src = Addr(from, 0);
            // 14 address bytes + control + PID, then the payload.
            byte[] withPid = new byte[16 + info.Length];
            Buffer.BlockCopy(dst, 0, withPid, 0, 7);
            Buffer.BlockCopy(src, 0, withPid, 7, 7);
            withPid[14] = ControlUi;
            withPid[15] = PidNoLayer3;
            Buffer.BlockCopy(info, 0, withPid, 16, info.Length);

            ushort fcs = Crc(withPid, withPid.Length);
            byte[] outp = new byte[withPid.Length + 2];
            Buffer.BlockCopy(withPid, 0, outp, 0, withPid.Length);
            outp[outp.Length - 2] = (byte)(fcs & 0xFF);
            outp[outp.Length - 1] = (byte)((fcs >> 8) & 0xFF);
            return outp;
        }

        public static bool Parse(byte[] frame, out string from, out string to, out byte[] info)
        {
            from = ""; to = ""; info = null;
            // 14 address bytes + control + PID + 2 FCS
            if (frame == null || frame.Length < 18) return false;
            ushort got = (ushort)(frame[frame.Length - 2] | (frame[frame.Length - 1] << 8));
            ushort want = Crc(frame, frame.Length - 2);
            if (got != want) return false;                      // corrupted or not ours
            if (frame[14] != ControlUi) return false;
            to = ReadAddr(frame, 0);
            from = ReadAddr(frame, 7);
            int len = frame.Length - (14 + 1 + 1 + 2);
            if (len < 0) return false;
            info = new byte[len];
            if (len > 0) Buffer.BlockCopy(frame, 16, info, 0, len);
            return true;
        }

        // CRC-16/CCITT (poly 0x1021, init 0xFFFF), bit at a time, no reflection.
        // This is deliberately OUR integrity check, not the reflected FCS a real
        // TNC puts on the wire: a hand-transcribed version of the AX.25 routine
        // silently stopped depending on the payload, and the flipped-bit test
        // caught it. So these frames are for links between instances of this app
        // over a KISS pipe or serial line - not an interop claim about anyone
        // else's radio, which nothing here can verify without hardware.
        public static ushort Crc(byte[] data, int len)
        {
            ushort fcs = 0xFFFF;
            for (int i = 0; i < len; i++)
            {
                fcs ^= (ushort)(data[i] << 8);
                for (int b = 0; b < 8; b++)
                    fcs = (ushort)((fcs & 0x8000) != 0 ? (fcs << 1) ^ 0x1021 : (fcs << 1));
            }
            return fcs;
        }

        // A callsign from an app number. AX.25 gives six characters, so a full
        // 700-XXXXXXX number cannot be carried literally; the tail can, and it is
        // unique inside any mesh small enough to be on one radio.
        public static string CallsignForNumber(string number)
        {
            StringBuilder d = new StringBuilder(7);
            foreach (char c in (number ?? "").ToUpperInvariant())
                if ((c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')) d.Append(c);
            if (d.Length == 0) return "UNKNOWN";
            string s = d.ToString();
            return s.Length <= 6 ? s : s.Substring(s.Length - 6);
        }
    }

    // ---- Fragmentation ---------------------------------------------------
    // A chat frame is routinely larger than a radio payload window. Without
    // splitting, the router would have to refuse it; with silent truncation it
    // would deliver damaged text. So: split with a sequence header, reassemble
    // at the far end, drop anything that never completes.
    public sealed class Fragmenter
    {
        const byte Version = 1;
        const int HeaderLen = 6;        // ver, id(2), index, total, reserved
        public const int MaxFragments = 32;

        sealed class Piece
        {
            public int Total;
            public byte[][] Parts;
            public int Got;
            public long LastSeen;
        }

        readonly Dictionary<ushort, Piece> _in = new Dictionary<ushort, Piece>();
        ushort _nextId = 1;
        readonly object _lock = new object();

        public static int PayloadRoom(int maxInfoBytes) { return Math.Max(0, maxInfoBytes - HeaderLen); }

        // One message in, N AX.25 info payloads out.
        public List<byte[]> Split(byte[] payload, int maxInfoBytes)
        {
            List<byte[]> outp = new List<byte[]>();
            if (payload == null || payload.Length == 0) return outp;
            int room = PayloadRoom(maxInfoBytes);
            if (room <= 0) return outp;
            int total = (payload.Length + room - 1) / room;
            if (total > MaxFragments) total = MaxFragments;      // caller must respect the cap
            ushort id = _nextId++;
            for (int i = 0; i < total; i++)
            {
                int off = i * room;
                int len = Math.Min(room, payload.Length - off);
                if (len <= 0) break;
                byte[] info = new byte[HeaderLen + len];
                info[0] = Version;
                info[1] = (byte)(id >> 8);
                info[2] = (byte)(id & 0xFF);
                info[3] = (byte)i;
                info[4] = (byte)total;
                info[5] = 0;
                Buffer.BlockCopy(payload, off, info, HeaderLen, len);
                outp.Add(info);
            }
            return outp;
        }

        // Returns the whole message when the last missing piece lands, else null.
        public byte[] Feed(byte[] info)
        {
            if (info == null || info.Length <= HeaderLen) return null;
            if (info[0] != Version) return null;
            ushort id = (ushort)((info[1] << 8) | info[2]);
            int idx = info[3], total = info[4];
            if (total < 1 || idx >= total || total > MaxFragments) return null;
            int len = info.Length - HeaderLen;
            lock (_lock)
            {
                Piece p;
                if (!_in.TryGetValue(id, out p))
                {
                    p = new Piece { Total = total, Parts = new byte[total][], LastSeen = DateTime.Now.Ticks };
                    _in[id] = p;
                    PruneLocked();
                }
                if (p.Total != total) { _in.Remove(id); return null; }     // id reused mid-flight
                if (p.Parts[idx] == null)
                {
                    byte[] part = new byte[len];
                    Buffer.BlockCopy(info, HeaderLen, part, 0, len);
                    p.Parts[idx] = part;
                    p.Got++;
                }
                p.LastSeen = DateTime.Now.Ticks;
                if (p.Got < p.Total) return null;
                _in.Remove(id);
                int total2 = 0;
                foreach (byte[] b in p.Parts) total2 += b.Length;
                byte[] whole = new byte[total2];
                int at = 0;
                foreach (byte[] b in p.Parts) { Buffer.BlockCopy(b, 0, whole, at, b.Length); at += b.Length; }
                return whole;
            }
        }

        // A lost fragment must not leak a slot forever: 40 years of dictionary
        // entries is a slow memory leak on a machine left running as a node.
        void PruneLocked()
        {
            long now = DateTime.Now.Ticks;
            List<ushort> dead = new List<ushort>();
            foreach (KeyValuePair<ushort, Piece> kv in _in)
                if (now - kv.Value.LastSeen > TimeSpan.TicksPerSecond * 180) dead.Add(kv.Key);
            foreach (ushort k in dead) _in.Remove(k);
            if (_in.Count > 256)
            {
                dead.Clear();
                foreach (KeyValuePair<ushort, Piece> kv in _in) { dead.Add(kv.Key); if (dead.Count >= _in.Count - 128) break; }
                foreach (ushort k in dead) _in.Remove(k);
            }
        }

        public int Pending { get { lock (_lock) return _in.Count; } }
    }

    // ---- The transport ---------------------------------------------------
    // One ITransport over any byte stream: a SerialPort at runtime, a pipe or a
    // MemoryStream pair in a test. It owns the KISS codec, the AX.25 header and
    // the fragmenter, and it declares its ceiling so the router can be honest.
    public sealed class RadioTransport : ITransport, IDisposable
    {
        public event Action<string, byte[]> Frame;

        readonly string _name;
        readonly Stream _port;
        readonly int _bitRate;
        readonly int _maxInfo;
        readonly bool _carries;                 // true = this node repeats for others
        readonly Kiss.Stream _kiss = new Kiss.Stream();
        readonly Fragmenter _frag = new Fragmenter();
        readonly object _write = new object();
        Thread _reader;
        volatile bool _run;
        string _error = "";
        string _myCallsign = "NOCALL";
        readonly Dictionary<string, string> _calls = new Dictionary<string, string>();  // number -> callsign

        public RadioTransport(string name, Stream port, int bitRate, int maxInfoBytes, bool carriesForOthers)
        {
            _name = name;
            _port = port;
            _bitRate = bitRate;
            _maxInfo = maxInfoBytes;
            _carries = carriesForOthers;
        }

        public string Name { get { return _name; } }
        // What the router judges us on. Payload, not airtime: an AX.25 UI frame
        // carries at most this many info bytes before addressing and FCS.
        public int MaxFrameBytes { get { return Fragmenter.PayloadRoom(_maxInfo) * Fragmenter.MaxFragments; } }
        public int BitRate { get { return _bitRate; } }
        public bool RequiresConsent { get { return _carries; } }
        public bool Ready { get { return _run && _port != null && _port.CanWrite; } }
        public string LastError { get { return _error; } }

        public void Start(string myCallsign)
        {
            _myCallsign = string.IsNullOrEmpty(myCallsign) ? "NOCALL" : myCallsign;
            if (_run) return;
            _run = true;
            _reader = new Thread(ReadLoop);
            _reader.IsBackground = true;
            _reader.Name = "Radio-" + _name;
            _reader.Start();
        }

        // A peer's app number is what callers address; the radio needs a
        // callsign. Explicit mappings win, the derived tail is the fallback.
        public void Map(string number, string callsign)
        {
            if (!string.IsNullOrEmpty(number) && !string.IsNullOrEmpty(callsign))
                _calls[number] = callsign;
        }

        // Incoming frames carry a callsign, but the chat dispatcher is keyed by
        // app number. The map is small and explicit, so a reverse scan beats
        // keeping a second dictionary that can drift out of step with the first.
        public string NumberForCall(string callsign)
        {
            if (string.IsNullOrEmpty(callsign)) return "";
            foreach (KeyValuePair<string, string> kv in _calls)
                if (string.Equals(kv.Value, callsign, StringComparison.OrdinalIgnoreCase)) return kv.Key;
            return callsign;
        }

        string CallFor(string number)
        {
            string c;
            if (_calls.TryGetValue(number ?? "", out c)) return c;
            return Axa25.CallsignForNumber(number);
        }

        public bool Send(string to, byte[] frame)
        {
            if (!Ready || frame == null || frame.Length == 0) return false;
            if (frame.Length > MaxFrameBytes) { _error = "frame exceeds the link"; return false; }
            byte[][] parts;
            lock (_write)
            {
                List<byte[]> infos = _frag.Split(frame, _maxInfo);
                if (infos.Count == 0) { _error = "nothing to send"; return false; }
                parts = infos.ToArray();
            }
            foreach (byte[] info in parts)
            {
                byte[] ax = Axa25.Build(_myCallsign, CallFor(to), info);
                byte[] wire = Kiss.Encode(ax);
                lock (_write)
                {
                    try { _port.Write(wire, 0, wire.Length); }
                    catch (Exception ex) { _error = ex.Message; return false; }
                }
            }
            return true;
        }

        void ReadLoop()
        {
            byte[] buf = new byte[1024];
            while (_run)
            {
                int n;
                try { n = _port.Read(buf, 0, buf.Length); }
                catch (Exception ex) { if (_run) { _error = ex.Message; _run = false; } return; }
                if (n <= 0) continue;
                _kiss.Feed(buf, n);
                byte[] ax;
                while (_kiss.TryNext(out ax))
                {
                    string from, to;
                    byte[] info;
                    if (!Axa25.Parse(ax, out from, out to, out info)) continue;
                    byte[] whole = _frag.Feed(info);
                    if (whole == null) continue;
                    Action<string, byte[]> h = Frame;
                    if (h != null) h(from, whole);
                }
            }
        }

        public void Stop()
        {
            _run = false;
            try { if (_port != null) _port.Close(); } catch { }
        }

        public void Dispose() { Stop(); }
    }
}
