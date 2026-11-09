using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Threading;

namespace UssdApp
{
    // =====================================================================
    // Call transcription, through whisper.cpp.
    //
    // whisper.cpp transcribes a WAV file and prints text; it has no streaming
    // input, so this works in segments: the remote speaker's PCM is buffered
    // until it holds SegSeconds of audio, written as a mono 16 kHz WAV, and
    // handed to the binary on a worker thread. The audio path never waits for
    // a model, and if the model falls behind, segments are dropped rather than
    // queued forever - a late subtitle is worse than a missing one.
    //
    // Nothing is downloaded or bundled here: if the binary or model is not on
    // this machine the transcriber reports that once and stays inert. That is
    // how this feature coexists with a zero-install, single-exe app.
    // =====================================================================
    public sealed class Transcriber : IDisposable
    {
        public const int Rate = 16000;                    // 16 kHz mono 16-bit
        public const int SegSeconds = 8;                  // audio per whisper run
        const int ProcessTimeoutMs = 45000;

        private readonly object _lock = new object();
        private readonly List<byte[]> _pending = new List<byte[]>();
        private int _pendingBytes;
        private readonly int _segBytes = Rate * 2 * SegSeconds;
        private Thread _worker;
        private readonly AutoResetEvent _haveWork = new AutoResetEvent(false);
        private bool _run, _disposed, _warnedOnce;
        private long _segIndex;
        private string _transcriptPath;
        private StreamWriter _transcript;

        public event Action<string> Line;         // one finished segment
        public event Action<string> Notice;       // progress or failure, for the log

        public string TranscriptPath { get { return _transcriptPath; } }

        private readonly string _exe, _model, _lang;

        public Transcriber(string exe, string model, string lang)
        {
            _exe = exe ?? "";
            _model = model ?? "";
            _lang = string.IsNullOrEmpty(lang) ? "auto" : lang;
        }

        public bool Available
        {
            get { return _exe.Length > 0 && File.Exists(_exe) && _model.Length > 0 && File.Exists(_model); }
        }

        // ---- discovery ----------------------------------------------------
        // A user-installed whisper.cpp is found where the common builds put it,
        // so the Settings fields can be left alone in the easy case.

        public static string FindExe(string configured)
        {
            if (!string.IsNullOrEmpty(configured) && File.Exists(configured)) return configured;
            List<string> tries = new List<string>();
            string home = SafeHome();
            if (home != null)
            {
                tries.Add(Path.Combine(home, "tools", "whisper", "whisper-cli.exe"));
                tries.Add(Path.Combine(home, "tools", "whisper", "main.exe"));
                tries.Add(Path.Combine(home, "whisper-cli.exe"));
            }
            string baseDir = AppDomain.CurrentDomain.BaseDirectory;
            if (!string.IsNullOrEmpty(baseDir))
            {
                tries.Add(Path.Combine(baseDir, "whisper-cli.exe"));
                tries.Add(Path.Combine(baseDir, "main.exe"));
                tries.Add(Path.Combine(baseDir, "tools", "whisper-cli.exe"));
            }
            // A machine-wide install is usually on PATH.
            string path = Environment.GetEnvironmentVariable("PATH") ?? "";
            foreach (string dir in path.Split(';'))
            {
                string d = (dir ?? "").Trim().Trim('"');
                if (d.Length == 0 || d.IndexOfAny(Path.GetInvalidPathChars()) >= 0) continue;
                tries.Add(Path.Combine(d, "whisper-cli.exe"));
                tries.Add(Path.Combine(d, "main.exe"));
            }
            foreach (string t in tries)
                try { if (File.Exists(t)) return t; } catch { }
            return "";
        }

        public static string FindModel(string configured)
        {
            if (!string.IsNullOrEmpty(configured) && File.Exists(configured)) return configured;
            List<string> dirs = new List<string>();
            string home = SafeHome();
            string baseDir = AppDomain.CurrentDomain.BaseDirectory;
            if (home != null) { dirs.Add(Path.Combine(home, "models")); dirs.Add(home); }
            if (!string.IsNullOrEmpty(baseDir)) { dirs.Add(Path.Combine(baseDir, "models")); dirs.Add(baseDir); }
            foreach (string d in dirs)
            {
                try
                {
                    if (!Directory.Exists(d)) continue;
                    // Prefer the quantised models: they are the ones people ship
                    // on a desktop, and the smallest download.
                    string[] bins = Directory.GetFiles(d, "ggml-*.bin");
                    if (bins.Length > 0) return FirstBySize(bins);
                }
                catch { }
            }
            return "";
        }

        static string FirstBySize(string[] bins)
        {
            // Deterministic pick: "base" is the usual desktop default, then the
            // smallest file, so a machine with several models gets a sensible one.
            foreach (string b in bins)
                if (b.IndexOf("base", StringComparison.OrdinalIgnoreCase) >= 0) return b;
            string best = bins[0];
            long bestLen = new FileInfo(best).Length;
            foreach (string b in bins)
            {
                long len = new FileInfo(b).Length;
                if (len < bestLen) { best = b; bestLen = len; }
            }
            return best;
        }

        static string SafeHome()
        {
            try { return Home.Dir; } catch { return null; }
        }

        // ---- lifecycle ----------------------------------------------------

        public void Start(string peerLabel, string nearRecording)
        {
            if (_run) return;
            if (!Available)
            {
                if (!_warnedOnce)
                {
                    _warnedOnce = true;
                    Say("Transcription is off: no whisper.cpp binary or ggml model found. " +
                        "Set both under Settings > Communication.");
                }
                return;
            }
            _transcriptPath = TranscriptPathFor(peerLabel, nearRecording);
            try
            {
                _transcript = new StreamWriter(_transcriptPath, false, Encoding.UTF8);
                _transcript.WriteLine("# transcript for " + peerLabel + " - " + DateTime.Now.ToString("s"));
            }
            catch { _transcript = null; }
            _run = true;
            _worker = new Thread(WorkLoop);
            _worker.IsBackground = true;
            _worker.Name = "UssdTranscriber";
            _worker.Start();
            Say("Transcribing this call with whisper.cpp (" + Path.GetFileName(_model) + ").");
        }

        public void Stop()
        {
            if (!_run) return;
            _run = false;
            _haveWork.Set();
            Thread w = _worker;
            _worker = null;
            // Let a segment already in flight finish rather than killing whisper
            // mid-sentence; it is a background thread, so a stuck one cannot
            // keep the app open.
            try { if (w != null) w.Join(3000); } catch { }
            lock (_lock) { _pending.Clear(); _pendingBytes = 0; }
            try { if (_transcript != null) { _transcript.Flush(); _transcript.Dispose(); } } catch { }
            _transcript = null;
            if (_transcriptPath != null) Say("Transcript saved: " + _transcriptPath);
        }

        public void Dispose() { Stop(); _disposed = true; try { _haveWork.Close(); } catch { } }

        // One remote-audio frame (20 ms, 640 bytes). Called from the audio path.
        public void AddFrame(byte[] pcm)
        {
            if (!_run || pcm == null || pcm.Length == 0) return;
            bool fire = false;
            lock (_lock)
            {
                _pending.Add((byte[])pcm.Clone());
                _pendingBytes += pcm.Length;
                if (_pendingBytes >= _segBytes) fire = true;
            }
            if (fire) _haveWork.Set();
        }

        // ---- worker -------------------------------------------------------

        void WorkLoop()
        {
            while (_run)
            {
                _haveWork.WaitOne(500);
                if (!_run) break;
                byte[] seg = TakeSegment();
                if (seg == null || seg.Length == 0) continue;

                // Overrun protection: if a second segment is already waiting
                // behind this one, drop the oldest backlog. Subtitles must stay
                // near live, or they misrepresent the conversation.
                lock (_lock)
                {
                    while (_pendingBytes >= _segBytes * 2 && _run)
                    {
                        TakeSegmentLocked();
                        Say("Dropped a transcription segment to keep up with the call.");
                    }
                }

                string wav = null;
                try
                {
                    wav = WriteWav(seg);
                    if (wav == null) continue;
                    List<string> lines = Run(seg.Length, wav);
                    if (lines == null) continue;
                    foreach (string ln in lines) Emit(ln);
                }
                catch (Exception ex)
                {
                    if (!_warnedOnce)
                    {
                        _warnedOnce = true;
                        Say("Transcription error: " + ex.Message);
                    }
                }
                finally
                {
                    if (wav != null) try { File.Delete(wav); } catch { }
                }
            }
        }

        byte[] TakeSegment()
        {
            lock (_lock) return TakeSegmentLocked();
        }

        byte[] TakeSegmentLocked()
        {
            if (_pendingBytes < _segBytes)
            {
                // On stop we still want whatever partial audio exists: flush it.
                if (!_run || _pending.Count == 0) return null;
            }
            int want = _segBytes;
            List<byte> outp = new List<byte>(want);
            while (_pending.Count > 0 && outp.Count < want)
            {
                byte[] f = _pending[0];
                _pending.RemoveAt(0);
                outp.AddRange(f);
                _pendingBytes -= f.Length;
                if (_pendingBytes < 0) _pendingBytes = 0;
            }
            if (outp.Count == 0) return null;
            // whisper expects whole samples
            int len = outp.Count - (outp.Count % 2);
            byte[] seg = outp.GetRange(0, len).ToArray();
            if (_pendingBytes < _segBytes) _haveWork.Reset();
            return seg;
        }

        string WriteWav(byte[] pcm)
        {
            try
            {
                string dir = Path.Combine(Path.GetTempPath(), "ussd_transcribe");
                Directory.CreateDirectory(dir);
                string path = Path.Combine(dir, "seg_" + Interlocked.Increment(ref _segIndex) +
                                           "_" + DateTime.Now.ToString("HHmmssfff") + ".wav");
                using (FileStream fs = File.Create(path))
                using (BinaryWriter bw = new BinaryWriter(fs))
                {
                    int dataLen = pcm.Length;
                    bw.Write(Encoding.ASCII.GetBytes("RIFF"));
                    bw.Write(36 + dataLen);
                    bw.Write(Encoding.ASCII.GetBytes("WAVE"));
                    bw.Write(Encoding.ASCII.GetBytes("fmt "));
                    bw.Write(16);
                    bw.Write((short)1);              // PCM
                    bw.Write((short)1);              // mono
                    bw.Write(Rate);
                    bw.Write(Rate * 2);
                    bw.Write((short)2);
                    bw.Write((short)16);
                    bw.Write(Encoding.ASCII.GetBytes("data"));
                    bw.Write(dataLen);
                    bw.Write(pcm);
                }
                return path;
            }
            catch { return null; }
        }

        List<string> Run(int pcmBytes, string wav)
        {
            ProcessStartInfo psi = new ProcessStartInfo
            {
                FileName = _exe,
                Arguments = "-m \"" + _model + "\" -f \"" + wav + "\" -l " + _lang + " -nt -t 2",
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true,
                WorkingDirectory = Path.GetDirectoryName(_exe) ?? ""
            };
            Process p;
            try { p = Process.Start(psi); }
            catch (Exception ex)
            {
                _warnedOnce = true;
                Say("Could not start whisper.cpp: " + ex.Message);
                Stop();
                return null;
            }
            using (p)
            {
                // Both pipes are drained asynchronously. Reading one to the end
                // before the other deadlocks as soon as the child fills the
                // second buffer - which a verbose whisper build will do.
                StringBuilder stdout = new StringBuilder();
                StringBuilder stderr = new StringBuilder();
                object pipeLock = new object();
                p.OutputDataReceived += delegate(object s, DataReceivedEventArgs e)
                {
                    if (e.Data == null) return;
                    lock (pipeLock) stdout.AppendLine(e.Data);
                };
                p.ErrorDataReceived += delegate(object s, DataReceivedEventArgs e)
                {
                    if (e.Data == null) return;
                    lock (pipeLock) stderr.AppendLine(e.Data);
                };
                try { p.BeginOutputReadLine(); p.BeginErrorReadLine(); } catch { }
                bool exited = false;
                try { exited = p.WaitForExit(ProcessTimeoutMs); } catch { }
                if (!exited)
                {
                    try { p.Kill(); } catch { }
                    _warnedOnce = true;
                    Say("whisper.cpp timed out on a segment; transcription paused.");
                    Stop();
                    return null;
                }
                string text;
                lock (pipeLock) text = stdout.ToString();
                if (text.Length == 0)
                {
                    // An unparseable model path usually surfaces only on stderr.
                    string why;
                    lock (pipeLock) why = stderr.ToString().Trim();
                    if (why.Length > 0 && !_warnedOnce)
                    {
                        _warnedOnce = true;
                        Say("whisper.cpp: " + why.Split('\n')[0]);
                    }
                    return null;
                }
                return Parse(text);
            }
        }

        // whisper prints its own diagnostics mixed in with the text. Keep the
        // sentences and drop the machinery.
        static List<string> Parse(string stdout)
        {
            List<string> outp = new List<string>();
            foreach (string raw in stdout.Replace("\r", "").Split('\n'))
            {
                string s = (raw ?? "").Trim();
                if (s.Length == 0) continue;
                if (s.StartsWith("load_", StringComparison.OrdinalIgnoreCase) ||
                    s.StartsWith("whisper_", StringComparison.OrdinalIgnoreCase) ||
                    s.StartsWith("system_info", StringComparison.OrdinalIgnoreCase) ||
                    s.StartsWith("print_usage", StringComparison.OrdinalIgnoreCase)) continue;
                // Without -nt (older builds) lines are "[a --> b]   text".
                int arrow = s.IndexOf("-->", StringComparison.Ordinal);
                if (arrow >= 0)
                {
                    int bracket = s.IndexOf(']');
                    if (bracket > arrow) s = s.Substring(bracket + 1).Trim();
                    else s = "";
                }
                if (s.Length == 0) continue;
                if (s.StartsWith("(", StringComparison.Ordinal)) continue;   // (no audio detected)
                outp.Add(s);
            }
            return outp;
        }

        void Emit(string line)
        {
            try
            {
                if (_transcript != null)
                {
                    _transcript.WriteLine(DateTime.Now.ToString("HH:mm:ss") + "  " + line);
                    _transcript.Flush();
                }
            }
            catch { }
            Action<string> h = Line;
            if (h != null) h(line);
        }

        void Say(string s)
        {
            Action<string> h = Notice;
            if (h != null) h(s);
        }

        // One deliberate no-op run, so a user can prove the binary, the model and
        // the argument line all work before they are halfway through a call.
        public string SelfTest()
        {
            if (_exe.Length == 0 || !File.Exists(_exe))
                return "No whisper.cpp binary found - set the path (or install whisper-cli on PATH).";
            if (_model.Length == 0 || !File.Exists(_model))
                return "Found " + Path.GetFileName(_exe) + " but no ggml model - point the model path at a ggml-*.bin file.";
            string wav = WriteWav(new byte[Rate * 2 * 2]);       // 2 s of silence
            if (wav == null) return "Could not write the test audio.";
            try
            {
                List<string> lines = Run(0, wav);
                if (lines == null) return "Failed to run - see the log for the reason.";
                if (lines.Count == 0) return "OK: " + Path.GetFileName(_exe) + " + " + Path.GetFileName(_model) +
                                             " responded correctly (silence produced no text).";
                return "OK: it answered - \"" + lines[0] + "\"";
            }
            finally { try { File.Delete(wav); } catch { } }
        }

        // The transcript sits next to the recording it belongs to. With recording
        // off, it still lands in recordings/ so one folder holds a call's artefacts.
        static string TranscriptPathFor(string peerLabel, string nearRecording)
        {
            try
            {
                string dir = Path.Combine(SafeHome() ?? AppDomain.CurrentDomain.BaseDirectory, "recordings");
                Directory.CreateDirectory(dir);
                string stamp = DateTime.Now.ToString("yyyyMMdd_HHmmss");
                string safe = Sanitize(peerLabel);
                if (!string.IsNullOrEmpty(nearRecording) && File.Exists(nearRecording))
                {
                    string alt = Path.ChangeExtension(nearRecording, ".txt");
                    if (alt.ToLowerInvariant().EndsWith(".txt")) return alt;
                }
                return Path.Combine(dir, "transcript_" + stamp + "_" + safe + ".txt");
            }
            catch { return null; }
        }

        static string Sanitize(string s)
        {
            string r = string.IsNullOrEmpty(s) ? "peer" : s;
            char[] bad = Path.GetInvalidFileNameChars();
            for (int i = 0; i < r.Length; i++)
                if (Array.IndexOf(bad, r[i]) >= 0) r = r.Replace(r[i], '_');
            return r.Length > 40 ? r.Substring(0, 40) : r;
        }
    }
}
