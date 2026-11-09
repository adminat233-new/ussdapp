using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;

namespace UssdApp
{
    // =====================================================================
    // Sticker packs and their sync between two devices.
    //
    // A pack is a folder: stickers/<packId>/manifest.json plus the frames it
    // lists. Frames are PNG or GIF. (GIF animates natively in WPF's Image;
    // APNG and WebP would need a codec we cannot ship inside a single-exe,
    // no-install build, so they are deliberately not part of the format.)
    //
    // Sync is a delta, never a dump. Each side publishes the content hash of
    // every frame it holds; only the difference crosses the wire. The same
    // hash does three jobs at once:
    //   - it dedups (a sticker offered twice lands once),
    //   - it selects (missing = remote hashes minus mine),
    //   - it verifies (an imported frame whose bytes do not hash to the offered
    //     hash is thrown away rather than trusted).
    //
    // Wire lines, all of which ride inside the sealed chat payload next to
    // CHAT and VAUD - sticker bytes are content and never travel in clear:
    //   STKIT_REQ|<packId>                                what do you hold?
    //   STKIT_CAT|<packId>|<hash>=<file>,<hash>=<file>,...   what I hold
    //   STKIT_WANT|<packId>|<hash>,<hash>,...             send me these
    //   STKIT_BIN|<packId>|<file>|<hash>|<base64>         one frame
    // =====================================================================
    public static class StickerSync
    {
        public const string Verb = "STKIT_";
        public const string SyncPack = "shared";        // the folder sync converges on
        public const int MaxWantPerPack = 24;          // per exchange
        public const int MaxFrameBytes = 512 * 1024;   // one frame, generous
        public const int MaxCatalogEntries = 200;
        static readonly string[] FrameExt = { ".png", ".gif" };

        public static bool IsStickerLine(string line)
        {
            return !string.IsNullOrEmpty(line) && line.StartsWith(Verb, StringComparison.Ordinal);
        }

        public static string MakeReq(string packId)
        {
            return "STKIT_REQ|" + SafePackId(packId);
        }

        public static bool IsReq(string line, out string packId)
        {
            packId = "";
            if (string.IsNullOrEmpty(line) || !line.StartsWith("STKIT_REQ", StringComparison.Ordinal)) return false;
            string[] p = line.Split('|');
            packId = p.Length >= 2 ? SafePackId(p[1]) : "";
            return true;
        }

        // ---- hashing ----------------------------------------------------

        public static string HashBytes(byte[] data)
        {
            if (data == null) return "";
            using (SHA256 sha = SHA256.Create())
            {
                byte[] h = sha.ComputeHash(data);
                StringBuilder sb = new StringBuilder(16);
                // 64 bits of SHA-256: collision-proof for a few hundred stickers
                // and short enough to keep catalogue lines small.
                for (int i = 0; i < 8; i++) sb.Append(h[i].ToString("x2"));
                return sb.ToString();
            }
        }

        public static string HashFile(string path)
        {
            try
            {
                byte[] data = File.ReadAllBytes(path);
                return HashBytes(data);
            }
            catch { return ""; }
        }

        // ---- file naming ------------------------------------------------

        // A peer chooses the name in STKIT_BIN, so it is treated as hostile:
        // no directory components, no traversal, no characters that break the
        // line framing, and it must end in a frame extension we can render.
        public static string SafeName(string fileName)
        {
            string raw = (fileName ?? "").Replace('\\', '/');
            int slash = raw.LastIndexOf('/');
            if (slash >= 0) raw = raw.Substring(slash + 1);
            StringBuilder sb = new StringBuilder(raw.Length);
            foreach (char ch in raw)
            {
                if ((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') ||
                    (ch >= '0' && ch <= '9') || ch == '.' || ch == '-' || ch == '_')
                    sb.Append(ch);
                else sb.Append('_');
            }
            string name = sb.ToString().TrimStart('.');
            if (name.Length == 0) name = "sticker.png";
            if (name.Length > 60) name = name.Substring(name.Length - 60);
            string ext = Path.GetExtension(name).ToLowerInvariant();
            bool known = false;
            foreach (string e in FrameExt) if (e == ext) { known = true; break; }
            if (!known) name = (name.Length > 55 ? name.Substring(0, 55) : name) + ".png";
            return name;
        }

        // A pack id becomes a folder name, so it gets the same treatment.
        public static string SafePackId(string packId)
        {
            string raw = (packId ?? "").Trim().ToLowerInvariant();
            StringBuilder sb = new StringBuilder(raw.Length);
            foreach (char ch in raw)
                sb.Append(((ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') ||
                           ch == '-' || ch == '_') ? ch : '-');
            string id = sb.ToString().Trim('-');
            if (id.Length == 0) id = "shared";
            return id.Length > 40 ? id.Substring(0, 40) : id;
        }

        // ---- catalogue --------------------------------------------------

        // hash -> file name, for one pack folder.
        public static Dictionary<string, string> CatalogOf(string packDir)
        {
            Dictionary<string, string> map = new Dictionary<string, string>();
            if (!Directory.Exists(packDir)) return map;
            string[] files;
            try { files = Directory.GetFiles(packDir); }
            catch { return map; }
            foreach (string f in files)
            {
                string ext = Path.GetExtension(f).ToLowerInvariant();
                bool frame = false;
                foreach (string e in FrameExt) if (e == ext) { frame = true; break; }
                if (!frame) continue;
                string h = HashFile(f);
                if (h.Length == 0 || map.ContainsKey(h)) continue;
                map[h] = Path.GetFileName(f);
                if (map.Count >= MaxCatalogEntries) break;
            }
            return map;
        }

        // Everything this device holds, across every pack: two devices converge
        // on one sticker set rather than negotiating pack by pack. Names are
        // remembered so a wanted hash can be sent back with a sensible file name.
        public static Dictionary<string, string> CatalogAll(string root)
        {
            Dictionary<string, string> map = new Dictionary<string, string>();
            if (string.IsNullOrEmpty(root) || !Directory.Exists(root)) return map;
            AddFramesFrom(map, root);
            string[] subs;
            try { subs = Directory.GetDirectories(root); } catch { return map; }
            foreach (string sub in subs) AddFramesFrom(map, sub);
            return map;
        }

        static void AddFramesFrom(Dictionary<string, string> map, string dir)
        {
            string[] files;
            try { files = Directory.GetFiles(dir); } catch { return; }
            foreach (string f in files)
            {
                string ext = Path.GetExtension(f).ToLowerInvariant();
                bool frame = false;
                foreach (string e in FrameExt) if (e == ext) { frame = true; break; }
                if (!frame) continue;
                string h = HashFile(f);
                if (h.Length == 0 || map.ContainsKey(h)) continue;
                map[h] = Path.GetFileName(f);
                if (map.Count >= MaxCatalogEntries) return;
            }
        }

        // Full path of the frame holding this hash, or null. Names on the wire
        // are just labels, so a WANT answered later has to re-locate the bytes.
        public static string FindFrame(string root, string hash)
        {
            if (string.IsNullOrEmpty(root) || string.IsNullOrEmpty(hash) || !Directory.Exists(root)) return null;
            string here = FindFrameIn(root, hash);
            if (here != null) return here;
            string[] subs;
            try { subs = Directory.GetDirectories(root); } catch { return null; }
            foreach (string sub in subs)
            {
                string hit = FindFrameIn(sub, hash);
                if (hit != null) return hit;
            }
            return null;
        }

        static string FindFrameIn(string dir, string hash)
        {
            string[] files;
            try { files = Directory.GetFiles(dir); } catch { return null; }
            foreach (string f in files)
            {
                string ext = Path.GetExtension(f).ToLowerInvariant();
                bool frame = false;
                foreach (string e in FrameExt) if (e == ext) { frame = true; break; }
                if (!frame) continue;
                if (string.Equals(HashFile(f), hash, StringComparison.OrdinalIgnoreCase)) return f;
            }
            return null;
        }

        public static string MakeCat(string packId, Dictionary<string, string> catalog)
        {
            StringBuilder sb = new StringBuilder("STKIT_CAT|" + SafePackId(packId) + "|");
            bool first = true;
            foreach (KeyValuePair<string, string> kv in catalog)
            {
                if (!first) sb.Append(',');
                sb.Append(kv.Key).Append('=').Append(kv.Value);
                first = false;
            }
            return sb.ToString();
        }

        // Returns packId and the hash -> name map from a CAT line.
        public static bool TryParseCat(string line, out string packId, out Dictionary<string, string> catalog)
        {
            packId = "";
            catalog = new Dictionary<string, string>();
            string[] p = (line ?? "").Split('|');
            if (p.Length < 2 || p[0] != "STKIT_CAT") return false;
            packId = SafePackId(p[1]);
            if (p.Length < 3 || string.IsNullOrEmpty(p[2])) return true;   // empty pack
            foreach (string entry in p[2].Split(','))
            {
                int eq = entry.IndexOf('=');
                if (eq <= 0) continue;
                string h = entry.Substring(0, eq);
                string f = SafeName(entry.Substring(eq + 1));
                if (h.Length == 16) catalog[h] = f;
            }
            return true;
        }

        // Hashes the remote side has that we do not.
        public static List<string> Missing(Dictionary<string, string> remote, Dictionary<string, string> mine)
        {
            List<string> outp = new List<string>();
            if (remote == null) return outp;
            foreach (string h in remote.Keys)
            {
                if (mine != null && mine.ContainsKey(h)) continue;
                outp.Add(h);
                if (outp.Count >= MaxWantPerPack) break;
            }
            return outp;
        }

        public static string MakeWant(string packId, List<string> hashes)
        {
            // C# 5 (the pinned csc.exe) will not take `new List<string>()` on the
            // right of ?? inside a parenthesised expression, so spell it out.
            string joined = hashes == null ? "" : string.Join(",", hashes.ToArray());
            return "STKIT_WANT|" + SafePackId(packId) + "|" + joined;
        }

        public static bool TryParseWant(string line, out string packId, out List<string> hashes)
        {
            packId = "";
            hashes = new List<string>();
            string[] p = (line ?? "").Split('|');
            if (p.Length < 2 || p[0] != "STKIT_WANT") return false;
            packId = SafePackId(p[1]);
            if (p.Length >= 3)
            {
                foreach (string h in p[2].Split(','))
                {
                    string t = h.Trim().ToLowerInvariant();
                    if (t.Length == 16) hashes.Add(t);
                }
            }
            return true;
        }

        public static string MakeBin(string packId, string fileName, byte[] data)
        {
            return "STKIT_BIN|" + SafePackId(packId) + "|" + SafeName(fileName) + "|" +
                   HashBytes(data) + "|" + Convert.ToBase64String(data);
        }

        public static bool TryParseBin(string line, out string packId, out string fileName,
                                       out string hash, out byte[] data)
        {
            packId = ""; fileName = ""; hash = ""; data = null;
            string[] p = (line ?? "").Split(new char[] { '|' }, 5);
            if (p.Length < 5 || p[0] != "STKIT_BIN") return false;
            packId = SafePackId(p[1]);
            fileName = SafeName(p[2]);
            hash = p[3].Trim().ToLowerInvariant();
            if (hash.Length != 16) return false;
            try { data = Convert.FromBase64String(p[4]); }
            catch { return false; }
            return data != null && data.Length > 0 && data.Length <= MaxFrameBytes;
        }

        // Store one frame if we do not already hold it and the bytes match the
        // hash that was offered. Returns the path, or null when nothing was
        // written (duplicate, mismatch, or a rejected name).
        public static string Import(string root, string packId, string fileName, string hash, byte[] data)
        {
            if (data == null || data.Length == 0 || data.Length > MaxFrameBytes) return null;
            string id = SafePackId(packId);
            string name = SafeName(fileName);
            string dir = Path.Combine(root, id);
            string target = Path.Combine(dir, name);
            // Never step outside the stickers root, whatever the peer sent.
            if (!WithinRoot(root, target)) return null;
            if (HashBytes(data) != hash) return null;        // not what was offered
            try
            {
                if (!Directory.Exists(dir)) Directory.CreateDirectory(dir);
                // Same content already on disk under some other name: skip it.
                foreach (string existing in CatalogOf(dir).Keys)
                    if (existing == hash) return null;
                File.WriteAllBytes(target, data);
                return target;
            }
            catch { return null; }
        }

        static bool WithinRoot(string root, string target)
        {
            try
            {
                string r = Path.GetFullPath(root).TrimEnd('\\', '/');
                string t = Path.GetFullPath(target);
                return t.StartsWith(r + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase) ||
                       string.Equals(t, r, StringComparison.OrdinalIgnoreCase);
            }
            catch { return false; }
        }

        // ---- manifest ---------------------------------------------------

        // manifest.json sits in the pack folder and lists the frames it holds.
        // It is rebuilt from the folder, so a hand-added PNG is picked up too.
        public static void WriteManifest(string packDir, string packId, string title, string author)
        {
            Dictionary<string, string> cat = CatalogOf(packDir);
            StringBuilder sb = new StringBuilder();
            sb.Append("{\n  \"id\": \"").Append(Json(Escape(packId))).Append("\",\n");
            sb.Append("  \"name\": \"").Append(Json(Escape(title))).Append("\",\n");
            sb.Append("  \"author\": \"").Append(Json(Escape(author))).Append("\",\n");
            sb.Append("  \"frames\": [\n");
            bool first = true;
            foreach (KeyValuePair<string, string> kv in cat)
            {
                if (!first) sb.Append(",\n");
                first = false;
                sb.Append("    { \"f\": \"").Append(Json(kv.Value))
                  .Append("\", \"h\": \"").Append(Json(kv.Key)).Append("\" }");
            }
            sb.Append(first ? "  ]\n" : "\n  ]\n");
            sb.Append("}\n");
            try { File.WriteAllText(Path.Combine(packDir, "manifest.json"), sb.ToString(), Encoding.UTF8); }
            catch { }
        }

        static string Json(string s) { return (s ?? "").Replace("\\", "\\\\").Replace("\"", "\\\""); }
        static string Escape(string s) { return (s ?? "").Trim(); }

        // ---- zipped pack ------------------------------------------------

        // A pack is shared as a zip of manifest.json + frames, so one download
        // carries the whole set and the format stays inspectable.
        public static string ExportZip(string packDir, string outPath)
        {
            if (!Directory.Exists(packDir)) return null;
            try
            {
                if (File.Exists(outPath)) File.Delete(outPath);
                using (FileStream fs = File.Create(outPath))
                using (ZipArchive zip = new ZipArchive(fs, ZipArchiveMode.Create))
                {
                    foreach (string f in Directory.GetFiles(packDir))
                    {
                        string ext = Path.GetExtension(f).ToLowerInvariant();
                        if (ext != ".png" && ext != ".gif" && ext != ".json") continue;
                        ZipArchiveEntry e = zip.CreateEntry(Path.GetFileName(f), CompressionLevel.NoCompression);
                        using (Stream es = e.Open())
                        using (FileStream src = File.OpenRead(f))
                            src.CopyTo(es);
                    }
                }
                return outPath;
            }
            catch { return null; }
        }

        public static int ImportZip(string root, string zipPath, string packId)
        {
            string id = SafePackId(packId);
            int added = 0;
            try
            {
                using (FileStream fs = File.OpenRead(zipPath))
                using (ZipArchive zip = new ZipArchive(fs, ZipArchiveMode.Read))
                {
                    string dir = Path.Combine(root, id);
                    if (!Directory.Exists(dir)) Directory.CreateDirectory(dir);
                    Dictionary<string, string> have = CatalogOf(dir);
                    foreach (ZipArchiveEntry e in zip.Entries)
                    {
                        string name = SafeName(e.Name);       // e.Name never carries a path
                        if (name.Length == 0) continue;
                        byte[] data;
                        using (Stream s = e.Open())
                        using (MemoryStream ms = new MemoryStream())
                        {
                            s.CopyTo(ms);
                            data = ms.ToArray();
                        }
                        if (data.Length == 0 || data.Length > MaxFrameBytes) continue;
                        string h = HashBytes(data);
                        if (have.ContainsKey(h)) continue;
                        File.WriteAllBytes(Path.Combine(dir, name), data);
                        have[h] = name;
                        added++;
                    }
                }
                WriteManifest(Path.Combine(root, id), id, id, "");
            }
            catch { }
            return added;
        }
    }
}
