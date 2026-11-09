using System;
using System.Collections.Generic;
using System.IO;
using System.Reflection;
using System.Windows;
using System.Windows.Markup;
using System.Windows.Media;

namespace UssdApp
{
    // Design-token system.
    //
    // Every token is ONE shared mutable SolidColorBrush instance. Code-built
    // elements hold references to these instances, and XAML control styles
    // resolve the same instances through Application.Resources (DynamicResource).
    // Apply() copies colors from the embedded token dictionaries
    // (Themes\Light.xaml / Themes\Dark.xaml) into the shared instances, so the
    // whole UI repaints live - no rebuild needed.
    public static class Theme
    {
        public static readonly SolidColorBrush Bg = New("#F8FAFC");
        public static readonly SolidColorBrush Panel = New("#FFFFFF");
        public static readonly SolidColorBrush Card = New("#FFFFFF");
        public static readonly SolidColorBrush CardBorder = New("#E2E8F0");
        public static readonly SolidColorBrush Chrome = New("#F1F5F9");
        public static readonly SolidColorBrush Text = New("#0F172A");
        public static readonly SolidColorBrush Subtle = New("#64748B");
        public static readonly SolidColorBrush Gray = New("#64748B");
        public static readonly SolidColorBrush Accent = New("#2563EB");
        public static readonly SolidColorBrush AccentHover = New("#1D4ED8");
        public static readonly SolidColorBrush AccentSoft = New("#EFF6FF");
        public static readonly SolidColorBrush CallBlue = New("#0084FF");
        public static readonly SolidColorBrush CallBlueHover = New("#006FD6");
        public static readonly SolidColorBrush Danger = New("#EF4444");
        public static readonly SolidColorBrush DangerHover = New("#DC2626");
        public static readonly SolidColorBrush DangerSoft = New("#FEF2F2");
        public static readonly SolidColorBrush Error = New("#DC2626");
        public static readonly SolidColorBrush Success = New("#16A34A");
        public static readonly SolidColorBrush Warn = New("#F59E0B");
        public static readonly SolidColorBrush Green = New("#16A34A");
        public static readonly SolidColorBrush Red = New("#DC2626");
        public static readonly SolidColorBrush Keypad = New("#F1F5F9");
        public static readonly SolidColorBrush KeypadHover = New("#E2E8F0");
        public static readonly SolidColorBrush KeypadPress = New("#CBD5E1");
        public static readonly SolidColorBrush Pill = New("#F1F5F9");
        public static readonly SolidColorBrush Online = New("#22C55E");

        // Transport mode switcher tokens
        public static readonly SolidColorBrush SegmentActive = New("#2563EB");   // active pill background (= Accent in light)
        public static readonly SolidColorBrush SegmentBg = New("#F1F5F9");       // pill track background

        public static string Current = "light";
        public static event Action Changed;

        private static bool _initialized;

        private static SolidColorBrush New(string hex)
        {
            // NOT frozen: colors are mutated on theme switch so every
            // referencing element updates automatically.
            return new SolidColorBrush((Color)ColorConverter.ConvertFromString(hex));
        }

        // token key -> shared instance
        private static Dictionary<string, SolidColorBrush> BuildMap()
        {
            Dictionary<string, SolidColorBrush> m = new Dictionary<string, SolidColorBrush>();
            m["AppBg"] = Bg;
            m["PanelBrush"] = Panel;
            m["CardBrush"] = Card;
            m["CardBorder"] = CardBorder;
            m["ChromeBrush"] = Chrome;
            m["TextBrush"] = Text;
            m["SubtextBrush"] = Subtle;
            m["GrayBrush"] = Gray;
            m["AccentBrush"] = Accent;
            m["AccentHover"] = AccentHover;
            m["AccentSoft"] = AccentSoft;
            m["CallBrush"] = CallBlue;
            m["CallHover"] = CallBlueHover;
            m["DangerBrush"] = Danger;
            m["DangerHover"] = DangerHover;
            m["DangerSoft"] = DangerSoft;
            m["ErrorBrush"] = Error;
            m["SuccessBrush"] = Success;
            m["WarnBrush"] = Warn;
            m["GreenBrush"] = Green;
            m["RedBrush"] = Red;
            m["KeypadBrush"] = Keypad;
            m["KeypadHover"] = KeypadHover;
            m["KeypadPress"] = KeypadPress;
            m["PillBrush"] = Pill;
            m["OnlineBrush"] = Online;
            return m;
        }

        public static ResourceDictionary LoadEmbedded(string fileNameNoExt)
        {
            string resName = "ussd.Themes." + fileNameNoExt + ".xaml";
            Stream s = Assembly.GetExecutingAssembly().GetManifestResourceStream(resName);
            if (s == null)
                throw new InvalidOperationException("Missing embedded resource: " + resName);
            using (s)
            {
                StreamReader r = new StreamReader(s);
                string xaml = r.ReadToEnd();
                return (ResourceDictionary)XamlReader.Parse(xaml);
            }
        }

        // Load control styles + register shared brushes + apply saved theme.
        // Call once from MainWindow's constructor, before BuildUi().
        public static void Init(Application app)
        {
            if (_initialized || app == null) return;
            _initialized = true;
            Diag("Init start; Bg frozen=" + Bg.IsFrozen);
            try
            {
                ResourceDictionary styles = LoadEmbedded("Controls");
                app.Resources.MergedDictionaries.Add(styles);
                Diag("Controls added; Bg frozen=" + Bg.IsFrozen);
            }
            catch (Exception ex)
            {
                try { File.WriteAllText(Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "theme_error.log"), ex.ToString()); }
                catch { }
            }
            Dictionary<string, SolidColorBrush> map = BuildMap();
            // Register FRESH copies: WPF freezes Freezables placed in
            // Application.Resources, so the shared (mutable) instances must
            // never be stored there - styles get swap-in replacements instead.
            foreach (KeyValuePair<string, SolidColorBrush> kv in map)
                app.Resources[kv.Key] = new SolidColorBrush(kv.Value.Color);
            Diag("registered " + map.Count + " token copies; Bg frozen=" + Bg.IsFrozen);

            string theme = "light";
            try
            {
                AppConfig c = AppConfig.Load();
                if (!string.IsNullOrEmpty(c.theme)) theme = c.theme;
            }
            catch { }
            Apply(theme);
            Diag("applied theme " + Current);
        }

        // Copy colors out of the named embedded token dictionary into the
        // shared instances, then notify listeners. Resilient: a frozen shared
        // instance is logged and skipped instead of crashing the app.
        public static void Apply(string name)
        {
            string file = (name != null && name.ToLowerInvariant() == "dark") ? "Dark" : "Light";
            ResourceDictionary tokens;
            try { tokens = LoadEmbedded(file); }
            catch (Exception ex) { Diag("Apply load failed: " + ex.Message); return; }
            Dictionary<string, SolidColorBrush> map = BuildMap();
            Application app = Application.Current;
            foreach (KeyValuePair<string, SolidColorBrush> kv in map)
            {
                try
                {
                    SolidColorBrush src = tokens[kv.Key] as SolidColorBrush;
                    if (src == null) continue;
                    // 1) code-built UI: mutate the shared instance (live repaint)
                    if (!kv.Value.IsFrozen) kv.Value.Color = src.Color;
                    else Diag("Frozen shared instance for token '" + kv.Key + "' - code-side color not applied.");
                    // 2) XAML styles: swap a fresh instance; DynamicResource re-resolves
                    if (app != null) app.Resources[kv.Key] = new SolidColorBrush(src.Color);
                }
                catch (Exception ex)
                {
                    Diag("Apply '" + kv.Key + "' failed: " + ex.Message);
                }
            }
            Current = (file == "Dark") ? "dark" : "light";
            if (Changed != null) Changed();
        }

        private static void Diag(string msg)
        {
            try
            {
                File.AppendAllText(
                    Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "theme_error.log"),
                    DateTime.Now.ToString("HH:mm:ss") + " " + msg + Environment.NewLine);
            }
            catch { }
        }
    }
}
