"""USSD App - Python tkinter GUI (Method 1 + Method 2)."""
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import threading
import time
import json
import os
from datetime import datetime

import requests
import serial
from serial.tools import list_ports

from mifi_api import send_ussd as mifi_send, get_ussd_result as mifi_result, ussd_session as mifi_session
from serial_ussd import send_ussd_at, extract_ussd_text, auto_detect_modem_port
from detect_ports import detect_ports

CONFIG_FILE = os.path.join(os.path.dirname(__file__), "config.json")
HISTORY_FILE = os.path.join(os.path.dirname(__file__), "history.json")

BG = "#1e1e2e"
BG2 = "#2a2a3c"
FG = "#e0e0e0"
ACCENT = "#0078d4"
ACCENT2 = "#005a9e"
SUCCESS = "#00c853"
ERROR = "#ff5252"
WARN = "#ffc107"
FONT = ("Segoe UI", 10)
FONT_B = ("Segoe UI", 10, "bold")
FONT_T = ("Segoe UI", 14, "bold")
MONO = ("Consolas", 10)


class USSDApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("USSD Manager Pro")
        self.geometry("900x700")
        self.minsize(750, 550)
        self.configure(bg=BG)

        self.mode = tk.StringVar(value="mifi")
        self.mifi_ip = tk.StringVar(value="http://192.168.100.1")
        self.com_port = tk.StringVar(value="")
        self.baud = tk.StringVar(value="115200")
        self.connected = tk.BooleanVar(value=False)
        self.status_text = tk.StringVar(value="Disconnected")

        self._load_config()
        self._build_ui()
        self._refresh_ports()
        self.protocol("WM_DELETE_WINDOW", self._on_close)

    def _load_config(self):
        try:
            if os.path.exists(CONFIG_FILE):
                with open(CONFIG_FILE) as f:
                    cfg = json.load(f)
                self.mifi_ip.set(cfg.get("mifi_ip", self.mifi_ip.get()))
                self.com_port.set(cfg.get("com_port", ""))
                self.baud.set(cfg.get("baud", "115200"))
        except Exception:
            pass

    def _save_config(self):
        with open(CONFIG_FILE, "w") as f:
            json.dump({
                "mifi_ip": self.mifi_ip.get(),
                "com_port": self.com_port.get(),
                "baud": self.baud.get(),
            }, f, indent=2)

    def _build_ui(self):
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("TFrame", background=BG)
        style.configure("TLabel", background=BG, foreground=FG, font=FONT)
        style.configure("Header.TLabel", font=FONT_T, foreground=ACCENT)
        style.configure("Status.TLabel", font=FONT_B)
        style.configure("TButton", font=FONT, padding=6)
        style.configure("Accent.TButton", font=FONT_B, padding=8)
        style.configure("TEntry", font=FONT)
        style.configure("TCombobox", font=FONT)
        style.configure("TRadiobutton", background=BG, foreground=FG, font=FONT)

        # Header
        hdr = ttk.Frame(self)
        hdr.pack(fill="x", padx=12, pady=(12, 6))
        ttk.Label(hdr, text="USSD Manager Pro", style="Header.TLabel").pack(side="left")
        self.status_lbl = ttk.Label(hdr, textvariable=self.status_text, foreground=ERROR, font=FONT_B)
        self.status_lbl.pack(side="right")

        # Mode selector
        mode_fr = ttk.LabelFrame(self, text=" Connection Method ")
        mode_fr.pack(fill="x", padx=12, pady=4)
        ttk.Radiobutton(mode_fr, text="Method 1: MiFi Web API (HTTP)", variable=self.mode, value="mifi").pack(side="left", padx=8, pady=6)
        ttk.Radiobutton(mode_fr, text="Method 2: USB Serial / AT", variable=self.mode, value="serial").pack(side="left", padx=8, pady=6)

        # Method 1 panel
        self.mifi_fr = ttk.LabelFrame(self, text=" MiFi Web API Settings ")
        self.mifi_fr.pack(fill="x", padx=12, pady=4)
        row = ttk.Frame(self.mifi_fr); row.pack(fill="x", padx=8, pady=6)
        ttk.Label(row, text="MiFi IP:").pack(side="left")
        ttk.Entry(row, textvariable=self.mifi_ip, width=25).pack(side="left", padx=6)
        ttk.Button(row, text="Test Connection", command=self._test_mifi).pack(side="left", padx=4)

        # Method 2 panel
        self.serial_fr = ttk.LabelFrame(self, text=" USB Serial / AT Settings ")
        self.serial_fr.pack(fill="x", padx=12, pady=4)
        row2 = ttk.Frame(self.serial_fr); row2.pack(fill="x", padx=8, pady=6)
        ttk.Label(row2, text="COM Port:").pack(side="left")
        self.port_cb = ttk.Combobox(row2, textvariable=self.com_port, width=15, state="readonly")
        self.port_cb.pack(side="left", padx=6)
        ttk.Label(row2, text="Baud:").pack(side="left")
        ttk.Combobox(row2, textvariable=self.baud, width=8, values=["9600","19200","38400","57600","115200","230400"], state="readonly").pack(side="left", padx=6)
        ttk.Button(row2, text="Auto-Detect", command=self._refresh_ports).pack(side="left", padx=4)
        ttk.Button(row2, text="Test Port", command=self._test_serial).pack(side="left", padx=4)

        # USSD send
        send_fr = ttk.LabelFrame(self, text=" Send USSD ")
        send_fr.pack(fill="x", padx=12, pady=4)
        row3 = ttk.Frame(send_fr); row3.pack(fill="x", padx=8, pady=8)
        ttk.Label(row3, text="USSD Code:").pack(side="left")
        self.code_var = tk.StringVar(value="*124#")
        e = ttk.Entry(row3, textvariable=self.code_var, width=20)
        e.pack(side="left", padx=6)
        e.bind("<Return>", lambda e: self._send_ussd())
        for code, lbl in [("*124#","Balance"),("*170#","Data"),("*#06#","IMEI"),("*135#","Menu")]:
            ttk.Button(row3, text=lbl, command=lambda c=code: self.code_var.set(c)).pack(side="left", padx=2)
        ttk.Button(row3, text="SEND", style="Accent.TButton", command=self._send_ussd).pack(side="right", padx=6)

        # Output console
        out_fr = ttk.LabelFrame(self, text=" Network Response ")
        out_fr.pack(fill="both", expand=True, padx=12, pady=4)
        self.output = scrolledtext.ScrolledText(out_fr, height=10, bg=BG2, fg=FG, font=MONO,
                                                insertbackground=FG, relief="flat", wrap="word")
        self.output.pack(fill="both", expand=True, padx=4, pady=4)
        self.output.tag_configure("time", foreground="#888888")
        self.output.tag_configure("send", foreground=ACCENT)
        self.output.tag_configure("recv", foreground=SUCCESS)
        self.output.tag_configure("err", foreground=ERROR)
        self.output.tag_configure("info", foreground=WARN)

        # Bottom bar
        bot = ttk.Frame(self)
        bot.pack(fill="x", padx=12, pady=(4, 10))
        ttk.Button(bot, text="Clear Log", command=lambda: self.output.delete("1.0", "end")).pack(side="left")
        ttk.Button(bot, text="Save Config", command=self._save_config).pack(side="left", padx=6)
        self.progress = ttk.Progressbar(bot, mode="indeterminate", length=120)
        self.progress.pack(side="right")

        # Toggle panels
        self.mode.trace_add("write", lambda *_: self._toggle_panels())
        self._toggle_panels()

    def _toggle_panels(self):
        if self.mode.get() == "mifi":
            self.serial_fr.pack_forget()
            self.mifi_fr.pack(fill="x", padx=12, pady=4, after=self.winfo_children()[1])
        else:
            self.mifi_fr.pack_forget()
            self.serial_fr.pack(fill="x", padx=12, pady=4, after=self.winfo_children()[1])

    def _log(self, text, tag="info"):
        ts = datetime.now().strftime("%H:%M:%S")
        self.output.insert("end", f"[{ts}] ", "time")
        self.output.insert("end", text + "\n", tag)
        self.output.see("end")

    def _refresh_ports(self):
        ports = detect_ports()
        vals = [f"{p['device']} — {p['description']}" for p in ports]
        self.port_cb["values"] = vals
        if ports:
            best = auto_detect_modem_port()
            for p in ports:
                if p["device"] == best:
                    self.com_port.set(f"{p['device']} — {p['description']}")
                    break
            self._log(f"Found {len(ports)} port(s). Best guess: {best}", "info")
        else:
            self._log("No COM ports found.", "err")

    def _port_name(self):
        v = self.com_port.get()
        return v.split("—")[0].strip() if "—" in v else v.strip()

    def _test_mifi(self):
        def run():
            try:
                r = requests.get(self.mifi_ip.get().rstrip("/") + "/", timeout=5)
                self.after(0, lambda: self._log(f"MiFi reachable: HTTP {r.status_code}", "recv"))
            except Exception as ex:
                self.after(0, lambda: self._log(f"MiFi unreachable: {ex}", "err"))
        threading.Thread(target=run, daemon=True).start()

    def _test_serial(self):
        def run():
            port = self._port_name()
            try:
                with serial.Serial(port, int(self.baud.get()), timeout=1) as ser:
                    ser.write(b"AT\r")
                    time.sleep(0.3)
                    rep = ser.read(100).decode(errors="replace")
                self.after(0, lambda: self._log(f"Port {port} OK: {rep.strip()}", "recv"))
            except Exception as ex:
                self.after(0, lambda: self._log(f"Port error: {ex}", "err"))
        threading.Thread(target=run, daemon=True).start()

    def _send_ussd(self):
        code = self.code_var.get().strip()
        if not code:
            messagebox.showwarning("Input", "Enter a USSD code.")
            return
        self.progress.start(12)
        threading.Thread(target=self._send_worker, args=(code,), daemon=True).start()

    def _send_worker(self, code):
        self.after(0, lambda: self._log(f"Sending {code} via {self.mode.get()}...", "send"))
        try:
            if self.mode.get() == "mifi":
                s, r = mifi_session(self.mifi_ip.get(), code)
                self.after(0, lambda: self._log(f"Send: {s}", "send"))
                self.after(0, lambda: self._log(f"Response: {r}", "recv"))
                self.after(0, lambda: self._set_status("Connected (MiFi)", SUCCESS))
            else:
                port = self._port_name() or auto_detect_modem_port()
                if not port:
                    self.after(0, lambda: self._log("No COM port found.", "err"))
                    return
                raw = send_ussd_at(port, code, baud=int(self.baud.get()))
                parsed = extract_ussd_text(raw)
                self.after(0, lambda: self._log(f"Raw: {raw.strip()}", "send"))
                self.after(0, lambda: self._log(f"USSD: {parsed}", "recv"))
                self.after(0, lambda: self._set_status(f"Connected ({port})", SUCCESS))
        except Exception as ex:
            self.after(0, lambda: self._log(f"Error: {ex}", "err"))
            self.after(0, lambda: self._set_status("Error", ERROR))
        finally:
            self.after(0, self.progress.stop)

    def _set_status(self, text, color):
        self.status_text.set(text)
        self.status_lbl.configure(foreground=color)

    def _on_close(self):
        self._save_config()
        self.destroy()


if __name__ == "__main__":
    app = USSDApp()
    app.mainloop()
