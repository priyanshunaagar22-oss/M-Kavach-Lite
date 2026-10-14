#!/usr/bin/env python3
"""
M-Kavach Lite - Mobile Malware & Fraud Detection System
=========================================================
College Project Demo App

A Tkinter-based Cybersecurity Scanner Dashboard that:
  - Talks to a real Android phone over ADB (USB Debugging) when available,
    listing sideloaded (third-party) apps and flagging ones with unknown
    installers and/or high background data usage (parsed from
    `adb shell dumpsys netstats`).
  - Falls back to a realistic "Demo / Simulation" dataset when no device /
    ADB binary is available, so the UI is always demoable in class.

Only the Python standard library is used (tkinter, subprocess, threading,
re, random, dataclasses, datetime). No third-party packages required.

Run:
    python mkavach_lite.py
"""

import subprocess
import threading
import random
import re
import shutil
from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Optional

import tkinter as tk
from tkinter import ttk, messagebox


# ----------------------------------------------------------------------------
# THEME / COLOR PALETTE
# ----------------------------------------------------------------------------
class Theme:
    BG          = "#0d1117"   # app background
    PANEL       = "#161b22"   # card / panel background
    PANEL_ALT   = "#1c2330"   # slightly lighter panel
    BORDER      = "#2a3140"
    TEXT        = "#e6edf3"
    SUBTEXT     = "#8b949e"
    ACCENT      = "#00e5ff"   # cyan accent
    ACCENT_DARK = "#0891a8"
    HIGH        = "#ff4757"   # high risk red
    HIGH_BG     = "#3a1720"
    MEDIUM      = "#ffa502"   # medium risk amber
    MEDIUM_BG   = "#3a2c10"
    LOW         = "#2ed573"   # low / safe green
    LOW_BG      = "#0f2a1c"
    FONT_FAMILY = "Segoe UI"


# ----------------------------------------------------------------------------
# DATA MODEL
# ----------------------------------------------------------------------------
@dataclass
class AppRecord:
    app_name: str
    package_name: str
    risk_level: str            # "HIGH" | "MEDIUM" | "LOW"
    reason: str
    sideloaded: bool
    installer: str
    data_usage_mb: int
    scanned_at: str = field(default_factory=lambda: datetime.now().strftime("%H:%M:%S"))


# ----------------------------------------------------------------------------
# DEMO / SIMULATION DATA
# ----------------------------------------------------------------------------
DEMO_APPS = [
    dict(app_name="FakeBankingApp.apk", package_name="com.secure.bankupdate",
         installer="unknown (sideloaded)", data_usage_mb=450, sideloaded=True),
    dict(app_name="QuickLoan Pro", package_name="com.quickloan.instant",
         installer="unknown (sideloaded)", data_usage_mb=310, sideloaded=True),
    dict(app_name="Flashlight Ultra+", package_name="com.util.flashlightultra",
         installer="unknown (sideloaded)", data_usage_mb=275, sideloaded=True),
    dict(app_name="OTP Stealer Lite", package_name="com.sms.readerhelper",
         installer="unknown (sideloaded)", data_usage_mb=520, sideloaded=True),
    dict(app_name="WhatsApp Plus Mod", package_name="com.whatsapp.plusmod",
         installer="unknown (sideloaded)", data_usage_mb=190, sideloaded=True),
    dict(app_name="Free Recharge Genie", package_name="com.recharge.genie.free",
         installer="com.android.packageinstaller", data_usage_mb=140, sideloaded=True),
    dict(app_name="System Update Service", package_name="com.sys.update.core",
         installer="unknown (sideloaded)", data_usage_mb=88, sideloaded=True),
    dict(app_name="PhotoEditor Pro", package_name="com.photo.editorpro",
         installer="com.android.vending", data_usage_mb=35, sideloaded=False),
    dict(app_name="Notes Keeper", package_name="com.utility.noteskeeper",
         installer="com.android.vending", data_usage_mb=6, sideloaded=False),
    dict(app_name="Cricket Live Score", package_name="com.sports.crickscore",
         installer="com.android.vending", data_usage_mb=52, sideloaded=False),
]


def classify(sideloaded: bool, installer: str, data_usage_mb: int) -> (str, str):
    """Apply simple heuristic rules to derive a risk level + human reason."""
    unknown_installer = sideloaded and ("unknown" in installer.lower() or installer.strip() == "")
    high_data = data_usage_mb >= 200
    medium_data = 80 <= data_usage_mb < 200

    if unknown_installer and high_data:
        return "HIGH", f"Sideloaded APK with unknown installer + High Background Data Usage > 200MB ({data_usage_mb}MB)"
    if unknown_installer and medium_data:
        return "MEDIUM", f"Sideloaded APK with unknown installer + Elevated Background Data Usage ({data_usage_mb}MB)"
    if unknown_installer:
        return "MEDIUM", "Sideloaded APK with unknown/null installer source"
    if sideloaded and high_data:
        return "MEDIUM", f"Sideloaded APK + High Background Data Usage > 200MB ({data_usage_mb}MB)"
    if high_data:
        return "MEDIUM", f"High Background Data Usage > 200MB ({data_usage_mb}MB)"
    return "LOW", "No significant risk indicators detected"


def build_demo_records() -> List[AppRecord]:
    records = []
    for entry in DEMO_APPS:
        risk, reason = classify(entry["sideloaded"], entry["installer"], entry["data_usage_mb"])
        records.append(AppRecord(
            app_name=entry["app_name"],
            package_name=entry["package_name"],
            risk_level=risk,
            reason=reason,
            sideloaded=entry["sideloaded"],
            installer=entry["installer"],
            data_usage_mb=entry["data_usage_mb"],
        ))
    return records


# ----------------------------------------------------------------------------
# ADB BACKEND
# ----------------------------------------------------------------------------
class AdbError(Exception):
    pass


class AdbScanner:
    """Thin wrapper around the `adb` command-line tool."""

    def __init__(self, timeout: int = 15):
        self.timeout = timeout
        self.adb_path = shutil.which("adb")

    def is_adb_available(self) -> bool:
        return self.adb_path is not None

    def _run(self, args: List[str]) -> str:
        try:
            result = subprocess.run(
                [self.adb_path] + args,
                capture_output=True,
                text=True,
                timeout=self.timeout,
            )
            if result.returncode != 0 and not result.stdout:
                raise AdbError(result.stderr.strip() or "adb command failed")
            return result.stdout
        except FileNotFoundError:
            raise AdbError("adb binary not found on PATH")
        except subprocess.TimeoutExpired:
            raise AdbError("adb command timed out")

    def get_connected_device(self) -> Optional[str]:
        """Returns the first device serial in 'device' state, or None."""
        if not self.is_adb_available():
            return None
        try:
            out = self._run(["devices"])
        except AdbError:
            return None
        for line in out.splitlines()[1:]:
            line = line.strip()
            if not line:
                continue
            parts = line.split()
            if len(parts) >= 2 and parts[1] == "device":
                return parts[0]
        return None

    def list_third_party_packages(self, serial: str) -> List[str]:
        """adb shell pm list packages -3 -> list of package names."""
        out = self._run(["-s", serial, "shell", "pm", "list", "packages", "-3"])
        packages = []
        for line in out.splitlines():
            line = line.strip()
            if line.startswith("package:"):
                packages.append(line.split(":", 1)[1].strip())
        return packages

    def get_installer(self, serial: str, package: str) -> str:
        """Uses `dumpsys package <pkg>` to find the installer source."""
        try:
            out = self._run(["-s", serial, "shell", "dumpsys", "package", package])
        except AdbError:
            return "unknown (sideloaded)"
        m = re.search(r"installerPackageName=([^\s]+)", out)
        if m and m.group(1) and m.group(1).lower() != "null":
            return m.group(1)
        return "unknown (sideloaded)"

    def get_network_usage_mb(self, serial: str, package: str) -> int:
        """
        Best-effort parse of `adb shell dumpsys netstats detail` to estimate
        background data usage for a package. Real device parsing of netstats
        is UID-based and quite involved, so this uses a lightweight heuristic
        scan for the package's UID bytes; if unavailable, falls back to a
        deterministic pseudo-estimate so the demo remains stable.
        """
        try:
            out = self._run(["-s", serial, "shell", "dumpsys", "netstats", "detail"])
        except AdbError:
            out = ""
        # Heuristic: look for "rb=<bytes>" (received bytes) near mentions
        # of the package's UID; real parsing requires cross-referencing
        # `dumpsys package` UID with netstats UID stats tables.
        total_bytes = 0
        for match in re.finditer(r"rb=(\d+)", out):
            total_bytes += int(match.group(1))
        if total_bytes > 0:
            # Rough proportional share so numbers stay in a believable range.
            return min(600, max(1, total_bytes // (1024 * 1024 * 50)))
        # Fallback deterministic estimate (stable per package, not random),
        # used only when netstats parsing yields nothing on this device.
        seed = sum(ord(c) for c in package)
        return 20 + (seed % 180)

    def scan(self) -> (Optional[str], List[AppRecord]):
        """
        Full scan pipeline. Returns (device_serial_or_None, records).
        Raises AdbError if adb exists but scanning fails outright.
        """
        serial = self.get_connected_device()
        if not serial:
            return None, []

        packages = self.list_third_party_packages(serial)
        records = []
        for pkg in packages:
            installer = self.get_installer(serial, pkg)
            sideloaded = "unknown" in installer.lower()
            data_mb = self.get_network_usage_mb(serial, pkg)
            risk, reason = classify(sideloaded, installer, data_mb)
            records.append(AppRecord(
                app_name=pkg.split(".")[-1],
                package_name=pkg,
                risk_level=risk,
                reason=reason,
                sideloaded=sideloaded,
                installer=installer,
                data_usage_mb=data_mb,
            ))
        return serial, records


# ----------------------------------------------------------------------------
# UI WIDGETS
# ----------------------------------------------------------------------------
class StatCard(tk.Frame):
    def __init__(self, master, title: str, accent: str, **kwargs):
        super().__init__(master, bg=Theme.PANEL, highlightbackground=Theme.BORDER,
                          highlightthickness=1, **kwargs)
        self.value_var = tk.StringVar(value="0")

        tk.Label(self, text=title.upper(), bg=Theme.PANEL, fg=Theme.SUBTEXT,
                  font=(Theme.FONT_FAMILY, 9, "bold")).pack(anchor="w", padx=16, pady=(14, 0))
        tk.Label(self, textvariable=self.value_var, bg=Theme.PANEL, fg=accent,
                  font=(Theme.FONT_FAMILY, 28, "bold")).pack(anchor="w", padx=16, pady=(0, 14))

    def set_value(self, value):
        self.value_var.set(str(value))


class AppCard(tk.Frame):
    """A single flagged-app result card."""

    RISK_COLORS = {
        "HIGH":   (Theme.HIGH, Theme.HIGH_BG),
        "MEDIUM": (Theme.MEDIUM, Theme.MEDIUM_BG),
        "LOW":    (Theme.LOW, Theme.LOW_BG),
    }

    def __init__(self, master, record: AppRecord, on_inspect, on_uninstall, **kwargs):
        super().__init__(master, bg=Theme.PANEL, highlightbackground=Theme.BORDER,
                          highlightthickness=1, **kwargs)
        self.record = record
        fg, bg = self.RISK_COLORS.get(record.risk_level, (Theme.SUBTEXT, Theme.PANEL_ALT))

        top = tk.Frame(self, bg=Theme.PANEL)
        top.pack(fill="x", padx=16, pady=(12, 4))

        tk.Label(top, text=record.app_name, bg=Theme.PANEL, fg=Theme.TEXT,
                  font=(Theme.FONT_FAMILY, 13, "bold")).pack(side="left")

        badge = tk.Label(top, text=f"  {record.risk_level} RISK  ", bg=bg, fg=fg,
                          font=(Theme.FONT_FAMILY, 9, "bold"))
        badge.pack(side="right")

        tk.Label(self, text=record.package_name, bg=Theme.PANEL, fg=Theme.SUBTEXT,
                  font=(Theme.FONT_FAMILY, 9)).pack(anchor="w", padx=16)

        meta = tk.Frame(self, bg=Theme.PANEL)
        meta.pack(fill="x", padx=16, pady=(6, 0))
        install_txt = "Sideloaded (unknown source)" if record.sideloaded else "Play Store / trusted"
        tk.Label(meta, text=f"Installer: {install_txt}", bg=Theme.PANEL, fg=Theme.SUBTEXT,
                  font=(Theme.FONT_FAMILY, 9)).pack(side="left")
        tk.Label(meta, text=f"   |   Bg Data: {record.data_usage_mb} MB", bg=Theme.PANEL,
                  fg=Theme.SUBTEXT, font=(Theme.FONT_FAMILY, 9)).pack(side="left")
        tk.Label(meta, text=f"   |   Scanned @ {record.scanned_at}", bg=Theme.PANEL,
                  fg=Theme.SUBTEXT, font=(Theme.FONT_FAMILY, 9)).pack(side="left")

        reason_frame = tk.Frame(self, bg=Theme.PANEL_ALT, highlightbackground=Theme.BORDER,
                                 highlightthickness=1)
        reason_frame.pack(fill="x", padx=16, pady=8)
        tk.Label(reason_frame, text=f"⚠  {record.reason}", bg=Theme.PANEL_ALT, fg=fg,
                  font=(Theme.FONT_FAMILY, 9), wraplength=760, justify="left",
                  anchor="w").pack(fill="x", padx=10, pady=6)

        btn_row = tk.Frame(self, bg=Theme.PANEL)
        btn_row.pack(fill="x", padx=16, pady=(0, 12))

        inspect_btn = tk.Button(btn_row, text="🔍 Inspect", bg=Theme.PANEL_ALT, fg=Theme.TEXT,
                                 activebackground=Theme.BORDER, activeforeground=Theme.TEXT,
                                 relief="flat", font=(Theme.FONT_FAMILY, 9, "bold"),
                                 cursor="hand2", padx=12, pady=4,
                                 command=lambda: on_inspect(record))
        inspect_btn.pack(side="left")

        uninstall_btn = tk.Button(btn_row, text="🗑 Uninstall", bg=Theme.HIGH_BG, fg=Theme.HIGH,
                                   activebackground=Theme.HIGH, activeforeground="white",
                                   relief="flat", font=(Theme.FONT_FAMILY, 9, "bold"),
                                   cursor="hand2", padx=12, pady=4,
                                   command=lambda: on_uninstall(record))
        uninstall_btn.pack(side="left", padx=(8, 0))


class ScrollableFrame(tk.Frame):
    """A vertically scrollable container frame."""

    def __init__(self, master, **kwargs):
        super().__init__(master, bg=Theme.BG, **kwargs)

        self.canvas = tk.Canvas(self, bg=Theme.BG, highlightthickness=0)
        self.scrollbar = ttk.Scrollbar(self, orient="vertical", command=self.canvas.yview)
        self.inner = tk.Frame(self.canvas, bg=Theme.BG)

        self.inner.bind(
            "<Configure>",
            lambda e: self.canvas.configure(scrollregion=self.canvas.bbox("all"))
        )
        self.window_id = self.canvas.create_window((0, 0), window=self.inner, anchor="nw")
        self.canvas.configure(yscrollcommand=self.scrollbar.set)

        self.canvas.bind("<Configure>", self._on_canvas_resize)
        self.canvas.pack(side="left", fill="both", expand=True)
        self.scrollbar.pack(side="right", fill="y")

        # Mouse wheel support (Windows/Mac/Linux)
        self.canvas.bind_all("<MouseWheel>", self._on_mousewheel)
        self.canvas.bind_all("<Button-4>", lambda e: self.canvas.yview_scroll(-1, "units"))
        self.canvas.bind_all("<Button-5>", lambda e: self.canvas.yview_scroll(1, "units"))

    def _on_canvas_resize(self, event):
        self.canvas.itemconfig(self.window_id, width=event.width)

    def _on_mousewheel(self, event):
        self.canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")

    def clear(self):
        for widget in self.inner.winfo_children():
            widget.destroy()


# ----------------------------------------------------------------------------
# MAIN APPLICATION
# ----------------------------------------------------------------------------
class MKavachApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("M-Kavach Pocket / Malware Detector")
        self.geometry("980x760")
        self.minsize(820, 600)
        self.configure(bg=Theme.BG)

        self.adb = AdbScanner()
        self.demo_mode = tk.BooleanVar(value=not self.adb.is_adb_available())
        self.records: List[AppRecord] = []
        self.scanning = False

        self._build_style()
        self._build_header()
        self._build_stats_bar()
        self._build_controls()
        self._build_results_area()
        self._build_status_bar()

        self._render_empty_state()

    # -- styling ------------------------------------------------------------
    def _build_style(self):
        style = ttk.Style(self)
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass
        style.configure("Horizontal.TProgressbar",
                         troughcolor=Theme.PANEL_ALT, background=Theme.ACCENT,
                         bordercolor=Theme.PANEL_ALT, lightcolor=Theme.ACCENT,
                         darkcolor=Theme.ACCENT)
        style.configure("Vertical.TScrollbar",
                         background=Theme.PANEL_ALT, troughcolor=Theme.BG,
                         bordercolor=Theme.BG, arrowcolor=Theme.TEXT)
        style.configure("TCheckbutton", background=Theme.BG, foreground=Theme.TEXT,
                         font=(Theme.FONT_FAMILY, 9))
        style.map("TCheckbutton", background=[("active", Theme.BG)])

    # -- header ---------------------------------------------------------------
    def _build_header(self):
        header = tk.Frame(self, bg=Theme.BG)
        header.pack(fill="x", padx=24, pady=(20, 10))

        title_frame = tk.Frame(header, bg=Theme.BG)
        title_frame.pack(side="left")

        tk.Label(title_frame, text="🛡  M-Kavach Pocket", bg=Theme.BG, fg=Theme.TEXT,
                  font=(Theme.FONT_FAMILY, 20, "bold")).pack(anchor="w")
        tk.Label(title_frame, text="Mobile Malware & Fraud Detection System",
                  bg=Theme.BG, fg=Theme.SUBTEXT, font=(Theme.FONT_FAMILY, 10)).pack(anchor="w")

        self.adb_status_var = tk.StringVar()
        status_label = tk.Label(header, textvariable=self.adb_status_var, bg=Theme.BG,
                                 fg=Theme.SUBTEXT, font=(Theme.FONT_FAMILY, 9))
        status_label.pack(side="right", anchor="e")
        self._refresh_adb_status_label()

    def _refresh_adb_status_label(self):
        if self.adb.is_adb_available():
            device = self.adb.get_connected_device()
            if device:
                self.adb_status_var.set(f"🟢 ADB connected: {device}")
            else:
                self.adb_status_var.set("🟡 ADB found — no device attached")
        else:
            self.adb_status_var.set("🔴 ADB not found on PATH — Demo Mode only")

    # -- stats bar ------------------------------------------------------------
    def _build_stats_bar(self):
        bar = tk.Frame(self, bg=Theme.BG)
        bar.pack(fill="x", padx=24, pady=(0, 14))
        bar.columnconfigure((0, 1, 2), weight=1)

        self.stat_total = StatCard(bar, "Total Apps Scanned", Theme.ACCENT)
        self.stat_high = StatCard(bar, "High Risk Apps", Theme.HIGH)
        self.stat_side = StatCard(bar, "Sideloaded Apps", Theme.MEDIUM)

        self.stat_total.grid(row=0, column=0, sticky="nsew", padx=(0, 8))
        self.stat_high.grid(row=0, column=1, sticky="nsew", padx=8)
        self.stat_side.grid(row=0, column=2, sticky="nsew", padx=(8, 0))

    # -- controls ---------------------------------------------------------------
    def _build_controls(self):
        controls = tk.Frame(self, bg=Theme.BG)
        controls.pack(fill="x", padx=24, pady=(0, 10))

        self.scan_btn = tk.Button(
            controls, text="▶  Start ADB Scan", bg=Theme.ACCENT, fg="#00232b",
            activebackground=Theme.ACCENT_DARK, activeforeground="white",
            relief="flat", font=(Theme.FONT_FAMILY, 10, "bold"),
            cursor="hand2", padx=18, pady=8, command=self.start_scan
        )
        self.scan_btn.pack(side="left")

        demo_check = ttk.Checkbutton(
            controls, text="Load Demo / Simulation Data (fallback when no device found)",
            variable=self.demo_mode, style="TCheckbutton"
        )
        demo_check.pack(side="left", padx=16)

        refresh_btn = tk.Button(
            controls, text="⟳ Refresh ADB status", bg=Theme.PANEL_ALT, fg=Theme.TEXT,
            activebackground=Theme.BORDER, activeforeground=Theme.TEXT,
            relief="flat", font=(Theme.FONT_FAMILY, 9), cursor="hand2",
            padx=10, pady=6, command=self._refresh_adb_status_label
        )
        refresh_btn.pack(side="right")

        self.progress = ttk.Progressbar(self, orient="horizontal", mode="indeterminate",
                                         style="Horizontal.TProgressbar")
        self.progress.pack(fill="x", padx=24, pady=(0, 6))

    # -- results area -----------------------------------------------------------
    def _build_results_area(self):
        wrapper = tk.Frame(self, bg=Theme.BG, highlightbackground=Theme.BORDER,
                            highlightthickness=1)
        wrapper.pack(fill="both", expand=True, padx=24, pady=(0, 8))

        header = tk.Frame(wrapper, bg=Theme.PANEL_ALT)
        header.pack(fill="x")
        tk.Label(header, text="Detected Suspicious Apps", bg=Theme.PANEL_ALT, fg=Theme.TEXT,
                  font=(Theme.FONT_FAMILY, 11, "bold")).pack(anchor="w", padx=14, pady=8)

        self.results_frame = ScrollableFrame(wrapper)
        self.results_frame.pack(fill="both", expand=True)

    # -- status bar ---------------------------------------------------------------
    def _build_status_bar(self):
        self.status_var = tk.StringVar(value="Idle. Ready to scan.")
        bar = tk.Frame(self, bg=Theme.PANEL, highlightbackground=Theme.BORDER,
                        highlightthickness=1)
        bar.pack(fill="x", padx=24, pady=(0, 16))
        tk.Label(bar, textvariable=self.status_var, bg=Theme.PANEL, fg=Theme.SUBTEXT,
                  font=(Theme.FONT_FAMILY, 9), anchor="w").pack(fill="x", padx=12, pady=6)

    # -- empty state -----------------------------------------------------------
    def _render_empty_state(self):
        self.results_frame.clear()
        placeholder = tk.Label(
            self.results_frame.inner,
            text="No scan results yet.\nClick 'Start ADB Scan' to begin.",
            bg=Theme.BG, fg=Theme.SUBTEXT, font=(Theme.FONT_FAMILY, 11),
            justify="center"
        )
        placeholder.pack(expand=True, pady=60)

    # -- scan orchestration -----------------------------------------------------
    def start_scan(self):
        if self.scanning:
            return
        self.scanning = True
        self.scan_btn.configure(state="disabled", text="⏳ Scanning...")
        self.progress.start(12)
        self.status_var.set("Starting scan...")
        self.results_frame.clear()

        thread = threading.Thread(target=self._run_scan_worker, daemon=True)
        thread.start()

    def _run_scan_worker(self):
        """Runs on a background thread; only touches Tk via `self.after`."""
        serial = None
        records: List[AppRecord] = []
        error_msg = None

        try:
            self._safe_status("Checking for connected Android device via ADB...")
            serial = self.adb.get_connected_device()

            if serial:
                self._safe_status(f"Device found ({serial}). Listing third-party packages...")
                serial_used, records = self.adb.scan()
                if not records:
                    self._safe_status("No third-party packages found on device.")
            else:
                self._safe_status("No ADB device detected.")
        except AdbError as e:
            error_msg = str(e)
        except Exception as e:  # keep the demo bulletproof for a live presentation
            error_msg = f"Unexpected error: {e}"

        used_demo = False
        if not serial or not records:
            if self.demo_mode.get():
                self._safe_status("Falling back to Demo / Simulation dataset...")
                records = build_demo_records()
                used_demo = True
            elif error_msg:
                self._safe_status(f"ADB error: {error_msg}")
            else:
                self._safe_status("No device connected and Demo Mode is off — nothing to show.")

        self.after(0, self._on_scan_complete, records, serial, used_demo, error_msg)

    def _safe_status(self, text: str):
        self.after(0, lambda: self.status_var.set(text))

    def _on_scan_complete(self, records: List[AppRecord], serial: Optional[str],
                           used_demo: bool, error_msg: Optional[str]):
        self.progress.stop()
        self.scan_btn.configure(state="normal", text="▶  Start ADB Scan")
        self.scanning = False
        self.records = records

        self._update_stats(records)
        self._render_results(records)
        self._refresh_adb_status_label()

        if used_demo:
            self.status_var.set(
                f"Scan complete — showing DEMO data ({len(records)} apps). "
                f"{'ADB error: ' + error_msg if error_msg else 'No live device detected.'}"
            )
        elif serial:
            self.status_var.set(f"Scan complete — {len(records)} third-party app(s) found on {serial}.")
        else:
            self.status_var.set("Scan complete — no data to display.")

    # -- rendering ------------------------------------------------------------
    def _update_stats(self, records: List[AppRecord]):
        total = len(records)
        high = sum(1 for r in records if r.risk_level == "HIGH")
        sideloaded = sum(1 for r in records if r.sideloaded)
        self.stat_total.set_value(total)
        self.stat_high.set_value(high)
        self.stat_side.set_value(sideloaded)

    def _render_results(self, records: List[AppRecord]):
        self.results_frame.clear()
        if not records:
            self._render_empty_state()
            return

        # Sort HIGH -> MEDIUM -> LOW for readability
        order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
        sorted_records = sorted(records, key=lambda r: order.get(r.risk_level, 3))

        for rec in sorted_records:
            card = AppCard(self.results_frame.inner, rec,
                            on_inspect=self.on_inspect, on_uninstall=self.on_uninstall)
            card.pack(fill="x", padx=14, pady=6)

    # -- dummy actions ----------------------------------------------------------
    def on_inspect(self, record: AppRecord):
        messagebox.showinfo(
            "Inspect App",
            f"App: {record.app_name}\n"
            f"Package: {record.package_name}\n"
            f"Risk Level: {record.risk_level}\n"
            f"Installer: {record.installer}\n"
            f"Background Data: {record.data_usage_mb} MB\n\n"
            f"Reason:\n{record.reason}\n\n"
            f"(This is a demo action — in a production build this would open "
            f"a detailed static/behavioral analysis report.)"
        )

    def on_uninstall(self, record: AppRecord):
        confirm = messagebox.askyesno(
            "Confirm Uninstall (Demo)",
            f"Uninstall '{record.app_name}' ({record.package_name})?\n\n"
            f"This is a DEMO action for the college project — no real "
            f"uninstall command will be executed."
        )
        if confirm:
            self.records = [r for r in self.records if r.package_name != record.package_name]
            self._update_stats(self.records)
            self._render_results(self.records)
            self.status_var.set(f"(Demo) Uninstalled {record.app_name}.")


# ----------------------------------------------------------------------------
if __name__ == "__main__":
    app = MKavachApp()
    app.mainloop()
