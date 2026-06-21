"""Tkinter GUI for codex-cap — live Wireshark-like capture + on-the-fly analyze.

Layout:
    Top bar:    [Interface▾] [BPF filter] [Start] [Stop] [Save pcap] [Analyze saved] [Analyze now]
    Left pane:  live packet table (sortable, like Wireshark's packet list)
    Right top:  selected packet details (scapy ls())
    Right bot:  tshark analyze output (SNI / DNS / conv table)

Capture runs in a background thread; packets are marshalled to the UI thread
via a queue.Queue polled by Tk's `after()`.

Auto-record: every Stop automatically saves the captured pcap AND the
preliminary tshark report to `captures/cap_YYYYMMDD_HHMMSS.{pcap,txt}`
under the project root, so the artifact is always on disk for the user
(or their AI assistant) to read later. No clicking "Save" required.
"""

from __future__ import annotations

import contextlib
import datetime as _dt
import io
import os
import queue
import subprocess
import sys
import time
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk
from typing import List, Optional

from scapy.all import AsyncSniffer, Packet
from scapy.utils import wrpcap

from .capture import list_interfaces
from .format import format_packet
from . import analyze as analyze_mod
from . import config as cfg_mod
from .process_filter import AppPortFilter, PRESETS, resolve_preset


PACKET_COLUMNS = ("no", "time", "process", "pid", "src", "dst", "proto", "len", "info")

# Auto-record directory: <project_root>/captures/
PROJECT_ROOT = Path(__file__).resolve().parents[2]
CAPTURES_DIR = PROJECT_ROOT / "captures"


def captures_dir() -> Path:
    CAPTURES_DIR.mkdir(parents=True, exist_ok=True)
    return CAPTURES_DIR


def next_capture_paths() -> tuple[Path, Path]:
    """Return (pcap_path, txt_report_path) for a fresh timestamped capture."""
    ts = _dt.datetime.now().strftime("%Y%m%d_%H%M%S")
    d = captures_dir()
    return d / f"cap_{ts}.pcap", d / f"cap_{ts}.txt"


class CodexCapGUI:
    QUEUE_MAX = 20_000
    POLL_INTERVAL_MS = 50
    POLL_BATCH = 500

    def __init__(self) -> None:
        self.cfg = cfg_mod.load()

        self.root = tk.Tk()
        self.root.title("codex-cap")
        self.root.geometry(self.cfg.get("window_geometry", "1280x780"))
        self.root.minsize(960, 540)

        self.pkt_queue: queue.Queue = queue.Queue(maxsize=self.QUEUE_MAX)
        self.captured: List[Packet] = []
        self.packet_count = 0
        self.dropped_count = 0
        self.sniffer: Optional[AsyncSniffer] = None
        self.app_filter: Optional[AppPortFilter] = None
        self.start_time = 0.0
        self.capturing = False

        self._build_ui()
        self._apply_cfg_to_widgets()
        self.root.after(self.POLL_INTERVAL_MS, self._poll_queue)
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)

    # ---------- UI scaffolding ----------

    def _build_ui(self) -> None:
        bar = ttk.Frame(self.root, padding=(6, 6))
        bar.pack(fill=tk.X)

        ttk.Label(bar, text="Interface:").pack(side=tk.LEFT)
        self.iface_var = tk.StringVar()
        self.iface_combo = ttk.Combobox(bar, textvariable=self.iface_var, width=42)
        self.iface_combo.pack(side=tk.LEFT, padx=(4, 0))
        self._refresh_ifaces()
        ttk.Button(bar, text="Reload", command=self._refresh_ifaces, width=8).pack(side=tk.LEFT, padx=4)

        ttk.Label(bar, text="BPF:").pack(side=tk.LEFT, padx=(12, 0))
        self.filter_var = tk.StringVar(value="port 7892")
        ttk.Entry(bar, textvariable=self.filter_var, width=28).pack(side=tk.LEFT, padx=4)

        ttk.Label(bar, text="App:").pack(side=tk.LEFT, padx=(8, 0))
        self.app_filter_var = tk.StringVar(value="codex+chatgpt")
        preset_keys = ["(none)"] + sorted(PRESETS.keys())
        self.app_combo = ttk.Combobox(
            bar,
            textvariable=self.app_filter_var,
            values=preset_keys,
            state="readonly",
            width=14,
        )
        self.app_combo.pack(side=tk.LEFT, padx=4)

        self.drop_imposters_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(
            bar,
            text="Drop imposters",
            variable=self.drop_imposters_var,
        ).pack(side=tk.LEFT, padx=(4, 0))

        self.start_btn = ttk.Button(bar, text="Start", command=self.start_capture)
        self.start_btn.pack(side=tk.LEFT, padx=(16, 2))
        self.stop_btn = ttk.Button(bar, text="Stop", command=self.stop_capture, state=tk.DISABLED)
        self.stop_btn.pack(side=tk.LEFT, padx=2)
        self.save_btn = ttk.Button(bar, text="Save pcap...", command=self.save_pcap, state=tk.DISABLED)
        self.save_btn.pack(side=tk.LEFT, padx=(16, 2))
        self.analyze_btn = ttk.Button(bar, text="Analyze saved...", command=self.open_analyze)
        self.analyze_btn.pack(side=tk.LEFT, padx=2)
        self.analyze_now_btn = ttk.Button(bar, text="Analyze now", command=self.analyze_now, state=tk.DISABLED)
        self.analyze_now_btn.pack(side=tk.LEFT, padx=2)
        ttk.Button(bar, text="Open captures folder", command=self.open_captures_folder).pack(side=tk.LEFT, padx=(16, 2))
        ttk.Button(bar, text="Copy report", command=self.copy_report_to_clipboard).pack(side=tk.LEFT, padx=2)

        # Main split: packet list | (details over analysis)
        main = ttk.PanedWindow(self.root, orient=tk.HORIZONTAL)
        main.pack(fill=tk.BOTH, expand=True, padx=6, pady=(0, 6))

        list_frame = ttk.Frame(main)
        main.add(list_frame, weight=3)

        widths = {
            "no": 50,
            "time": 100,
            "process": 160,
            "pid": 60,
            "src": 180,
            "dst": 180,
            "proto": 60,
            "len": 70,
            "info": 280,
        }
        self.pkt_tree = ttk.Treeview(list_frame, columns=PACKET_COLUMNS, show="headings")
        for col in PACKET_COLUMNS:
            self.pkt_tree.heading(col, text=col.title())
            self.pkt_tree.column(col, width=widths[col], anchor=tk.W)
        sb_y = ttk.Scrollbar(list_frame, orient=tk.VERTICAL, command=self.pkt_tree.yview)
        sb_x = ttk.Scrollbar(list_frame, orient=tk.HORIZONTAL, command=self.pkt_tree.xview)
        self.pkt_tree.configure(yscrollcommand=sb_y.set, xscrollcommand=sb_x.set)
        self.pkt_tree.grid(row=0, column=0, sticky="nsew")
        sb_y.grid(row=0, column=1, sticky="ns")
        sb_x.grid(row=1, column=0, sticky="ew")
        list_frame.rowconfigure(0, weight=1)
        list_frame.columnconfigure(0, weight=1)
        self.pkt_tree.bind("<<TreeviewSelect>>", self._on_select_packet)

        right = ttk.PanedWindow(main, orient=tk.VERTICAL)
        main.add(right, weight=2)

        det_frame = ttk.Frame(right)
        right.add(det_frame, weight=2)
        ttk.Label(det_frame, text="Packet details").pack(side=tk.TOP, anchor=tk.W)
        det_text_wrap = ttk.Frame(det_frame)
        det_text_wrap.pack(side=tk.TOP, fill=tk.BOTH, expand=True)
        self.details_text = tk.Text(det_text_wrap, wrap=tk.NONE, font=("Consolas", 9))
        sd_y = ttk.Scrollbar(det_text_wrap, orient=tk.VERTICAL, command=self.details_text.yview)
        sd_x = ttk.Scrollbar(det_text_wrap, orient=tk.HORIZONTAL, command=self.details_text.xview)
        self.details_text.configure(yscrollcommand=sd_y.set, xscrollcommand=sd_x.set)
        self.details_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        sd_y.pack(side=tk.RIGHT, fill=tk.Y)
        sd_x.pack(side=tk.BOTTOM, fill=tk.X)

        ana_frame = ttk.Frame(right)
        right.add(ana_frame, weight=1)
        ttk.Label(ana_frame, text="Analysis (tshark)").pack(side=tk.TOP, anchor=tk.W)
        ana_text_wrap = ttk.Frame(ana_frame)
        ana_text_wrap.pack(side=tk.TOP, fill=tk.BOTH, expand=True)
        self.analysis_text = tk.Text(ana_text_wrap, wrap=tk.NONE, font=("Consolas", 9))
        sa_y = ttk.Scrollbar(ana_text_wrap, orient=tk.VERTICAL, command=self.analysis_text.yview)
        sa_x = ttk.Scrollbar(ana_text_wrap, orient=tk.HORIZONTAL, command=self.analysis_text.xview)
        self.analysis_text.configure(yscrollcommand=sa_y.set, xscrollcommand=sa_x.set)
        self.analysis_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        sa_y.pack(side=tk.RIGHT, fill=tk.Y)
        sa_x.pack(side=tk.BOTTOM, fill=tk.X)

        self.status_var = tk.StringVar(value="Ready. Pick interface + filter, then Start.")
        status = ttk.Label(self.root, textvariable=self.status_var, anchor=tk.W, relief=tk.SUNKEN, padding=(6, 2))
        status.pack(fill=tk.X, side=tk.BOTTOM)

    def _refresh_ifaces(self) -> None:
        ifaces = list_interfaces()
        self.iface_combo["values"] = ifaces
        # Priority: (1) saved config; (2) Loopback if available; (3) first interface
        saved = self.cfg.get("interface") or ""
        if saved and saved in ifaces:
            self.iface_var.set(saved)
            return
        if ifaces:
            loopback = next((i for i in ifaces if "loopback" in i.lower()), None)
            self.iface_var.set(loopback or ifaces[0])

    def _apply_cfg_to_widgets(self) -> None:
        """Push persisted settings into the tk vars before the user sees them."""
        self.filter_var.set(self.cfg.get("bpf_filter", "port 7892"))
        app_choice = self.cfg.get("app_filter", "codex")
        if app_choice in (self.app_combo["values"] or ()):
            self.app_filter_var.set(app_choice)
        # interface is set inside _refresh_ifaces after enumerating
        self._refresh_ifaces()

    def _save_cfg(self) -> None:
        self.cfg.update({
            "interface": self.iface_var.get(),
            "bpf_filter": self.filter_var.get(),
            "app_filter": self.app_filter_var.get(),
            "window_geometry": self.root.geometry(),
        })
        cfg_mod.save(self.cfg)

    # ---------- capture control ----------

    def start_capture(self) -> None:
        if self.capturing:
            return
        iface = self.iface_var.get() or None
        bpf = self.filter_var.get() or None

        # Resolve app filter preset -> list of process names -> AppPortFilter
        app_choice = self.app_filter_var.get()
        proc_names = [] if app_choice == "(none)" else (resolve_preset(app_choice) or [])
        self.app_filter = AppPortFilter(proc_names) if proc_names else None
        if self.app_filter is not None:
            self.app_filter.start()

        self.captured.clear()
        self.packet_count = 0
        for item in self.pkt_tree.get_children():
            self.pkt_tree.delete(item)
        while not self.pkt_queue.empty():
            try:
                self.pkt_queue.get_nowait()
            except queue.Empty:
                break

        self.sniffer = AsyncSniffer(iface=iface, filter=bpf, prn=self._on_packet, store=False)
        try:
            self.sniffer.start()
        except (OSError, PermissionError) as exc:
            messagebox.showerror("Capture failed", f"Could not start sniffer:\n{exc}")
            self.sniffer = None
            if self.app_filter is not None:
                self.app_filter.stop()
                self.app_filter = None
            return

        self.capturing = True
        self.start_time = time.monotonic()
        self._set_running(True)
        filter_desc = f"app={app_choice}" + (
            f" ({len(self.app_filter.ports)} ports, {len(self.app_filter.pids)} PIDs)"
            if self.app_filter else ""
        )
        self.status_var.set(
            f"Capturing on {iface or '<default>'}  bpf={bpf or '<none>'}  {filter_desc}"
        )

    def _on_packet(self, pkt: Packet) -> None:
        # Filter decision: if app filter active AND drop_imposters is on, reject
        # packets whose source/dest port is not owned by a target PID.
        is_target = True
        if self.app_filter is not None:
            is_target = self.app_filter.matches_packet(pkt)
        if not is_target and self.drop_imposters_var.get():
            self.dropped_count += 1
            return
        try:
            self.pkt_queue.put_nowait((pkt, is_target))
        except queue.Full:
            pass

    def stop_capture(self) -> None:
        if not self.capturing or self.sniffer is None:
            return
        self.sniffer.stop()
        self.sniffer = None
        self.capturing = False
        elapsed = time.monotonic() - self.start_time
        app_info = ""
        if self.app_filter is not None:
            app_info = f"  app-filter={self.app_filter_var.get()} (PIDs: {sorted(self.app_filter.pids)})"
            self.app_filter.stop()
            self.app_filter = None
        self._set_running(False)
        self.status_var.set(
            f"Stopped. {self.packet_count} packets in {elapsed:.1f}s.{app_info}  Auto-saving..."
        )

        # Auto-record: every Stop writes pcap + tshark report to captures/
        # so the artifact is always on disk for the user / an AI assistant
        # to read later. No need to click "Save".
        if self.captured:
            self._auto_record()

    def _auto_record(self) -> None:
        pcap_path, report_path = next_capture_paths()
        try:
            wrpcap(str(pcap_path), self.captured)
        except Exception as exc:  # noqa: BLE001
            self.status_var.set(f"Auto-save failed: {exc}")
            return
        # Run tshark analysis and write report alongside
        try:
            report = analyze_mod.analyze(str(pcap_path))
            report_path.write_text(analyze_mod.render_text(report), encoding="utf-8")
            summary = (
                f"Auto-saved: {pcap_path.name}  +  {report_path.name}  "
                f"({report.packet_count} pkts, {len(report.sni_counts)} SNI, "
                f"{len(report.dns_counts)} DNS, {len(report.http_requests)} HTTP)"
            )
        except Exception as exc:  # noqa: BLE001
            summary = f"Auto-saved: {pcap_path.name} (analyze failed: {exc})"
        self.status_var.set(summary)
        # Also render into the analysis pane so it's visible immediately
        self._run_analyze(str(pcap_path))

    def _set_running(self, running: bool) -> None:
        if running:
            self.start_btn.configure(state=tk.DISABLED)
            self.stop_btn.configure(state=tk.NORMAL)
            self.save_btn.configure(state=tk.DISABLED)
            self.analyze_now_btn.configure(state=tk.DISABLED)
        else:
            self.start_btn.configure(state=tk.NORMAL)
            self.stop_btn.configure(state=tk.DISABLED)
            self.save_btn.configure(state=tk.NORMAL if self.captured else tk.DISABLED)
            self.analyze_now_btn.configure(state=tk.NORMAL if self.captured else tk.DISABLED)

    # ---------- UI queue pump ----------

    def _poll_queue(self) -> None:
        try:
            for _ in range(self.POLL_BATCH):
                item = self.pkt_queue.get_nowait()
                pkt, is_target = item
                self.packet_count += 1
                self.captured.append(pkt)
                rel_t = time.monotonic() - self.start_time

                # Lookup owning process for the source port (annotation)
                proc_name, proc_pid = "?", "?"
                try:
                    from scapy.layers.inet import TCP
                    if TCP in pkt:
                        sport = pkt[TCP].sport
                        if self.app_filter is not None:
                            looked = self.app_filter.lookup_port(sport)
                            if looked:
                                proc_pid, proc_name = looked
                except Exception:  # noqa: BLE001
                    pass

                try:
                    line = format_packet(pkt, rel_t, self.packet_count)
                except Exception as exc:  # noqa: BLE001
                    line = f"{self.packet_count:>5}  ?  ?  ->  ?  ?  ?  <format error: {exc}>"
                parts = line.split(maxsplit=6)
                # Old format: [no, time, src, dst, proto, len, info]
                # New format: [no, time, process, pid, src, dst, proto, len, info]
                if len(parts) >= 7:
                    src, dst, proto, length, info = parts[2], parts[3], parts[4], parts[5], parts[6]
                else:
                    src, dst, proto, length, info = "?", "?", "?", "?", line
                # Highlight imposters visually
                marker = "" if is_target else " (dropped-rule)"
                row = [
                    parts[0],                 # no
                    parts[1],                 # time
                    proc_name + marker,       # process
                    str(proc_pid),            # pid
                    src,                      # src
                    dst,                      # dst
                    proto,                    # proto
                    length,                   # length
                    info,                     # info
                ]
                self.pkt_tree.insert("", tk.END, iid=str(self.packet_count), values=row)
        except queue.Empty:
            pass
        if self.capturing:
            self.status_var.set(
                f"Capturing... {self.packet_count} packets  "
                f"({self.dropped_count} dropped by filter)"
            )
        self.root.after(self.POLL_INTERVAL_MS, self._poll_queue)

    # ---------- packet details ----------

    def _on_select_packet(self, _evt: object) -> None:
        sel = self.pkt_tree.selection()
        if not sel:
            return
        try:
            idx = int(sel[0]) - 1
            pkt = self.captured[idx]
        except (ValueError, IndexError):
            return
        self.details_text.delete("1.0", tk.END)
        try:
            from scapy.all import ls
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                ls(pkt)
            text = buf.getvalue() or "(scapy ls() returned no output)"
        except Exception as exc:  # noqa: BLE001
            text = f"(error rendering packet: {exc})\n\nRaw:\n{pkt.summary()}"
        self.details_text.insert(tk.END, text)

    # ---------- save / analyze ----------

    def save_pcap(self) -> None:
        if not self.captured:
            messagebox.showinfo("Empty capture", "No packets to save yet.")
            return
        path = filedialog.asksaveasfilename(
            title="Save pcap",
            defaultextension=".pcap",
            filetypes=[("pcap files", "*.pcap"), ("all files", "*.*")],
        )
        if not path:
            return
        try:
            wrpcap(path, self.captured)
        except Exception as exc:  # noqa: BLE001
            messagebox.showerror("Save failed", str(exc))
            return
        self.status_var.set(f"Saved {len(self.captured)} packets to {path}")

    def analyze_now(self) -> None:
        if not self.captured:
            messagebox.showinfo("Empty capture", "No packets to analyze yet.")
            return
        path = filedialog.asksaveasfilename(
            title="Save pcap before analysis",
            defaultextension=".pcap",
            filetypes=[("pcap files", "*.pcap")],
        )
        if not path:
            return
        try:
            wrpcap(path, self.captured)
        except Exception as exc:  # noqa: BLE001
            messagebox.showerror("Save failed", str(exc))
            return
        self._run_analyze(path)

    def open_analyze(self) -> None:
        path = filedialog.askopenfilename(
            title="Open pcap",
            filetypes=[("pcap files", "*.pcap *.pcapng"), ("all files", "*.*")],
        )
        if not path:
            return
        self._run_analyze(path)

    def open_captures_folder(self) -> None:
        """Open the captures/ directory in Windows Explorer."""
        d = captures_dir()
        try:
            if sys.platform == "win32":
                os.startfile(str(d))  # type: ignore[attr-defined]
            elif sys.platform == "darwin":
                subprocess.Popen(["open", str(d)])
            else:
                subprocess.Popen(["xdg-open", str(d)])
        except Exception as exc:  # noqa: BLE001
            messagebox.showerror("Open folder failed", str(exc))

    def copy_report_to_clipboard(self) -> None:
        """Copy the analysis pane contents to the clipboard."""
        text = self.analysis_text.get("1.0", tk.END).rstrip()
        if not text:
            messagebox.showinfo("Nothing to copy", "Run analyze first.")
            return
        self.root.clipboard_clear()
        self.root.clipboard_append(text)
        self.status_var.set("Report copied to clipboard.")

    def _run_analyze(self, path: str) -> None:
        self.status_var.set(f"Analyzing {Path(path).name}...")
        self.analysis_text.delete("1.0", tk.END)
        try:
            report = analyze_mod.analyze(path)
            self.analysis_text.insert(tk.END, analyze_mod.render_text(report))
            self.status_var.set(
                f"Analyzed {Path(path).name}: {report.packet_count} pkts, "
                f"{len(report.sni_counts)} SNI, {len(report.dns_counts)} DNS"
            )
        except FileNotFoundError as exc:
            self.analysis_text.insert(tk.END, f"Error: {exc}")
            self.status_var.set("Analysis failed (tshark not found).")
        except Exception as exc:  # noqa: BLE001
            self.analysis_text.insert(tk.END, f"Error: {exc}")
            self.status_var.set("Analysis failed.")

    # ---------- lifecycle ----------

    def _on_close(self) -> None:
        if self.capturing:
            if not messagebox.askokcancel("Capture running", "Capture is still running. Stop and exit?"):
                return
            self.stop_capture()
        self._save_cfg()
        self.root.destroy()

    def run(self) -> None:
        self.root.mainloop()


def main() -> None:
    CodexCapGUI().run()


if __name__ == "__main__":
    main()