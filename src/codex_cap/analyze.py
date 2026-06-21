"""Preliminary pcap analysis via tshark.

Wraps tshark to extract:
- TLS Server Name Indication (SNI) from ClientHello
- DNS queries
- TCP conversation statistics (bytes per endpoint pair, duration)
- Packet count and capture duration

Output is a plain text report. Designed for the MVP — relies on tshark
being installed (bundled with Wireshark) for protocol dissection, since
re-implementing TLS/DNS/TCP parsing in scapy would duplicate Wireshark's
work.
"""

from __future__ import annotations

import shutil
import subprocess
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional


TSHARK_CANDIDATES = [
    r"C:\Program Files\Wireshark\tshark.exe",
    r"C:\Program Files (x86)\Wireshark\tshark.exe",
    "/Applications/Wireshark.app/Contents/MacOS/tshark",
    "/usr/bin/tshark",
    "/usr/local/bin/tshark",
]


def find_tshark(explicit: Optional[str] = None) -> str:
    """Return a working tshark path, or raise FileNotFoundError."""
    if explicit:
        p = Path(explicit)
        if not p.exists():
            raise FileNotFoundError(f"tshark not found at {explicit}")
        return str(p)
    # PATH first
    on_path = shutil.which("tshark")
    if on_path:
        return on_path
    for cand in TSHARK_CANDIDATES:
        if Path(cand).exists():
            return cand
    raise FileNotFoundError(
        "tshark not found. Install Wireshark (https://www.wireshark.org/) "
        "or pass --tshark PATH\\to\\tshark.exe"
    )


class TShark:
    """Thin wrapper around tshark. All methods run synchronously."""

    def __init__(self, path: str):
        self.path = path

    def _run(self, args: List[str]) -> str:
        cmd = [self.path, *args]
        result = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace")
        if result.returncode != 0:
            raise RuntimeError(
                f"tshark failed (exit {result.returncode}): {result.stderr.strip()}"
            )
        return result.stdout

    def duration_and_count(self, pcap: str) -> tuple[float, int]:
        """Return (duration_seconds, packet_count)."""
        out = self._run(["-r", pcap, "-T", "fields", "-e", "frame.time_epoch"])
        ts: List[float] = []
        for line in out.splitlines():
            line = line.strip()
            if line:
                try:
                    ts.append(float(line))
                except ValueError:
                    pass
        if not ts:
            return 0.0, 0
        return ts[-1] - ts[0], len(ts)

    def sni(self, pcap: str) -> List[str]:
        """All TLS Server Name Indication values seen in ClientHellos."""
        out = self._run([
            "-r", pcap,
            "-Y", "tls.handshake.extensions_server_name",
            "-T", "fields",
            "-e", "tls.handshake.extensions_server_name",
        ])
        return [ln.strip() for ln in out.splitlines() if ln.strip()]

    def dns_queries(self, pcap: str) -> List[str]:
        """All DNS query names (response packets excluded)."""
        out = self._run([
            "-r", pcap,
            "-Y", "dns.flags.response == 0",
            "-T", "fields",
            "-e", "dns.qry.name",
        ])
        return [ln.strip() for ln in out.splitlines() if ln.strip()]

    def tcp_conversations(self, pcap: str) -> str:
        """tshark conv,tcp text table."""
        return self._run(["-r", pcap, "-q", "-z", "conv,tcp"])

    def http_requests(self, pcap: str) -> List[tuple[str, str, str]]:
        """Return list of (method, host, uri) tuples for HTTP requests seen."""
        out = self._run([
            "-r", pcap,
            "-Y", "http.request",
            "-T", "fields",
            "-e", "http.request.method",
            "-e", "http.host",
            "-e", "http.request.uri",
        ])
        result = []
        for ln in out.splitlines():
            parts = ln.split("\t")
            if len(parts) >= 3:
                result.append((parts[0].strip(), parts[1].strip(), parts[2].strip()))
        return result


@dataclass
class Report:
    pcap: str
    packet_count: int = 0
    duration_s: float = 0.0
    sni_counts: Counter = field(default_factory=Counter)
    dns_counts: Counter = field(default_factory=Counter)
    http_requests: List[tuple[str, str, str]] = field(default_factory=list)
    tcp_conversations_raw: str = ""


def analyze(pcap: str, tshark_path: Optional[str] = None) -> Report:
    path = find_tshark(tshark_path)
    ts = TShark(path)
    r = Report(pcap=pcap)
    r.duration_s, r.packet_count = ts.duration_and_count(pcap)
    r.sni_counts = Counter(ts.sni(pcap))
    r.dns_counts = Counter(ts.dns_queries(pcap))
    r.http_requests = ts.http_requests(pcap)
    r.tcp_conversations_raw = ts.tcp_conversations(pcap)
    return r


def render_text(r: Report) -> str:
    out: List[str] = []
    out.append(f"=== codex-cap analysis: {r.pcap} ===")
    out.append("")
    out.append(f"  packets : {r.packet_count}")
    out.append(f"  duration: {r.duration_s:.3f} s")
    out.append("")

    out.append("--- TLS SNI (top 20) ---")
    if r.sni_counts:
        for sni, c in r.sni_counts.most_common(20):
            out.append(f"  {c:>5}  {sni}")
    else:
        out.append("  (no TLS ClientHello captured)")
    out.append("")

    out.append("--- DNS queries (top 20) ---")
    if r.dns_counts:
        for name, c in r.dns_counts.most_common(20):
            out.append(f"  {c:>5}  {name}")
    else:
        out.append("  (no DNS queries captured)")
    out.append("")

    if r.http_requests:
        out.append(f"--- HTTP requests ({len(r.http_requests)}) ---")
        for method, host, uri in r.http_requests[:50]:
            out.append(f"  {method:>6}  {host}{uri}")
        if len(r.http_requests) > 50:
            out.append(f"  ... ({len(r.http_requests) - 50} more)")
        out.append("")

    out.append("--- TCP conversations (tshark conv,tcp) ---")
    out.append(r.tcp_conversations_raw.rstrip())

    return "\n".join(out)