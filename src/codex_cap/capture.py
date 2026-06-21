"""Shared capture helpers used by both the CLI (`__main__.py`) and the GUI (`gui.py`).

Holds:
- `list_interfaces` — enumerate NPF (Npcap) interfaces
- `resolve_iface`    — accept NPF name / substring / index from a CLI string
- `capture`          — blocking scapy sniff loop with print + optional pcap dump

`gui.py` uses `AsyncSniffer` directly so it can stop programmatically; it
imports `list_interfaces` from here.
"""

from __future__ import annotations

import sys
import time
from typing import List, Optional

from scapy.all import Packet, get_if_list, sniff
from scapy.utils import wrpcap

from .format import format_packet


def list_interfaces() -> List[str]:
    return list(get_if_list())


def resolve_iface(spec: Optional[str]) -> Optional[str]:
    """Resolve an interface spec: NPF name, index, substring, or None for default.

    Raises SystemExit on bad input (CLI-friendly error reporting).
    """
    if spec is None:
        return None
    ifaces = list_interfaces()
    if spec.isdigit():
        idx = int(spec)
        if 0 <= idx < len(ifaces):
            return ifaces[idx]
        raise SystemExit(f"[codex-cap] interface index {idx} out of range (have {len(ifaces)})")
    if spec in ifaces:
        return spec
    matches = [i for i in ifaces if spec.lower() in i.lower()]
    if len(matches) == 1:
        return matches[0]
    if len(matches) > 1:
        print(f"[codex-cap] ambiguous interface '{spec}', candidates:", file=sys.stderr)
        for i, m in enumerate(matches):
            print(f"  {i}: {m}", file=sys.stderr)
        raise SystemExit(1)
    raise SystemExit(f"[codex-cap] no interface matching '{spec}' (use --list)")


def capture(
    iface: Optional[str],
    bpf: Optional[str],
    count: int,
    pcap_out: Optional[str],
    quiet: bool,
) -> int:
    """Run the blocking sniff loop. Returns packet count captured."""
    captured: List[Packet] = []
    start = time.monotonic()

    def handler(pkt: Packet) -> None:
        rel_t = time.monotonic() - start
        captured.append(pkt)
        if not quiet:
            try:
                line = format_packet(pkt, rel_t, len(captured))
            except Exception as exc:  # noqa: BLE001 — never crash capture on bad packet
                line = f"{rel_t:>9.6f} ? -> ? ? {len(pkt):>5} <format error: {exc}>"
            print(line, flush=True)

    if not quiet:
        if iface:
            print(f"[codex-cap] interface: {iface}", file=sys.stderr)
        else:
            print("[codex-cap] interface: <scapy default>", file=sys.stderr)
        if bpf:
            print(f"[codex-cap] BPF filter: {bpf}", file=sys.stderr)
        print("[codex-cap] capturing... (Ctrl+C to stop)", file=sys.stderr)

    sniff_kwargs = dict(iface=iface, filter=bpf, prn=handler, store=False)
    if count and count > 0:
        sniff_kwargs["count"] = count

    try:
        sniff(**sniff_kwargs)
    except KeyboardInterrupt:
        if not quiet:
            print("\n[codex-cap] interrupted", file=sys.stderr)

    if pcap_out and captured:
        wrpcap(pcap_out, captured)
        print(f"[codex-cap] wrote {len(captured)} packets to {pcap_out}", file=sys.stderr)

    return len(captured)