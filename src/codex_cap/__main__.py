"""codex_cap CLI entry point.

Wireshark-like packet capture for Codex traffic analysis.

Usage examples:
    python -m codex_cap -i NPF_Loopback -c 5
    python -m codex_cap -f "tcp port 443" -w sample.pcap
    python -m codex_cap --list
"""

from __future__ import annotations

import argparse
import signal
import sys
import time
from typing import List, Optional

from scapy.all import Packet, get_if_list, sniff
from scapy.utils import wrpcap

from .format import format_packet
from . import __version__


def list_interfaces() -> List[str]:
    return list(get_if_list())


def _resolve_iface(spec: Optional[str]) -> Optional[str]:
    """Resolve an interface spec: NPF name, index, substring, or None for default."""
    if spec is None:
        return None
    ifaces = list_interfaces()
    # Numeric index
    if spec.isdigit():
        idx = int(spec)
        if 0 <= idx < len(ifaces):
            return ifaces[idx]
        raise SystemExit(f"[codex-cap] interface index {idx} out of range (have {len(ifaces)})")
    # Exact NPF name match
    if spec in ifaces:
        return spec
    # Substring match (e.g. "Loopback" -> "NPF_Loopback")
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
    """Run the sniff loop. Returns count of packets captured."""
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

    sniff_kwargs = dict(
        iface=iface,
        filter=bpf,
        prn=handler,
        store=False,
    )
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


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="codex-cap",
        description="Wireshark-like packet capture for Codex traffic analysis.",
    )
    p.add_argument("-i", "--interface", help="Interface NPF name, substring, or index (default: scapy default)")
    p.add_argument("-f", "--filter", help='BPF filter, e.g. "tcp port 443 and host chatgpt.com"')
    p.add_argument("-c", "--count", type=int, default=0, help="Stop after N packets (0 = until Ctrl+C)")
    p.add_argument("-w", "--write", metavar="PCAP", help="Save captured packets to pcap file")
    p.add_argument("-q", "--quiet", action="store_true", help="Suppress per-packet output (still saves pcap if -w)")
    p.add_argument("--list", action="store_true", help="List available interfaces and exit")
    p.add_argument("--version", action="version", version=f"codex-cap {__version__}")
    return p


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.list:
        print("Available interfaces:")
        for i, name in enumerate(list_interfaces()):
            print(f"  {i}: {name}")
        return 0

    try:
        iface = _resolve_iface(args.interface)
    except SystemExit as exc:
        print(str(exc), file=sys.stderr)
        return 2

    # Ensure Ctrl+C is handled cleanly on Windows
    signal.signal(signal.SIGINT, signal.default_int_handler)

    n = capture(
        iface=iface,
        bpf=args.filter,
        count=args.count,
        pcap_out=args.write,
        quiet=args.quiet,
    )

    if n == 0 and not args.quiet:
        print("[codex-cap] no packets captured", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())