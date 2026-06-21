"""codex_cap CLI entry point.

Wireshark-like packet capture for Codex traffic analysis.

Usage examples:
    python -m codex_cap                      # launch GUI
    python -m codex_cap -i NPF_Loopback -c 5 # CLI capture
    python -m codex_cap analyze sample.pcap  # analyze saved pcap
"""

from __future__ import annotations

import argparse
import signal
import sys
from typing import List, Optional

from .capture import capture as run_capture_blocking
from .capture import list_interfaces, resolve_iface
from . import __version__
from . import analyze as analyze_mod


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="codex-cap",
        description="Wireshark-like packet capture for Codex traffic analysis.",
    )
    # Capture flags at top level (back-compat: `codex-cap -i foo -c 5` still works)
    p.add_argument("-i", "--interface", help="Interface NPF name, substring, or index (default: scapy default)")
    p.add_argument("-f", "--filter", help='BPF filter, e.g. "tcp port 443 and host chatgpt.com"')
    p.add_argument("-c", "--count", type=int, default=0, help="Stop after N packets (0 = until Ctrl+C)")
    p.add_argument("-w", "--write", metavar="PCAP", help="Save captured packets to pcap file")
    p.add_argument("-q", "--quiet", action="store_true", help="Suppress per-packet output (still saves pcap if -w)")
    p.add_argument("--list", action="store_true", help="List available interfaces and exit")
    p.add_argument("--version", action="version", version=f"codex-cap {__version__}")

    sub = p.add_subparsers(dest="command")

    ana_p = sub.add_parser("analyze", help="Run preliminary analysis on a pcap file via tshark")
    ana_p.add_argument("pcap", help="Path to pcap file to analyze")
    ana_p.add_argument("--tshark", default=None, help="Path to tshark.exe (auto-detected otherwise)")

    sub.add_parser("gui", help="Launch the GUI (default if no args)")

    return p


def _run_capture(args: argparse.Namespace) -> int:
    if args.list:
        print("Available interfaces:")
        for i, name in enumerate(list_interfaces()):
            print(f"  {i}: {name}")
        return 0

    try:
        iface = resolve_iface(args.interface)
    except SystemExit as exc:
        print(str(exc), file=sys.stderr)
        return 2

    signal.signal(signal.SIGINT, signal.default_int_handler)

    n = run_capture_blocking(
        iface=iface,
        bpf=args.filter,
        count=args.count,
        pcap_out=args.write,
        quiet=args.quiet,
    )

    if n == 0 and not args.quiet:
        print("[codex-cap] no packets captured", file=sys.stderr)
    return 0


def _run_analyze(args: argparse.Namespace) -> int:
    try:
        report = analyze_mod.analyze(args.pcap, tshark_path=args.tshark)
    except FileNotFoundError as exc:
        print(f"[codex-cap] {exc}", file=sys.stderr)
        return 2
    except RuntimeError as exc:
        print(f"[codex-cap] {exc}", file=sys.stderr)
        return 3
    print(analyze_mod.render_text(report))
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    if argv is None:
        argv = sys.argv[1:]

    # No args at all -> launch GUI (the common case).
    if not argv:
        from .gui import main as gui_main
        gui_main()
        return 0

    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "analyze":
        return _run_analyze(args)
    if args.command == "gui":
        from .gui import main as gui_main
        gui_main()
        return 0
    return _run_capture(args)


if __name__ == "__main__":
    sys.exit(main())