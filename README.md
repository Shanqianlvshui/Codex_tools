# codex-cap

Wireshark-like packet capture for Codex traffic analysis. MVP — captures
packets via Npcap and prints them in Wireshark-style columns; optionally saves
a `.pcap` you can open in Wireshark for full protocol dissection.

## Why this exists

`Codex_tools` is being built up incrementally. The first concrete module is a
packet capture tool, used to:

1. Collect empirical request samples from real Codex traffic
2. Identify which auth headers / cookies the Codex desktop client sends
3. Drive later design decisions (MITM proxy? auth-storage swap? hook layer?)

This module answers question 1 and 2; later modules will act on the answers.

## Requirements

- Windows (uses Npcap)
- Python >= 3.11
- Npcap installed and the `npcap` / `npf` services running
  - Bundled with Wireshark, or install separately from <https://npcap.com>
- Python deps: `scapy`, `rich` (see `pyproject.toml`)

## Install

```powershell
cd C:\Workspace\Codex_tools
python -m pip install -e .
```

This gives you a `codex-cap` console script. For quick iteration you can also
just run the module directly:

```powershell
python -m codex_cap --list
python -m codex_cap -i NPF_Loopback -c 5
```

## Usage

```text
python -m codex_cap [options]

  -i, --interface NAME    NPF interface name, substring, or index
  -f, --filter BPF        BPF filter string, e.g. "tcp port 443"
  -c, --count N           Stop after N packets (0 = until Ctrl+C)
  -w, --write PCAP        Save packets to a pcap file
  -q, --quiet             Suppress per-packet output (still writes pcap)
      --list              List interfaces and exit
      --version
```

### Quickstart: capture 5 packets on the loopback interface

```powershell
python -m codex_cap -i Loopback -c 5
```

### Capture HTTPS-looking traffic to a pcap (open later in Wireshark)

```powershell
python -m codex_cap -f "tcp port 443" -w codex_sample.pcap
# open C:\Program Files\Wireshark\Wireshark.exe codex_sample.pcap
```

### Filter to one host

```powershell
python -m codex_cap -f "host 1.2.3.4" -w host.pcap
```

## Output format

One line per packet, Wireshark-style columns:

```text
    No.        Time         Source                                  -> Dest                                    Proto    Length  Info
      1   0.000123   192.168.1.5                                -> 1.1.1.1                                  TLS        517  443 -> 60412 [S] Seq=...
```

## Analyze a captured pcap (preliminary report)

After capturing traffic, run a quick analysis without opening Wireshark:

```powershell
python -m codex_cap analyze codex_sample.pcap
```

Uses tshark (bundled with Wireshark) to extract:

- Packet count + capture duration
- TLS SNI (which domains Codex reached)
- DNS queries
- HTTP requests (if any plain-text HTTP)
- TCP conversations with byte counts

tshark path is auto-detected (`C:\Program Files\Wireshark\tshark.exe`,
`tshark` on `PATH`, or Wireshark install on macOS/Linux). Pass
`--tshark PATH` to override.

### Sample output

```text
=== codex-cap analysis: codex_sample.pcap ===

  packets : 1234
  duration: 60.123 s

--- TLS SNI (top 20) ---
     47  chatgpt.com
     12  api.openai.com
      3  statsigapi.net
      ...

--- DNS queries (top 20) ---
     12  chatgpt.com
      ...

--- TCP conversations (tshark conv,tcp) ---
...
```

This is the first-cut "what is Codex talking to?" view. For deeper
inspection (full TLS details, stream following, HTTP/2 headers),
open the pcap in Wireshark directly.

## Open the pcap in Wireshark

```powershell
& "C:\Program Files\Wireshark\Wireshark.exe" codex_sample.pcap
```

Wireshark's protocol dissectors (TLS, HTTP/2, DNS, ...) work on the saved
pcap — this tool intentionally does NOT re-implement them.

## GUI (recommended for interactive use)

```powershell
python -m codex_cap            # launches GUI by default when no args given
python -m codex_cap gui        # explicit
```

A Tkinter window with three panes, Wireshark-style:

- **Top bar** — interface dropdown, BPF filter, Start / Stop / Save pcap / Analyze buttons
- **Left** — live packet table (No. / Time / Src / Dst / Proto / Len / Info)
- **Top-right** — selected packet details (via scapy's `ls()`)
- **Bottom-right** — tshark analysis output (SNI / DNS / conv table)

Click a row in the packet table to see its parsed structure on the right.
Hit `Stop`, then `Save pcap...` or `Analyze now` to write a pcap and run
the preliminary tshark report without leaving the window.

Default BPF is pre-filled with `port 7892` (Clash / common local proxy
port) so capturing Codex's outbound traffic through a local proxy is
one click away.

## Roadmap (later modules, not in MVP)

- TLS ClientHello SNI extraction (no decryption needed)
- HTTP / HTTP/2 CONNECT-style proxy with TLS fingerprint cloning
- Account rotation module driven by captured auth headers
- See `AGENTS.md` for repo conventions; this MVP is the first commit toward
  the larger Codex_tools plan.

## Development

```powershell
# install in editable mode
python -m pip install -e .

# quick smoke test
python -m codex_cap --list
```