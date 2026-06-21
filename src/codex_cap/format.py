"""Wireshark-style one-line packet formatter.

Output columns (Wireshark-ish):
    No.   Time         Source            -> Dest              Proto  Length  Info
"""

from __future__ import annotations

from typing import Optional

from scapy.packet import Packet
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.inet6 import IPv6


def _ip_layer(pkt: Packet):
    if IP in pkt:
        return pkt[IP]
    if IPv6 in pkt:
        return pkt[IPv6]
    return None


def _transport_info(pkt: Packet) -> tuple[str, str]:
    """Return (proto, info) for the transport layer, or (proto_guess, '')."""
    if TCP in pkt:
        t = pkt[TCP]
        flags = str(t.flags)
        info = f"{t.sport} -> {t.dport} [{flags}] Seq={t.seq} Win={t.window}"
        return "TCP", info
    if UDP in pkt:
        u = pkt[UDP]
        info = f"{u.sport} -> {u.dport} Len={u.len}"
        return "UDP", info
    return "", ""


def _guess_proto_from_ports(sport: Optional[int], dport: Optional[int]) -> str:
    if sport is None and dport is None:
        return "?"
    for p in (sport, dport):
        if p == 443:
            return "TLS"
        if p == 80:
            return "HTTP"
        if p == 53:
            return "DNS"
    return "?"


def format_packet(pkt: Packet, rel_time: float, seq: int) -> str:
    n = seq
    t = f"{rel_time:>10.6f}"
    length = len(pkt)

    ip = _ip_layer(pkt)
    src = ip.src if ip is not None else "?"
    dst = ip.dst if ip is not None else "?"

    proto, info = _transport_info(pkt)
    if not proto:
        sport = dport = None
        if hasattr(pkt, "sport"):
            sport = pkt.sport
        if hasattr(pkt, "dport"):
            dport = pkt.dport
        proto = _guess_proto_from_ports(sport, dport)

    return (
        f"{n:>5}  {t}  {src:<39} -> {dst:<39}  {proto:<5}  {length:>5}  {info}"
    )