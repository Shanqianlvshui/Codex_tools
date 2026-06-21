"""Process-aware packet filter.

Maintains a rolling map of TCP source port -> set of owning PIDs for processes
whose name matches a configured list (e.g. "Codex", "ChatGPT"). Lets the
capture pipeline drop packets that did not originate from one of those PIDs
on a matching port — critical when capturing a system-level proxy port like
127.0.0.1:7892 where unrelated apps also appear.

Usage:
    flt = AppPortFilter(["Codex", "ChatGPT"], poll_interval_s=0.2)
    flt.start()
    ...
    if not flt.matches_packet(pkt):
        return  # drop
    ...
    flt.stop()

Why port + PID (not just port):
    Ephemeral ports get reassigned to other processes quickly. A 1-second
    poll interval misses that and lets imposters through (verified empirically:
    Edge / Taobao / VS Code picked up Codex's just-released ports within ~100ms).
    Tracking `port -> {pids}` lets us reject packets whose source port is
    currently owned by a NON-target PID even if that port was a target port
    moments ago.

Note: PID-based filtering at the WinDivert driver level would be cleaner,
but the bundled pydivert 3.1.3 filter language does not recognize `pid`
("Filter expression contains a bad token" / WinError 87). The
port+PID-double-check approach gets us close to driver-level accuracy
with what works today.
"""

from __future__ import annotations

import threading
import time
from typing import Dict, Iterable, List, Optional, Set

try:
    import psutil
except ImportError as exc:  # pragma: no cover
    raise ImportError(
        "psutil is required for process-aware filtering. "
        "Install with: python -m pip install psutil"
    ) from exc


PRESETS = {
    "codex": ["Codex", "codex"],          # Codex Desktop + lowercase helper
    "chatgpt": ["ChatGPT"],                # ChatGPT desktop app
    "codex+chatgpt": ["Codex", "codex", "ChatGPT"],
}


class AppPortFilter:
    """Dynamic port->PID map filter. Updates via psutil.net_connections()."""

    def __init__(
        self,
        process_names: Iterable[str],
        poll_interval_s: float = 0.2,
    ) -> None:
        self.process_names: List[str] = list(process_names)
        self.poll_interval_s = poll_interval_s
        # port -> set of PIDs currently using that port (per psutil snapshot)
        self._port_to_pids: Dict[int, Set[int]] = {}
        # cached set of target PIDs (for fast lookups)
        self._target_pids: Set[int] = set()
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None

    # ---------- lifecycle ----------

    def start(self) -> None:
        if self._thread is not None:
            return
        self._refresh()
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, name="AppPortFilter", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=2.0)
            self._thread = None

    # ---------- matching ----------

    def matches_packet(self, pkt) -> bool:
        """Return True if pkt's TCP source port is currently owned by a target PID.

        If no processes are configured (empty filter), always True (no filter).
        If target PIDs is empty (target process not running), always False
        (strict — don't leak non-target traffic).
        Non-TCP packets: pass if no filter active, drop if filter active.
        """
        with self._lock:
            if not self.process_names:
                return True
            target_pids = self._target_pids
            port_map = self._port_to_pids
            if not target_pids:
                # Strict: no target running -> block everything.
                return False
            if not port_map:
                # Have target PIDs but their TCP tables haven't been read yet.
                # Strict: don't accept anything we can't prove is from a target.
                return False

        try:
            from scapy.layers.inet import TCP
            if TCP not in pkt:
                return False
        except Exception:  # noqa: BLE001
            return True

        sport = pkt[TCP].sport
        dport = pkt[TCP].dport

        # Primary match: source port's owner is a target PID.
        # (We don't trust dport==7892 because EVERYTHING connects to the
        # proxy; the meaningful side is the source.)
        sport_pids = port_map.get(sport, set())
        if sport_pids & target_pids:
            return True
        # Fallback for SYN-ACK / proxy-response packets: the destination port
        # is Codex's ephemeral. If Codex PID owns that port, accept.
        dport_pids = port_map.get(dport, set())
        if dport_pids & target_pids:
            return True
        return False

    @property
    def ports(self) -> Set[int]:
        with self._lock:
            return set(self._port_to_pids.keys())

    @property
    def pids(self) -> Set[int]:
        with self._lock:
            return set(self._target_pids)

    def lookup_port(self, port: int) -> Optional[Tuple[int, str]]:
        """Return (pid, process_name) currently using this TCP port, or None.

        Used to annotate captured packets with their owning PID so the user
        can see exactly which process each packet came from. Cached via the
        poll loop so it's effectively O(1).
        """
        with self._lock:
            port_to_pids = self._port_to_pids
        if not port_to_pids:
            return None
        # Only meaningful if we have *any* target PIDs being tracked; if empty,
        # do a fresh psutil lookup for that specific port.
        try:
            for c in psutil.net_connections(kind="tcp"):
                if c.laddr and c.laddr.port == port:
                    if c.pid:
                        try:
                            name = psutil.Process(c.pid).name()
                            return (c.pid, name)
                        except (psutil.NoSuchProcess, psutil.AccessDenied):
                            return (c.pid, "<unknown>")
            return None
        except (psutil.AccessDenied, OSError):
            return None

    def stats(self) -> dict:
        """Snapshot for the GUI: how many ports/PIDs being tracked."""
        with self._lock:
            return {
                "pids": len(self._target_pids),
                "ports": len(self._port_to_pids),
            }

    # ---------- internals ----------

    def _refresh(self) -> None:
        if not self.process_names:
            with self._lock:
                self._port_to_pids.clear()
                self._target_pids.clear()
            return

        # Windows psutil returns names with ".exe"; strip for comparison.
        names_lower = {n.lower().removesuffix(".exe") for n in self.process_names}
        target_pids: Set[int] = set()
        try:
            for p in psutil.process_iter(["name"]):
                n = (p.info.get("name") or "").lower().removesuffix(".exe")
                if n and n in names_lower:
                    target_pids.add(p.pid)
        except (psutil.AccessDenied, OSError):
            target_pids = set()

        port_map: Dict[int, Set[int]] = {}
        if target_pids:
            try:
                for c in psutil.net_connections(kind="tcp"):
                    if c.pid in target_pids and c.laddr is not None:
                        port_map.setdefault(c.laddr.port, set()).add(c.pid)
            except (psutil.AccessDenied, OSError):
                # On Windows without admin, net_connections() may fail partially.
                pass

        with self._lock:
            self._target_pids = target_pids
            self._port_to_pids = port_map

    def _loop(self) -> None:
        while not self._stop.is_set():
            self._refresh()
            self._stop.wait(self.poll_interval_s)


def resolve_preset(name: str) -> Optional[List[str]]:
    """Map a preset name (e.g. 'codex+chatgpt') to a list of process names."""
    return PRESETS.get(name.lower())