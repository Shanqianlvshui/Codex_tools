"""Process-aware packet filter.

Maintains a rolling set of TCP source ports belonging to processes whose
name matches a configured list (e.g. "Codex", "ChatGPT"). Lets the
capture pipeline drop packets that did not originate from (or terminate
at) one of those ports — critical when capturing a system-level proxy
port like 127.0.0.1:7892 where unrelated apps also appear.

Usage:
    flt = AppPortFilter(["Codex", "ChatGPT"], poll_interval_s=1.0)
    flt.start()
    ...
    if not flt.matches_packet(pkt):
        return  # drop
    ...
    flt.stop()

Note: ephemeral ports move quickly. The refresh loop updates the port set
~once per second so connections opened after that interval get picked up
within a second. Ports closed by the process drop out at the next refresh.
"""

from __future__ import annotations

import threading
import time
from typing import Iterable, List, Optional, Set

try:
    import psutil
except ImportError as exc:  # pragma: no cover
    raise ImportError(
        "psutil is required for process-aware filtering. "
        "Install with: python -m pip install psutil"
    ) from exc


# Preset bundles so users don't have to remember exact process names.
PRESETS = {
    "codex": ["Codex", "codex"],          # Codex CLI + lowercase helper
    "chatgpt": ["ChatGPT"],                # ChatGPT desktop app
    "codex+chatgpt": ["Codex", "codex", "ChatGPT"],
}


class AppPortFilter:
    """Dynamic port-set filter driven by psutil.net_connections()."""

    def __init__(
        self,
        process_names: Iterable[str],
        poll_interval_s: float = 1.0,
    ) -> None:
        self.process_names: List[str] = list(process_names)
        self.poll_interval_s = poll_interval_s
        self._ports: Set[int] = set()
        self._pids: Set[int] = set()
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
        """Return True if pkt's TCP sport/dport is in the current target-port set.

        If no processes are configured (empty filter), always True (no filter).
        Non-TCP packets: only pass if no filter is active.
        """
        with self._lock:
            if not self.process_names or not self._ports:
                return True
            ports = self._ports

        try:
            from scapy.layers.inet import TCP
            if TCP not in pkt:
                return False
            return pkt[TCP].sport in ports or pkt[TCP].dport in ports
        except Exception:  # noqa: BLE001
            return True  # on error, don't drop — safer to capture too much than too little

    @property
    def ports(self) -> Set[int]:
        with self._lock:
            return set(self._ports)

    @property
    def pids(self) -> Set[int]:
        with self._lock:
            return set(self._pids)

    # ---------- internals ----------

    def _refresh(self) -> None:
        if not self.process_names:
            with self._lock:
                self._ports.clear()
                self._pids.clear()
            return

        # Windows psutil returns names with ".exe"; strip for comparison.
        names_lower = {n.lower().removesuffix(".exe") for n in self.process_names}
        procs: Set[int] = set()
        try:
            for p in psutil.process_iter(["name"]):
                n = (p.info.get("name") or "").lower().removesuffix(".exe")
                if n and n in names_lower:
                    procs.add(p.pid)
        except (psutil.AccessDenied, OSError):
            procs = set()

        ports: Set[int] = set()
        if procs:
            try:
                for c in psutil.net_connections(kind="tcp"):
                    if c.pid in procs and c.laddr is not None:
                        ports.add(c.laddr.port)
            except (psutil.AccessDenied, OSError):
                # On Windows without admin, net_connections() may fail partially.
                # Best effort: still keep pids so caller knows filter is live.
                pass

        with self._lock:
            self._pids = procs
            self._ports = ports

    def _loop(self) -> None:
        while not self._stop.is_set():
            self._refresh()
            # wake up either on interval or on stop
            self._stop.wait(self.poll_interval_s)


def resolve_preset(name: str) -> Optional[List[str]]:
    """Map a preset name (e.g. 'codex+chatgpt') to a list of process names."""
    return PRESETS.get(name.lower())