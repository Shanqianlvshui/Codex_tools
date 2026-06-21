"""Persist user preferences across GUI sessions.

Stored at %APPDATA%/codex_cap/config.json (Windows) or
~/.config/codex_cap/config.json (POSIX) so they survive across runs
of `python -m codex_cap`.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any


def _config_dir() -> Path:
    if os.name == "nt":
        base = os.environ.get("APPDATA") or str(Path.home())
        return Path(base) / "codex_cap"
    # POSIX: respect XDG, fall back to ~/.config
    base = os.environ.get("XDG_CONFIG_HOME") or str(Path.home() / ".config")
    return Path(base) / "codex_cap"


CONFIG_PATH = _config_dir() / "config.json"


DEFAULTS: dict[str, Any] = {
    # Default to loopback since 127.0.0.1:7892 is the user's local proxy.
    # The actual interface NPF GUID is overwritten by the GUI on first load.
    "interface": "",
    # Most common Codex capture: port 7892 (Clash / local HTTP proxy).
    "bpf_filter": "port 7892",
    # User's actual choice: Codex only (not Codex + ChatGPT).
    "app_filter": "codex",
    # Persist window size so it opens the same way next time.
    "window_geometry": "1280x780",
}


def load() -> dict:
    """Load user config, layered over DEFAULTS so missing keys still work."""
    cfg = dict(DEFAULTS)
    if CONFIG_PATH.exists():
        try:
            data = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                cfg.update(data)
        except (OSError, json.JSONDecodeError):
            pass
    return cfg


def save(cfg: dict) -> None:
    """Persist user config. Never raises — config is convenience, not critical."""
    try:
        CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
        CONFIG_PATH.write_text(json.dumps(cfg, indent=2, ensure_ascii=False), encoding="utf-8")
    except OSError:
        pass


def path_for_display() -> str:
    """Human-readable path used in status messages."""
    return str(CONFIG_PATH)