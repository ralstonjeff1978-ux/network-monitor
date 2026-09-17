#!/usr/bin/env python3
"""
Accurate device identification via the full IEEE OUI registry.

The built-in vendor map in exposure_audit only covers a handful of common IoT makers, so
most devices show up as "unknown". This loads the official IEEE OUI/MA-L registry
(`data/oui.csv`, ~40k organizations) and resolves almost any MAC to its real manufacturer —
turning "unknown · unknown" into "Amazon Technologies", "Roku", "Hangzhou Hikvision", etc.,
which is what lets you actually recognize the vacuum, the TV, or a device that shouldn't be there.

Fully offline once the CSV is present; degrades to the built-in map if it isn't. The registry
is public data, re-downloadable with `--update` (or scripts/update_oui.py).
"""
from __future__ import annotations

import csv
import os

_CSV = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "oui.csv")
_CACHE: dict[str, str] | None = None


def _normalize_prefix(assignment: str) -> str:
    """'286FB9' -> '28:6f:b9' (lowercase, colon-joined) to match a MAC's first 3 octets."""
    a = assignment.strip().lower()
    return ":".join(a[i:i + 2] for i in range(0, 6, 2)) if len(a) >= 6 else ""


def load(path: str | None = None) -> dict[str, str]:
    """Parse the IEEE OUI CSV into {oui_prefix: organization}. Cached after first call."""
    global _CACHE
    if _CACHE is not None:
        return _CACHE
    path = path if path is not None else _CSV   # read the module _CSV at call time (test-patchable)
    table: dict[str, str] = {}
    try:
        with open(path, newline="", encoding="utf-8", errors="replace") as f:
            reader = csv.DictReader(f)
            for row in reader:
                pref = _normalize_prefix(row.get("Assignment", ""))
                org = (row.get("Organization Name") or "").strip()
                if pref and org:
                    table[pref] = org
    except OSError:
        pass
    _CACHE = table
    return table


def lookup(mac: str) -> str:
    """Manufacturer for a MAC via the IEEE registry, or '' if unknown / registry absent."""
    if not mac:
        return ""
    prefix = mac.lower().replace("-", ":")[:8]
    return load().get(prefix, "")


def available() -> bool:
    return os.path.exists(_CSV)
