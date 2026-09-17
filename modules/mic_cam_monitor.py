#!/usr/bin/env python3
"""
Mic / webcam access monitor (Windows-native).

Windows records, per application, when the microphone and camera were last used, in the
CapabilityAccessManager "ConsentStore". Each app key carries LastUsedTimeStart and
LastUsedTimeStop (FILETIME). A **stop time of 0 means the device is IN USE RIGHT NOW**.

This module reads those keys (per-user and machine-wide, packaged and desktop apps) and
reports which apps are using — or recently used — your mic/camera. The guardian service
polls it and pushes a phone alert the moment something STARTS using them, so nothing
listens or watches without your knowledge.

Pure Windows registry reads. No network, no drivers, no packets — zero impact on gaming.
Degrades cleanly on non-Windows (returns empty) so the rest of the suite still imports.
"""
from __future__ import annotations

from dataclasses import dataclass

try:
    import winreg
    _WIN = True
except ImportError:
    _WIN = False

_CONSENT = r"SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore"
_DEVICES = ("microphone", "webcam")
# FILETIME epoch (1601) → Unix epoch (1970) offset in 100-ns ticks.
_FT_EPOCH_DIFF = 116444736000000000
_FT_PER_SEC = 10_000_000


def _ft_to_unix(ft: int) -> float | None:
    if not ft:
        return None
    return (ft - _FT_EPOCH_DIFF) / _FT_PER_SEC


@dataclass(frozen=True)
class Usage:
    device: str          # "microphone" | "webcam"
    app: str             # readable app name
    in_use: bool         # True == currently accessing the device (stop time == 0)
    last_start: float | None = None   # unix seconds
    last_stop: float | None = None

    def key(self) -> tuple:
        return (self.device, self.app)


def _readable_app(raw: str) -> str:
    """Turn a ConsentStore subkey name into something human-readable.

    Desktop apps are stored under NonPackaged with '#'-escaped full paths; packaged apps use
    their package family name. We surface the executable / last path segment.
    """
    name = raw.replace("#", "\\")
    seg = name.rstrip("\\").split("\\")[-1]
    return seg or raw


def _read_hive(hive, device: str) -> list[Usage]:
    out: list[Usage] = []
    base = f"{_CONSENT}\\{device}"

    def scan(parent_path: str, prefix: str = ""):
        try:
            k = winreg.OpenKey(hive, parent_path)
        except OSError:
            return
        try:
            i = 0
            while True:
                try:
                    sub = winreg.EnumKey(k, i)
                except OSError:
                    break
                i += 1
                if sub == "NonPackaged":
                    scan(f"{parent_path}\\NonPackaged", prefix="")
                    continue
                start = _read_val(hive, f"{parent_path}\\{sub}", "LastUsedTimeStart")
                stop = _read_val(hive, f"{parent_path}\\{sub}", "LastUsedTimeStop")
                if start is None and stop is None:
                    continue
                out.append(Usage(
                    device=device,
                    app=_readable_app(sub),
                    in_use=(stop == 0),
                    last_start=_ft_to_unix(start or 0),
                    last_stop=_ft_to_unix(stop or 0),
                ))
        finally:
            winreg.CloseKey(k)

    scan(base)
    return out


def _read_val(hive, path: str, name: str):
    try:
        k = winreg.OpenKey(hive, path)
    except OSError:
        return None
    try:
        val, _ = winreg.QueryValueEx(k, name)
        return int(val)
    except OSError:
        return None
    finally:
        winreg.CloseKey(k)


def snapshot() -> list[Usage]:
    """All mic/cam usage records across HKCU + HKLM. Empty on non-Windows."""
    if not _WIN:
        return []
    out: list[Usage] = []
    for hive in (winreg.HKEY_CURRENT_USER, winreg.HKEY_LOCAL_MACHINE):
        for dev in _DEVICES:
            out.extend(_read_hive(hive, dev))
    # de-dupe on (device, app), preferring an in-use record
    best: dict[tuple, Usage] = {}
    for u in out:
        if u.key() not in best or (u.in_use and not best[u.key()].in_use):
            best[u.key()] = u
    return list(best.values())


def in_use_now(records: list[Usage] | None = None) -> list[Usage]:
    """Just the apps CURRENTLY accessing the mic or camera."""
    return [u for u in (records if records is not None else snapshot()) if u.in_use]


def diff_new_access(previous: list[Usage], current: list[Usage]) -> list[Usage]:
    """Apps that STARTED using a device since the previous snapshot (the alert trigger).

    Pure function (unit-testable): an app counts as newly-active if it is in-use now and was
    not in-use before.
    """
    was_active = {u.key() for u in previous if u.in_use}
    return [u for u in current if u.in_use and u.key() not in was_active]
