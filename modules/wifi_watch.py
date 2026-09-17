#!/usr/bin/env python3
"""
Wi-Fi environment watch — catch an ESP32 deauther / rogue AP without monitor-mode hardware.

The visiting red-teamer's device was "an ESP32 or some such" — i.e. a Spacehuhn-style ESP
deauther. Two of its behaviours are visible to an ORDINARY Windows adapter via
`netsh wlan show networks mode=bssid` (no monitor mode, no drivers, purely a scan):

  * it usually hosts its own config AP / sprays beacon frames → a NEW access point appears,
    often with an **Espressif BSSID** (its real MAC) or a burst of junk SSIDs (beacon spam);
  * an **evil-twin** attack rebroadcasts YOUR SSID from a different BSSID to lure devices.

This module scans the air, fingerprints every AP, and — diffed against a learned baseline of
the normal RF environment (tiny at a remote location) — flags:

  ROGUE_ESP     an AP whose BSSID is an Espressif OUI  (likely the deauther itself)
  EVIL_TWIN     your own SSID broadcast from an unknown BSSID  (CRITICAL)
  NEW_AP        an access point that wasn't here before
  BEACON_SPAM   an abnormal surge in visible SSIDs  (deauther beacon-spam signature)

The deauth FRAMES themselves still need monitor mode / an ESP32 sensor; detecting the
attacker's AP presence does not. Passive scan → zero impact on gaming.
"""
from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass, field

try:
    from .esp32_detector import ESP32Detector
    _ESP = ESP32Detector()
except Exception:
    _ESP = None

# Espressif OUI prefixes (fallback if esp32_detector isn't importable).
_ESP_PREFIXES = ("18:fe:34", "24:0a:c4", "2c:3a:e8", "30:ae:a4", "3c:71:bf", "54:5a:a6",
                 "5c:cf:7f", "60:01:94", "68:c6:3a", "84:0d:8e", "90:97:d5", "a4:7b:9d",
                 "ac:d0:74", "b4:e6:2d", "c4:4f:33", "cc:50:e3", "dc:4f:22", "a4:cf:12")

_BEACON_SPAM_THRESHOLD = 12   # this many NEW SSIDs at once = likely beacon spam


@dataclass
class AP:
    ssid: str
    bssid: str
    auth: str = ""
    signal: str = ""
    channel: str = ""
    band: str = ""
    radio: str = ""


@dataclass
class WifiEvent:
    kind: str            # ROGUE_ESP | EVIL_TWIN | NEW_AP | BEACON_SPAM
    ssid: str
    bssid: str
    severity: int
    detail: str

    def alert(self) -> tuple[str, str, str]:
        sev = "critical" if self.severity >= 4 else "high" if self.severity >= 3 else "warning"
        titles = {
            "ROGUE_ESP": "ESP-based Wi-Fi device nearby",
            "EVIL_TWIN": "EVIL TWIN of your Wi-Fi detected",
            "NEW_AP": "New Wi-Fi access point nearby",
            "BEACON_SPAM": "Wi-Fi beacon spam (deauther signature)",
        }
        return (titles.get(self.kind, self.kind),
                f"{self.ssid or '(hidden)'}  [{self.bssid}]\n{self.detail}", sev)


def is_espressif(bssid: str) -> bool:
    b = bssid.lower().replace("-", ":")
    if _ESP is not None:
        try:
            if _ESP.is_esp32_device(b):
                return True
        except Exception:
            pass
    return b[:8] in _ESP_PREFIXES


def parse_netsh(text: str) -> list[AP]:
    """Parse `netsh wlan show networks mode=bssid` output into AP records (pure, testable)."""
    aps: list[AP] = []
    ssid = auth = ""
    cur: AP | None = None
    for raw in text.splitlines():
        line = raw.strip()
        m = re.match(r"SSID \d+\s*:\s*(.*)$", line)
        if m:
            ssid = m.group(1).strip()
            continue
        if line.startswith("Authentication"):
            auth = line.split(":", 1)[1].strip()
            continue
        m = re.match(r"BSSID \d+\s*:\s*([0-9a-fA-F:]{17})", line)
        if m:
            cur = AP(ssid=ssid, bssid=m.group(1).lower(), auth=auth)
            aps.append(cur)
            continue
        if cur is not None and ":" in line:
            field_name = line.split(":", 1)[0].strip()   # exact name → no "Channel Utilization" collision
            for key, attr in (("Signal", "signal"), ("Channel", "channel"),
                              ("Band", "band"), ("Radio type", "radio")):
                if field_name == key:
                    setattr(cur, attr, line.split(":", 1)[1].strip())
    return aps


@dataclass
class WifiBaseline:
    known_bssids: set[str] = field(default_factory=set)
    home_ssid: str = ""
    home_bssids: set[str] = field(default_factory=set)   # BSSIDs legitimately serving home SSID


def diff(baseline: WifiBaseline, aps: list[AP]) -> list[WifiEvent]:
    """Pure diff of a scan vs the baseline → Wi-Fi threat events."""
    events: list[WifiEvent] = []
    new_bssids = [a for a in aps if a.bssid not in baseline.known_bssids]

    if len(new_bssids) >= _BEACON_SPAM_THRESHOLD:
        events.append(WifiEvent("BEACON_SPAM", "", "", 3,
                                f"{len(new_bssids)} new SSIDs appeared at once — likely beacon spam."))

    for a in aps:
        # evil twin: our SSID from a BSSID we haven't sanctioned
        if baseline.home_ssid and a.ssid == baseline.home_ssid and a.bssid not in baseline.home_bssids:
            events.append(WifiEvent("EVIL_TWIN", a.ssid, a.bssid, 4,
                                    f"Your network name is being broadcast from an UNKNOWN radio "
                                    f"({a.auth or 'open?'}). Do not connect; this can steal your Wi-Fi password."))
            continue
        if a.bssid in baseline.known_bssids:
            continue
        if is_espressif(a.bssid):
            events.append(WifiEvent("ROGUE_ESP", a.ssid, a.bssid, 4,
                                    "Access point with an Espressif (ESP32/ESP8266) radio — the hardware "
                                    "DIY Wi-Fi deauthers are built from. Investigate."))
        else:
            events.append(WifiEvent("NEW_AP", a.ssid, a.bssid, 2,
                                    f"New AP ({a.auth or 'unknown auth'}, {a.band} {a.radio}). "
                                    "Normal if a neighbour/new device; note it if unexpected."))
    return events


def update_baseline(baseline: WifiBaseline, aps: list[AP]) -> WifiBaseline:
    for a in aps:
        baseline.known_bssids.add(a.bssid)
        if baseline.home_ssid and a.ssid == baseline.home_ssid:
            baseline.home_bssids.add(a.bssid)
    return baseline


# --------------------------------------------------------------------------
# live scan (Windows, no monitor mode)
# --------------------------------------------------------------------------

def current_ssid() -> str:
    try:
        out = subprocess.run(["netsh", "wlan", "show", "interfaces"],
                             capture_output=True, text=True, timeout=8).stdout
    except Exception:
        return ""
    for line in out.splitlines():
        s = line.strip()
        if s.startswith("SSID") and "BSSID" not in s:
            return s.split(":", 1)[1].strip()
    return ""


def scan() -> list[AP]:
    try:
        out = subprocess.run(["netsh", "wlan", "show", "networks", "mode=bssid"],
                             capture_output=True, text=True, timeout=12).stdout
    except Exception:
        return []
    return parse_netsh(out)


def home_is_pmf_hardened(aps: list[AP], home_ssid: str) -> bool | None:
    """Best-effort: is the home network WPA3 (deauth-resistant)? None if unknown.

    netsh doesn't expose 802.11w PMF directly, but WPA3 implies PMF. WPA2 is the flag to raise.
    """
    for a in aps:
        if a.ssid == home_ssid and a.auth:
            return "WPA3" in a.auth.upper()
    return None
