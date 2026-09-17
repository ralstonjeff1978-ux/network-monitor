#!/usr/bin/env python3
"""
IoT exposure auditor — inventory the home network and report what's attackable.

Motivation: a visiting red-teamer claimed he could get in "in a couple hours and bring
devices down." This module answers that with a concrete attack-surface picture: it finds
every device (cameras, TVs, robot vacuums, voice assistants, phones, PCs, the router),
identifies each, checks which risky services are exposed, and produces a PRIORITIZED
hardening plan with specific remedies.

Design constraints (from the project):
  * PASSIVE-FIRST / LIGHT-TOUCH. Discovery reads the OS ARP cache (already-known devices);
    the optional port check is a short-timeout TCP connect to a small, curated set of
    risky ports on the OWNER'S OWN subnet only. No floods, no aggressive scanning — so it
    never adds latency or jitter to gaming traffic. It is a handful of SYNs, out-of-band.
  * NEVER "clean." The report states what was checked and what it could not see (the
    Cypher Scope rule): unreachable hosts, UDP services not probed, firmware it can't inspect.
  * DEFENSIVE ONLY. It identifies and recommends; it never attacks or exploits.

The pure logic (vendor lookup, device classification, port→remedy mapping, ARP parsing) is
unit-tested without a network; the live scan is a separate, explicit call.
"""
from __future__ import annotations

import concurrent.futures
import re
import socket
import subprocess
from dataclasses import dataclass, field

# --- OUI → vendor (first 3 MAC octets). Small, extendable; the classes that matter for a
# home IoT audit. Lowercase, colon-joined. ---
OUI_VENDORS: dict[str, str] = {
    "18:fe:34": "Espressif (ESP)", "24:0a:c4": "Espressif (ESP)", "3c:71:bf": "Espressif (ESP)",
    "68:c6:3a": "Espressif (ESP)", "dc:4f:22": "Espressif (ESP)", "a4:cf:12": "Espressif (ESP)",
    "fc:a1:83": "Amazon", "44:65:0d": "Amazon", "68:37:e9": "Amazon", "f0:27:2d": "Amazon",
    "50:dc:e7": "Amazon", "ac:63:be": "Amazon (Echo)", "40:b4:cd": "Amazon (Echo)",
    "f4:f5:d8": "Google", "d8:6c:63": "Google", "1c:f2:9a": "Google", "e4:f0:42": "Google (Nest)",
    "b0:2a:43": "Roku", "cc:6d:a0": "Roku", "dc:3a:5e": "Roku", "d0:4d:2c": "Roku",
    "8c:79:f5": "Samsung", "5c:49:7d": "Samsung", "e8:50:8b": "Samsung", "c0:97:27": "Samsung",
    "10:2b:41": "LG", "a8:23:fe": "LG", "cc:2d:8c": "LG",
    "50:ec:50": "Xiaomi/Roborock", "78:11:dc": "Xiaomi", "64:09:80": "Xiaomi", "28:6c:07": "Xiaomi",
    "b0:4a:39": "Roborock", "dd:a8:3f": "Roborock",
    "00:12:fb": "Hikvision", "44:19:b6": "Hikvision", "bc:ad:28": "Hikvision",
    "00:1a:3f": "Dahua/Xiongmai", "3c:ef:8c": "Xiongmai", "00:12:16": "Xiongmai",
    "b0:c5:54": "Reolink", "ec:71:db": "Reolink", "9c:8e:cd": "Wyze", "2c:aa:8e": "Wyze",
    "b8:27:eb": "Raspberry Pi", "dc:a6:32": "Raspberry Pi", "e4:5f:01": "Raspberry Pi",
    "50:c7:bf": "TP-Link", "ac:84:c6": "TP-Link", "c0:06:c3": "TP-Link",
    "d4:3b:04": "Ring/Amazon", "34:3e:a4": "Ring",
}

# --- risky exposed services → (label, severity 1-4, remedy) ---
RISKY_PORTS: dict[int, tuple[str, int, str]] = {
    23:   ("Telnet (cleartext admin)", 4, "Disable Telnet entirely; it sends credentials in the clear."),
    2323: ("Telnet (alt)", 4, "Disable Telnet; this alt port is a common IoT-botnet target."),
    22:   ("SSH", 2, "Fine if intended; use a key, not a password, and a non-default login."),
    21:   ("FTP (cleartext)", 3, "Disable FTP or replace with SFTP; FTP leaks credentials."),
    554:  ("RTSP video stream", 3, "Require a strong RTSP password; do not port-forward it to the internet."),
    34567:("DVRIP camera control", 4, "Set a strong admin password; disable cloud/P2P; put the camera on an isolated IoT VLAN."),
    80:   ("HTTP admin page", 2, "Change default credentials; prefer HTTPS; never expose to the internet."),
    8080: ("HTTP admin (alt)", 2, "Change default credentials; restrict to the LAN."),
    8000: ("HTTP admin (alt)", 2, "Change default credentials; restrict to the LAN."),
    443:  ("HTTPS admin page", 1, "Expected on many devices; ensure default credentials were changed."),
    1900: ("UPnP (SSDP)", 3, "Disable UPnP on the router; it lets devices punch firewall holes automatically."),
    5555: ("Android Debug Bridge", 4, "Disable ADB-over-network; it is remote code execution if reachable."),
    9000: ("HTTP service", 2, "Identify the service; restrict to the LAN and set credentials."),
    445:  ("SMB file sharing", 3, "Disable if unused; never expose SMB beyond the LAN."),
    7547: ("TR-069 remote mgmt", 3, "Disable ISP remote management (TR-069) if you don't need it; historic mass-exploit target."),
}

# --- device classification signatures: (vendor substrings, open ports, hostname regex) → type ---
_HOSTNAME_HINTS = [
    (re.compile(r"echo|alexa|amazon", re.I), "Voice assistant (Amazon Echo)"),
    (re.compile(r"google|nest|home", re.I), "Voice assistant / Nest"),
    (re.compile(r"roku|tv|samsung|lg|bravia|vizio", re.I), "Smart TV / streamer"),
    (re.compile(r"roborock|vacuum|xiaomi|robot", re.I), "Robot vacuum"),
    (re.compile(r"cam|ipc|dvr|nvr|hikvision|dahua|reolink|wyze|ring", re.I), "IP camera / NVR"),
    (re.compile(r"router|gateway|openwrt|asus|netgear|tplink|orbi", re.I), "Router / gateway"),
    (re.compile(r"iphone|android|galaxy|pixel|phone", re.I), "Phone"),
    (re.compile(r"desktop|pc|win|laptop|macbook", re.I), "Computer"),
]


@dataclass
class Device:
    ip: str
    mac: str = ""
    vendor: str = ""
    hostname: str = ""
    open_ports: list[int] = field(default_factory=list)
    device_type: str = "unknown"
    findings: list[dict] = field(default_factory=list)   # {port,label,severity,remedy}

    @property
    def max_severity(self) -> int:
        return max((f["severity"] for f in self.findings), default=0)


def vendor_for_mac(mac: str) -> str:
    """Vendor for a MAC. The curated map wins (friendly device-class labels like
    'Amazon (Echo)'); otherwise fall back to the full IEEE OUI registry for an exact name."""
    prefix = mac.lower().replace("-", ":")[:8]
    if prefix in OUI_VENDORS:
        return OUI_VENDORS[prefix]
    try:
        from . import oui
        return oui.lookup(mac)
    except Exception:
        return ""


def classify(vendor: str, hostname: str, open_ports: list[int]) -> str:
    v, h = (vendor or "").lower(), hostname or ""
    for rx, label in _HOSTNAME_HINTS:
        if rx.search(h) or rx.search(v):
            return label
    if 34567 in open_ports or 554 in open_ports:
        return "IP camera / NVR"
    if "espressif" in v:
        return "ESP / DIY IoT (verify — also used by deauthers)"
    if "amazon" in v:
        return "Voice assistant (Amazon Echo)"
    if "roku" in v or "samsung" in v or "lg" in v:
        return "Smart TV / streamer"
    if "roborock" in v or "xiaomi" in v:
        return "Robot vacuum / Xiaomi IoT"
    if any(x in v for x in ("hikvision", "dahua", "xiongmai", "reolink", "wyze", "ring")):
        return "IP camera / NVR"
    if "tp-link" in v or "netgear" in v or "asus" in v:
        return "Router / networking"
    return "unknown"


def parse_arp_table(text: str) -> list[tuple[str, str]]:
    """Parse `arp -a` output (Windows/Unix) into (ip, mac) pairs. Passive: no traffic sent."""
    out = []
    ip_re = re.compile(r"(\d{1,3}(?:\.\d{1,3}){3})")
    mac_re = re.compile(r"([0-9a-fA-F]{2}(?:[:-][0-9a-fA-F]{2}){5})")
    for line in text.splitlines():
        ip_m, mac_m = ip_re.search(line), mac_re.search(line)
        if ip_m and mac_m:
            mac = mac_m.group(1).lower().replace("-", ":")
            if mac not in ("ff:ff:ff:ff:ff:ff",) and not mac.startswith("01:00:5e"):
                out.append((ip_m.group(1), mac))
    return out


def audit_ports(device: Device) -> None:
    """Turn a device's open ports into severity-rated findings with remedies."""
    device.findings = []
    for port in device.open_ports:
        if port in RISKY_PORTS:
            label, sev, remedy = RISKY_PORTS[port]
            device.findings.append({"port": port, "label": label, "severity": sev, "remedy": remedy})
    device.findings.sort(key=lambda f: -f["severity"])


# --------------------------------------------------------------------------
# live (light-touch) discovery + probe — his own /24, out-of-band
# --------------------------------------------------------------------------

def sweep_subnet(base: str | None = None, timeout: float = 0.3, max_workers: int = 64) -> None:
    """Light ARP-populating sweep so ASLEEP IoT devices show up (TVs, vacuums, Alexas).

    One short TCP-connect per host on a commonly-open port; the OS records the MAC in its ARP
    cache whether or not the port answers. This is a single SYN per host, parallel and
    short-timeout — light enough to be gaming-safe, and only ever the owner's own /24.
    """
    if base is None:
        try:
            local = socket.gethostbyname(socket.gethostname())
        except OSError:
            return
        base = local.rsplit(".", 1)[0]
    def poke(host: int) -> None:
        _connect(f"{base}.{host}", 80, timeout)   # return value ignored; goal is the ARP entry
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as ex:
        list(ex.map(poke, range(1, 255)))


def discover() -> list[Device]:
    """Devices already in the OS ARP cache. Zero packets from us — purely passive."""
    try:
        text = subprocess.run(["arp", "-a"], capture_output=True, text=True, timeout=10).stdout
    except Exception:
        return []
    devices = []
    for ip, mac in parse_arp_table(text):
        v = vendor_for_mac(mac)
        devices.append(Device(ip=ip, mac=mac, vendor=v))
    return devices


def _connect(ip: str, port: int, timeout: float) -> bool:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            return s.connect_ex((ip, port)) == 0
    except OSError:
        return False


def probe_host(device: Device, ports: list[int] | None = None, timeout: float = 0.4) -> Device:
    """Light TCP-connect check of risky ports on ONE device. Short timeout, own network."""
    ports = ports or list(RISKY_PORTS.keys())
    device.open_ports = [p for p in ports if _connect(device.ip, p, timeout)]
    try:
        device.hostname = socket.getfqdn(device.ip)
        if device.hostname == device.ip:
            device.hostname = ""
    except OSError:
        device.hostname = ""
    device.device_type = classify(device.vendor, device.hostname, device.open_ports)
    audit_ports(device)
    return device


def scan(max_workers: int = 16, timeout: float = 0.4, sweep: bool = False) -> list[Device]:
    """Discover from ARP, then light-probe each device in parallel. Rate-limited, gaming-safe.

    `sweep=True` first wakes the full /24 into the ARP cache so idle IoT (TVs, vacuums, voice
    assistants) is included — the devices this audit most cares about.
    """
    if sweep:
        sweep_subnet()
    devices = discover()
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as ex:
        list(ex.map(lambda d: probe_host(d, timeout=timeout), devices))
    return devices


# --------------------------------------------------------------------------
# reporting
# --------------------------------------------------------------------------

# Network-wide hardening advice that isn't per-device (the structural remedies).
NETWORK_REMEDIES = [
    "Enable WPA3 (or WPA2 with 802.11w PMF *required*) — this neutralizes deauth/'bring-devices-down' floods.",
    "Put IoT (cameras, TVs, vacuums, voice assistants) on a SEPARATE SSID/VLAN or guest network, isolated from the gaming/work PCs.",
    "Disable WPS on the router. For UPnP: a game console auto-forwarding a port for online play is EXPECTED (needed for Open NAT / good Warzone matchmaking) — do NOT blindly kill it. The danger is a CAMERA or IoT device forwarding a port out; check the internet-exposure report and remove only those.",
    "Change every default/shared device password, starting with anything exposing Telnet, DVRIP, or HTTP admin.",
    "Disable ISP remote management (TR-069) and any cloud/P2P feature on cameras you access locally.",
    "Keep the gaming PCs on the trusted VLAN with no inbound exposure; leave their traffic un-inspected so ping is untouched.",
]


def build_report(devices: list[Device], probed: bool) -> dict:
    graded = sorted(devices, key=lambda d: -d.max_severity)
    high = [d for d in graded if d.max_severity >= 3]
    return {
        "summary": {
            "devices_seen": len(devices),
            "devices_probed": sum(1 for d in devices if d.open_ports or probed),
            "high_risk_devices": len(high),
        },
        "coverage_note": (
            "Devices are from the ARP cache; hosts that were idle or off may be missing. "
            "Only TCP risky-ports were probed — UDP services, firmware, and cloud accounts are NOT "
            "assessed. Absence of a finding means 'not detected by this pass', never 'secure'."
        ),
        "devices": [
            {
                "ip": d.ip, "mac": d.mac, "vendor": d.vendor or "unknown",
                "hostname": d.hostname, "type": d.device_type,
                "max_severity": d.max_severity,
                "exposures": d.findings,
            } for d in graded
        ],
        "network_hardening": NETWORK_REMEDIES,
        "disclaimer": "Defensive audit of your own network. Identifies exposure and remedies; performs no attack.",
    }
