#!/usr/bin/env python3
"""
Internet-exposure self-check — "is anything on my network reachable from the outside?"

The scariest question for a home network isn't what's open on the LAN — it's what's open to
the whole INTERNET. A camera whose DVRIP/RTSP port is forwarded out is exactly how strangers
end up watching people's homes (and how sites like Shodan/Insecam index them).

This answers it two ways, locally and safely:

  1. Your public IP (so you know your own edge address).
  2. Your router's UPnP port-forward table — the set of internal ports it has automatically
     opened to the internet. We query the router's IGD exactly the way a game console or the
     XMEye app does (SSDP discover -> read the device description -> GetGenericPortMappingEntry).
     Anything forwarded is flagged; a forward hitting the camera's DVRIP/RTSP/HTTP is CRITICAL.

If UPnP is disabled (which the hardening report recommends), there's nothing to enumerate —
that's the SECURE result, reported as such. This never port-scans anyone; it reads your own
router's forwarding table and your own public IP. Zero attack, zero third-party.
"""
from __future__ import annotations

import re
import socket
import urllib.request
from dataclasses import dataclass, field

_SSDP_ADDR = ("239.255.255.250", 1900)
_IGD_TARGETS = (
    "urn:schemas-upnp-org:device:InternetGatewayDevice:1",
    "urn:schemas-upnp-org:service:WANIPConnection:1",
    "upnp:rootdevice",
)
# Forwarded ports that map to these are the worst case (camera / remote admin).
_CRITICAL_FWD = {34567: "camera DVRIP", 554: "camera RTSP", 23: "Telnet", 5555: "ADB", 3389: "RDP"}


@dataclass
class Forward:
    ext_port: int
    int_port: int
    int_client: str
    proto: str
    desc: str

    def severity(self) -> int:
        if self.ext_port in _CRITICAL_FWD or self.int_port in _CRITICAL_FWD:
            return 4
        return 3   # any internet-facing forward is high by default

    def note(self) -> str:
        tag = _CRITICAL_FWD.get(self.ext_port) or _CRITICAL_FWD.get(self.int_port)
        base = f"{self.proto} {self.ext_port} -> {self.int_client}:{self.int_port} ({self.desc or 'no desc'})"
        return base + (f"  <-- {tag} EXPOSED TO THE INTERNET" if tag else "  (forwarded to the internet)")


@dataclass
class ExposureResult:
    public_ip: str = ""
    upnp_found: bool = False
    forwards: list[Forward] = field(default_factory=list)
    note: str = ""


def public_ip(timeout: float = 5.0) -> str:
    for url in ("https://api.ipify.org", "https://ifconfig.me/ip", "https://icanhazip.com"):
        try:
            with urllib.request.urlopen(url, timeout=timeout) as r:
                ip = r.read().decode().strip()
                if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ip):
                    return ip
        except Exception:
            continue
    return ""


def _ssdp_discover(timeout: float = 3.0) -> str:
    """Return the IGD device-description URL (LOCATION header), or '' if none answers."""
    for target in _IGD_TARGETS:
        msg = ("M-SEARCH * HTTP/1.1\r\n"
               f"HOST: {_SSDP_ADDR[0]}:{_SSDP_ADDR[1]}\r\n"
               'MAN: "ssdp:discover"\r\n'
               "MX: 2\r\n"
               f"ST: {target}\r\n\r\n").encode()
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.settimeout(timeout)
        try:
            s.sendto(msg, _SSDP_ADDR)
            while True:
                data, _ = s.recvfrom(65507)
                m = re.search(rb"location:\s*(\S+)", data, re.I)
                if m:
                    return m.group(1).decode(errors="replace").strip()
        except socket.timeout:
            pass
        except OSError:
            pass
        finally:
            s.close()
    return ""


def _wan_control(desc_url: str):
    """From the IGD description XML, find (control_url, service_type) for WAN connection."""
    try:
        with urllib.request.urlopen(desc_url, timeout=5) as r:
            xml = r.read().decode(errors="replace")
    except Exception:
        return None
    base = re.match(r"(https?://[^/]+)", desc_url)
    base = base.group(1) if base else ""
    # find a WANIPConnection or WANPPPConnection service block and its controlURL
    for svc in re.findall(r"<service>(.*?)</service>", xml, re.S | re.I):
        st = re.search(r"<serviceType>(.*?WANI?P?PP?Connection:\d)</serviceType>", svc, re.I)
        cu = re.search(r"<controlURL>(.*?)</controlURL>", svc, re.I)
        if st and cu:
            ctrl = cu.group(1).strip()
            if not ctrl.startswith("http"):
                ctrl = base + ("" if ctrl.startswith("/") else "/") + ctrl
            return ctrl, st.group(1).strip()
    return None


def _get_mappings(control_url: str, service_type: str, limit: int = 40) -> list[Forward]:
    forwards: list[Forward] = []
    for i in range(limit):
        body = (
            '<?xml version="1.0"?>'
            '<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" '
            's:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/"><s:Body>'
            f'<u:GetGenericPortMappingEntry xmlns:u="{service_type}">'
            f"<NewPortMappingIndex>{i}</NewPortMappingIndex>"
            "</u:GetGenericPortMappingEntry></s:Body></s:Envelope>"
        )
        req = urllib.request.Request(
            control_url, data=body.encode(),
            headers={"Content-Type": 'text/xml; charset="utf-8"',
                     "SOAPAction": f'"{service_type}#GetGenericPortMappingEntry"'})
        try:
            with urllib.request.urlopen(req, timeout=5) as r:
                xml = r.read().decode(errors="replace")
        except Exception:
            break   # index past the end returns a SOAP fault -> we're done
        def g(tag):
            m = re.search(rf"<{tag}>(.*?)</{tag}>", xml, re.I)
            return m.group(1).strip() if m else ""
        ext = g("NewExternalPort")
        if not ext:
            break
        forwards.append(Forward(
            ext_port=int(ext or 0), int_port=int(g("NewInternalPort") or 0),
            int_client=g("NewInternalClient"), proto=g("NewProtocol"),
            desc=g("NewPortMappingDescription")))
    return forwards


def check() -> ExposureResult:
    res = ExposureResult()
    res.public_ip = public_ip()
    desc = _ssdp_discover()
    if not desc:
        res.note = ("No UPnP internet-gateway responded. If you disabled UPnP, that's the SECURE "
                    "result (nothing auto-forwarded). Otherwise check port-forwards in the router UI.")
        return res
    res.upnp_found = True
    wan = _wan_control(desc)
    if not wan:
        res.note = "UPnP gateway found but its WAN connection service could not be read."
        return res
    res.forwards = _get_mappings(*wan)
    if not res.forwards:
        res.note = "UPnP is reachable but no ports are currently forwarded to the internet (good)."
    else:
        res.note = f"{len(res.forwards)} port-forward(s) exposing internal services to the internet."
    return res
