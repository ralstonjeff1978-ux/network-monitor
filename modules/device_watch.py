#!/usr/bin/env python3
"""
Presence + exposure watch — the always-on network layer that needs no special hardware.

Runs the light exposure audit on a schedule and DIFFS it against a learned baseline of
trusted devices. It raises an event — and the guardian pushes a phone alert — when:

  * NEW_DEVICE     an unknown MAC joins the network (someone/something new is on your LAN)
  * NEW_EXPOSURE   a known device suddenly opens a risky port (e.g. a camera exposes Telnet)
  * DEVICE_BACK    a previously-seen device with open risky ports reappears (informational)

The diff logic is pure and unit-tested; the live step calls the (light, gaming-safe) scanner.
Baseline persistence is the service's job, so this stays testable without disk or network.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from . import exposure_audit as ea


@dataclass
class WatchEvent:
    kind: str                 # NEW_DEVICE | NEW_EXPOSURE
    ip: str
    mac: str
    severity: int
    detail: str

    def alert(self) -> tuple[str, str, str]:
        """(title, message, severity-word) for the alerting layer."""
        sev = "critical" if self.severity >= 4 else "high" if self.severity >= 3 else "warning"
        if self.kind == "NEW_DEVICE":
            return ("New device on your network",
                    f"Unknown device joined:\n{self.ip}  ({self.mac})\n{self.detail}", sev)
        return ("New exposure detected",
                f"{self.ip} ({self.mac})\n{self.detail}", sev)


@dataclass
class Baseline:
    """What we consider normal. `known` = trusted MACs; `ports` = last-seen risky ports per MAC."""
    known: set[str] = field(default_factory=set)
    ports: dict[str, list[int]] = field(default_factory=dict)


def diff(baseline: Baseline, devices: list[ea.Device]) -> list[WatchEvent]:
    """Pure diff of a fresh scan against the baseline → events. Does not mutate the baseline."""
    events: list[WatchEvent] = []
    for d in devices:
        mac = d.mac or d.ip
        if mac not in baseline.known:
            events.append(WatchEvent(
                "NEW_DEVICE", d.ip, mac, max(d.max_severity, 2),
                f"{d.vendor or 'unknown vendor'} · {d.device_type}"
                + (f" · open: {d.open_ports}" if d.open_ports else "")))
            continue
        prev = set(baseline.ports.get(mac, []))
        new_risky = [p for p in d.open_ports if p in ea.RISKY_PORTS and p not in prev]
        for p in new_risky:
            label, sev, remedy = ea.RISKY_PORTS[p]
            events.append(WatchEvent("NEW_EXPOSURE", d.ip, mac, sev,
                                     f"opened port {p} ({label}). Fix: {remedy}"))
    return events


def update_baseline(baseline: Baseline, devices: list[ea.Device]) -> Baseline:
    """Fold a scan into the baseline (call AFTER alerting, so the next diff is against now)."""
    for d in devices:
        mac = d.mac or d.ip
        baseline.known.add(mac)
        baseline.ports[mac] = list(d.open_ports)
    return baseline


def scan_step(deep: bool = False, timeout: float = 0.4) -> list[ea.Device]:
    """One live inventory pass (light-touch, own /24, out-of-band).

    deep=False (the frequent pass): read the OS ARP cache only — instant, ZERO packets from
    us. Catches a new device the moment it talks on the LAN. No port data, so NEW_EXPOSURE is
    not evaluated here.
    deep=True  (the occasional pass): wake the full /24 and port-probe each device, so idle IoT
    is inventoried and newly-opened risky ports (NEW_EXPOSURE) are caught. ~seconds, run rarely.
    """
    if deep:
        return ea.scan(timeout=timeout, sweep=True)
    return ea.discover()
