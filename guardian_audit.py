#!/usr/bin/env python3
"""Guardian audit — run the IoT exposure auditor and write a readable hardening report.

  python guardian_audit.py            # ARP-cache pass (fast, fully passive)
  python guardian_audit.py --sweep    # + light /24 sweep to wake idle IoT (TVs, vacuums, Alexas)

Light-touch, own-network, out-of-band from gaming. Writes JSON + a plain-text report to reports/.
"""
from __future__ import annotations

import argparse
import json
import os
from datetime import datetime

from modules import exposure_audit as ea
from modules import internet_exposure as ie

_SEV = {4: "CRITICAL", 3: "HIGH", 2: "MEDIUM", 1: "LOW", 0: "none"}


def to_text(rep: dict) -> str:
    s = rep["summary"]
    lines = [
        "HOME GUARDIAN — NETWORK EXPOSURE REPORT",
        datetime.now().strftime("%Y-%m-%d %H:%M"),
        "=" * 64,
        f"Devices seen: {s['devices_seen']}   High-risk devices: {s['high_risk_devices']}",
        "",
        "DEVICES (worst first):",
    ]
    for d in rep["devices"]:
        lines.append(f"  {d['ip']:<15} {(d['vendor'] or '?'):<16} {d['type']:<26} [{_SEV[d['max_severity']]}]")
        for f in d["exposures"]:
            lines.append(f"      - port {f['port']} {f['label']} [{_SEV[f['severity']]}]")
            lines.append(f"          fix: {f['remedy']}")
    exp = rep.get("internet_exposure")
    if exp:
        lines += ["", "INTERNET EXPOSURE (reachable from outside your home):"]
        lines.append(f"  Public IP: {exp['public_ip'] or 'unknown'}")
        if exp["forwards"]:
            for f in exp["forwards"]:
                lines.append(f"  - [{_SEV[f['severity']]}] {f['note']}")
        lines.append(f"  {exp['note']}")
    lines += ["", "NETWORK-WIDE HARDENING (do these first):"]
    lines += [f"  {i+1}. {r}" for i, r in enumerate(rep["network_hardening"])]
    lines += ["", "COVERAGE: " + rep["coverage_note"], "", rep["disclaimer"]]
    return "\n".join(lines)


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description="Home Guardian network exposure audit.")
    p.add_argument("--sweep", action="store_true", help="light /24 sweep to include idle IoT")
    a = p.parse_args(argv)

    devices = ea.scan(timeout=0.5, sweep=a.sweep)
    rep = ea.build_report(devices, probed=True)
    # internet-exposure self-check (public IP + UPnP port-forwards)
    exp = ie.check()
    rep["internet_exposure"] = {
        "public_ip": exp.public_ip,
        "upnp_found": exp.upnp_found,
        "note": exp.note,
        "forwards": [{"severity": f.severity(), "note": f.note(),
                      "ext_port": f.ext_port, "int_client": f.int_client} for f in exp.forwards],
    }

    out_dir = os.path.join(os.path.dirname(__file__), "reports")
    os.makedirs(out_dir, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    with open(os.path.join(out_dir, f"exposure_{stamp}.json"), "w", encoding="utf-8") as f:
        json.dump(rep, f, indent=2)
    text = to_text(rep)
    with open(os.path.join(out_dir, f"exposure_{stamp}.txt"), "w", encoding="utf-8") as f:
        f.write(text)
    print(text)
    print(f"\n[saved to reports/exposure_{stamp}.txt]")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
