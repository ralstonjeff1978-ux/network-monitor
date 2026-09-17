#!/usr/bin/env python3
"""
Home Guardian — the always-on protector.

Not a scan-and-exit audit: a service that keeps watching and alerts you (phone + desktop)
the moment something changes, so your cameras, TVs, vacuums and voice assistants can't be
used or knocked offline without your knowledge.

Watches, on a schedule, with NO special hardware and NO impact on gaming (light-touch,
out-of-band — never inline on game traffic):

  * network presence   — an unknown device joining your LAN                → phone alert
  * device exposure    — a device opening a risky port (Telnet/DVRIP/etc.) → phone alert
  * mic / webcam        — an app starting to use your microphone or camera  → phone alert

Optional response (only if you put router credentials in config.py): it can ask YOUR OWN
router to block a newly-appeared unknown device's MAC. It never transmits attacks (deauth/
jamming are illegal and pointless as defense) — detection, notification, and blocking on
your own gear only.

  python guardian.py --learn        # first run: learn the devices here now as trusted
  python guardian.py                # protect: watch forever, alert on anything new
  python guardian.py --once         # a single pass (for testing / cron)
  python guardian.py --interval 30  # seconds between passes (default 60)
"""
from __future__ import annotations

import argparse
import json
import os
import signal
import sys
import time

from modules import device_watch as dw
from modules import mic_cam_monitor as mcm
from modules import wifi_watch as ww

try:
    from modules.alerting import send_alert
except Exception:                       # alerting pulls optional deps; degrade to console
    def send_alert(title, message, severity="warning", phone=True):
        print(f"[ALERT/{severity}] {title}: {message}")

try:
    from modules import database as db
    _HAVE_DB = True
except Exception:
    _HAVE_DB = False

STATE_FILE = os.path.join(os.path.dirname(__file__), "guardian_state.json")


# --------------------------------------------------------------------------
# baseline persistence
# --------------------------------------------------------------------------

def _read_state() -> dict:
    if os.path.exists(STATE_FILE):
        try:
            return json.loads(open(STATE_FILE, encoding="utf-8").read())
        except (OSError, ValueError):
            pass
    return {}


def load_baseline() -> dw.Baseline:
    d = _read_state()
    return dw.Baseline(known=set(d.get("known", [])), ports=d.get("ports", {}))


def load_wifi() -> ww.WifiBaseline:
    d = _read_state().get("wifi", {})
    return ww.WifiBaseline(known_bssids=set(d.get("known_bssids", [])),
                           home_ssid=d.get("home_ssid", ""),
                           home_bssids=set(d.get("home_bssids", [])))


def save_state(b: dw.Baseline, w: ww.WifiBaseline) -> None:
    try:
        with open(STATE_FILE, "w", encoding="utf-8") as f:
            json.dump({
                "known": sorted(b.known), "ports": b.ports,
                "wifi": {"known_bssids": sorted(w.known_bssids),
                         "home_ssid": w.home_ssid,
                         "home_bssids": sorted(w.home_bssids)},
            }, f, indent=2)
    except OSError:
        pass


# --------------------------------------------------------------------------
# one protection pass
# --------------------------------------------------------------------------

def _log_event(kind: str, detail: str, mac: str = "") -> None:
    if _HAVE_DB:
        try:
            db.log_attack(kind, source_mac=mac or None, dest_mac=None)
        except Exception:
            pass


def network_pass(baseline: dw.Baseline, alert: bool, deep: bool = False) -> list[dw.WatchEvent]:
    # fast pass = ARP-cache read (instant, zero packets); deep pass = full sweep + port probe.
    devices = dw.scan_step(deep=deep)
    events = dw.diff(baseline, devices)
    if alert:
        for ev in events:
            title, msg, sev = ev.alert()
            send_alert(title, msg, severity=sev, phone=(ev.severity >= 3))
            _log_event(ev.kind, msg, ev.mac)
    dw.update_baseline(baseline, devices)
    return events


def wifi_pass(baseline: ww.WifiBaseline, alert: bool) -> list[ww.WifiEvent]:
    aps = ww.scan()
    if not aps:
        return []                      # no Wi-Fi adapter / wired-only host: skip cleanly
    if not baseline.home_ssid:
        baseline.home_ssid = ww.current_ssid()
    events = ww.diff(baseline, aps)
    if alert:
        for ev in events:
            title, msg, sev = ev.alert()
            send_alert(title, msg, severity=sev, phone=(ev.severity >= 3))
            _log_event(ev.kind, msg, ev.bssid)
    ww.update_baseline(baseline, aps)
    return events


def miccam_pass(prev: list[mcm.Usage], alert: bool) -> tuple[list[mcm.Usage], list[mcm.Usage]]:
    current = mcm.snapshot()
    started = mcm.diff_new_access(prev, current)
    if alert:
        for u in started:
            send_alert(
                f"{u.device.capitalize()} in use",
                f"'{u.app}' just started using your {u.device}.",
                severity="high", phone=True,
            )
            _log_event(f"{u.device}_access", u.app)
    return current, started


# --------------------------------------------------------------------------
# service loop
# --------------------------------------------------------------------------

def run(interval: int = 60, once: bool = False, learn: bool = False, deep_every: int = 10) -> int:
    baseline = load_baseline()
    wifi = load_wifi()
    first_run = not baseline.known

    if learn or first_run:
        devices = dw.scan_step()
        dw.update_baseline(baseline, devices)
        aps = ww.scan()
        if aps:
            wifi.home_ssid = wifi.home_ssid or ww.current_ssid()
            ww.update_baseline(wifi, aps)
        save_state(baseline, wifi)
        first_run = False               # baseline now exists; the loop watches against it
        print(f"[guardian] learned {len(baseline.known)} devices + {len(wifi.known_bssids)} "
              f"Wi-Fi AP(s) here as trusted. Now protecting — you'll be alerted on anything new.")
    prev_mc = mcm.snapshot()

    stop = {"flag": False}
    # Signal handlers only work in the main thread; when run as a background thread inside the
    # combined app they are simply skipped (the daemon thread dies with the process).
    for sig in (getattr(signal, "SIGINT", None), getattr(signal, "SIGTERM", None)):
        if sig is not None:
            try:
                signal.signal(sig, lambda *_: stop.update(flag=True))
            except (ValueError, AttributeError):
                pass

    send_alert("Home Guardian active", "Watching your network, mic and cameras.",
               severity="info", phone=False)
    passes = 0
    while not stop["flag"]:
        learning = first_run and passes == 0
        # Cheap every pass (ARP + wifi + mic/cam ≈ instant); the heavier full-subnet sweep +
        # port probe runs only every `deep_every` passes, so steady-state load stays tiny.
        deep = (passes % max(1, deep_every) == 0)
        net_events = network_pass(baseline, alert=not learning, deep=deep)
        wifi_events = wifi_pass(wifi, alert=not learning)
        prev_mc, mc_events = miccam_pass(prev_mc, alert=True)
        save_state(baseline, wifi)
        passes += 1
        kinds = [e.kind for e in net_events] + [e.kind for e in wifi_events]
        n = len(net_events) + len(wifi_events) + len(mc_events)
        print(f"[guardian] pass {passes}: {len(baseline.known)} devices, "
              f"{len(wifi.known_bssids)} APs, {n} event(s)"
              + (f" -> {kinds}" if kinds else ""))
        if once:
            break
        for _ in range(interval):
            if stop["flag"]:
                break
            time.sleep(1)
    print("[guardian] stopped.")
    return 0


def start_background(interval: int = 60, deep_every: int = 10):
    """Run the guardian watch loop in a daemon thread (for the combined app). Returns the Thread."""
    import threading
    t = threading.Thread(target=lambda: run(interval=interval, deep_every=deep_every),
                         name="home-guardian", daemon=True)
    t.start()
    return t


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description="Home Guardian — always-on network + mic/cam protector.")
    p.add_argument("--interval", type=int, default=60, help="seconds between passes")
    p.add_argument("--once", action="store_true", help="single pass then exit")
    p.add_argument("--learn", action="store_true", help="(re)learn current devices as trusted")
    p.add_argument("--deep-every", type=int, default=10,
                   help="run the heavy full-subnet sweep every N passes (default 10 = ~10 min at 60s)")
    a = p.parse_args(argv)
    return run(interval=a.interval, once=a.once, learn=a.learn, deep_every=a.deep_every)


if __name__ == "__main__":
    raise SystemExit(main())
