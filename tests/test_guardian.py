"""Tests for the always-on guardian: device-watch diff + mic/cam access detection (pure logic)."""
from modules import device_watch as dw
from modules import mic_cam_monitor as mcm
from modules.exposure_audit import Device


def _dev(ip, mac, ports=()):
    d = Device(ip=ip, mac=mac, open_ports=list(ports))
    from modules import exposure_audit as ea
    ea.audit_ports(d)
    return d


def test_new_device_raises_event():
    base = dw.Baseline(known={"aa:aa:aa:aa:aa:aa"})
    devs = [_dev("192.168.0.5", "aa:aa:aa:aa:aa:aa"), _dev("192.168.0.9", "bb:bb:bb:bb:bb:bb")]
    events = dw.diff(base, devs)
    assert len(events) == 1
    assert events[0].kind == "NEW_DEVICE" and events[0].mac == "bb:bb:bb:bb:bb:bb"
    # known device with no new ports -> silent
    assert all(e.mac != "aa:aa:aa:aa:aa:aa" for e in events)


def test_new_exposure_on_known_device():
    mac = "cc:cc:cc:cc:cc:cc"
    base = dw.Baseline(known={mac}, ports={mac: [80]})       # 80 already seen
    devs = [_dev("192.168.0.36", mac, ports=[80, 34567])]     # DVRIP is newly open
    events = dw.diff(base, devs)
    assert len(events) == 1
    assert events[0].kind == "NEW_EXPOSURE" and "34567" in events[0].detail
    assert events[0].severity == 4


def test_update_baseline_makes_next_diff_quiet():
    base = dw.Baseline()
    devs = [_dev("192.168.0.5", "aa:aa:aa:aa:aa:aa", ports=[80])]
    dw.diff(base, devs)                      # first sight would alert
    dw.update_baseline(base, devs)
    assert dw.diff(base, devs) == []         # after learning, no repeat alert


def test_watch_event_alert_formatting():
    ev = dw.WatchEvent("NEW_DEVICE", "192.168.0.9", "bb:bb:bb:bb:bb:bb", 4, "unknown vendor")
    title, msg, sev = ev.alert()
    assert "New device" in title and "192.168.0.9" in msg and sev == "critical"


def test_miccam_new_access_detected():
    prev = [mcm.Usage("microphone", "teams.exe", in_use=False)]
    now = [mcm.Usage("microphone", "teams.exe", in_use=True),
           mcm.Usage("webcam", "zoom.exe", in_use=True)]
    started = mcm.diff_new_access(prev, now)
    keys = {u.key() for u in started}
    assert ("microphone", "teams.exe") in keys      # flipped to in-use
    assert ("webcam", "zoom.exe") in keys           # newly present + in-use
    # something already in use before is NOT re-alerted
    assert mcm.diff_new_access(now, now) == []


def test_filetime_conversion_and_app_name():
    # FILETIME for 1970-01-01 is the epoch-diff constant -> unix 0.
    assert mcm._ft_to_unix(mcm._FT_EPOCH_DIFF) == 0.0
    assert mcm._ft_to_unix(0) is None
    assert mcm._readable_app(r"C:#Program Files#Zoom#zoom.exe") == "zoom.exe"


def test_snapshot_is_safe_to_call_everywhere():
    # On Windows this reads the real ConsentStore; elsewhere it must return [] not crash.
    recs = mcm.snapshot()
    assert isinstance(recs, list)
