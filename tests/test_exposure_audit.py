"""Tests for the IoT exposure auditor — pure logic, no live network."""
from modules import exposure_audit as ea
from modules.exposure_audit import Device


def test_vendor_lookup_by_oui():
    assert "Espressif" in ea.vendor_for_mac("18:FE:34:AA:BB:CC")
    assert ea.vendor_for_mac("FC-A1-83-11-22-33") == "Amazon"      # dash form, uppercase (curated map wins)
    # locally-administered, never IEEE-assigned -> no vendor even with the full registry
    assert ea.vendor_for_mac("02:00:00:00:00:00") == ""


def test_arp_table_parse_windows_and_unix():
    win = (
        "Interface: 192.168.0.108 --- 0x5\n"
        "  Internet Address      Physical Address      Type\n"
        "  192.168.0.1           ac-84-c6-11-22-33     dynamic\n"
        "  192.168.0.36          3c-ef-8c-aa-bb-cc     dynamic\n"
        "  192.168.0.255         ff-ff-ff-ff-ff-ff     static\n"        # broadcast: dropped
        "  224.0.0.251           01-00-5e-00-00-fb     static\n"        # multicast: dropped
    )
    pairs = ea.parse_arp_table(win)
    ips = {ip for ip, _ in pairs}
    assert ips == {"192.168.0.1", "192.168.0.36"}
    assert ("192.168.0.36", "3c:ef:8c:aa:bb:cc") in pairs


def test_classification_prefers_hostname_then_ports_then_vendor():
    assert "Echo" in ea.classify("", "kitchen-echo.local", [])
    assert ea.classify("", "", [34567, 554]) == "IP camera / NVR"     # camera by port
    assert "vacuum" in ea.classify("Roborock", "", []).lower()        # by vendor
    assert ea.classify("", "", [443]) == "unknown"                    # nothing conclusive


def test_camera_dvrip_is_critical_with_remedy():
    d = Device(ip="192.168.0.36", mac="3c:ef:8c:aa:bb:cc", vendor="Xiongmai",
               open_ports=[554, 34567, 80])
    ea.audit_ports(d)
    assert d.max_severity == 4                                         # DVRIP telnet-class risk
    top = d.findings[0]
    assert top["port"] == 34567 and "VLAN" in top["remedy"]
    # findings are sorted worst-first
    assert [f["severity"] for f in d.findings] == sorted((f["severity"] for f in d.findings), reverse=True)


def test_telnet_and_adb_flag_as_critical():
    d = Device(ip="10.0.0.5", open_ports=[23, 5555, 443])
    ea.audit_ports(d)
    sev_by_port = {f["port"]: f["severity"] for f in d.findings}
    assert sev_by_port[23] == 4 and sev_by_port[5555] == 4 and sev_by_port[443] == 1


def test_report_is_honest_and_prioritized():
    cam = Device(ip="192.168.0.36", vendor="Xiongmai", open_ports=[34567])
    ea.audit_ports(cam)
    tv = Device(ip="192.168.0.50", vendor="Roku", open_ports=[8060])   # no risky port
    ea.audit_ports(tv)
    rep = ea.build_report([tv, cam], probed=True)
    assert rep["devices"][0]["ip"] == "192.168.0.36"          # highest severity first
    assert rep["summary"]["high_risk_devices"] == 1
    assert "never 'secure'" in rep["coverage_note"]           # never claims clean
    assert any("WPA3" in r or "802.11w" in r for r in rep["network_hardening"])
    assert any("VLAN" in r for r in rep["network_hardening"])
