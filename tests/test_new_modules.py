"""Tests for the best-in-class additions: OUI device-ID + internet-exposure (pure logic)."""
from modules import oui
from modules import internet_exposure as ie


def test_oui_prefix_normalization():
    assert oui._normalize_prefix("286FB9") == "28:6f:b9"
    assert oui._normalize_prefix("fca183") == "fc:a1:83"
    assert oui._normalize_prefix("xx") == ""


def test_oui_lookup_uses_registry_if_present(tmp_path, monkeypatch):
    csv = tmp_path / "oui.csv"
    csv.write_text(
        "Registry,Assignment,Organization Name,Organization Address\n"
        'MA-L,3CEF8C,"Xiongmai Tech","addr"\n', encoding="utf-8")
    oui._CACHE = None
    monkeypatch.setattr(oui, "_CSV", str(csv))
    assert oui.load(str(csv))  # populated
    oui._CACHE = None
    assert oui.lookup("3c:ef:8c:aa:bb:cc") == "Xiongmai Tech"
    assert oui.lookup("00:00:00:11:22:33") == ""     # unknown prefix
    oui._CACHE = None                                 # don't leak into other tests


def test_internet_forward_severity_and_note():
    cam = ie.Forward(ext_port=34567, int_port=34567, int_client="192.168.0.36", proto="TCP", desc="")
    assert cam.severity() == 4 and "EXPOSED TO THE INTERNET" in cam.note()
    game = ie.Forward(ext_port=9308, int_port=9308, int_client="192.168.0.75", proto="UDP", desc="PS5")
    assert game.severity() == 3 and "forwarded to the internet" in game.note()


def test_internet_check_shape_offline(monkeypatch):
    # No UPnP gateway (or no network): must return the SECURE-if-disabled message, not crash.
    monkeypatch.setattr(ie, "_ssdp_discover", lambda timeout=3.0: "")
    monkeypatch.setattr(ie, "public_ip", lambda timeout=5.0: "203.0.113.7")
    r = ie.check()
    assert r.public_ip == "203.0.113.7" and r.upnp_found is False and r.forwards == []
    assert "SECURE" in r.note or "router UI" in r.note
