"""Tests for the Wi-Fi environment watcher — netsh parsing + rogue/evil-twin/ESP detection."""
from modules import wifi_watch as ww

_SAMPLE = """
Interface name : Wi-Fi 2

SSID 1 : MyHomeWiFi
    Authentication          : WPA2-Personal
    Encryption              : CCMP
    BSSID 1                 : aa:bb:cc:11:22:33
         Signal             : 100%
         Radio type         : 802.11ax
         Band               : 5 GHz
         Channel            : 157
         Bss Load:
             Channel Utilization:        19 (7 %)
SSID 2 : NeighborNet
    Authentication          : WPA3-Personal
    Encryption              : CCMP
    BSSID 1                 : 00:11:22:33:44:55
         Signal             : 60%
         Radio type         : 802.11ac
         Band               : 2.4 GHz
         Channel            : 6
"""


def test_parse_extracts_aps_and_channel_not_utilization():
    aps = ww.parse_netsh(_SAMPLE)
    assert len(aps) == 2
    home = aps[0]
    assert home.ssid == "MyHomeWiFi" and home.bssid == "aa:bb:cc:11:22:33"
    assert home.auth == "WPA2-Personal" and home.band == "5 GHz"
    assert home.channel == "157"          # NOT "19 (7 %)" — the collision is fixed
    assert home.radio == "802.11ax"


def test_espressif_bssid_detection():
    assert ww.is_espressif("24:0A:C4:11:22:33") is True
    assert ww.is_espressif("aa:bb:cc:11:22:33") is False


def test_evil_twin_is_critical():
    base = ww.WifiBaseline(home_ssid="MyHomeWiFi",
                           known_bssids={"aa:bb:cc:11:22:33"},
                           home_bssids={"aa:bb:cc:11:22:33"})
    imposter = ww.AP(ssid="MyHomeWiFi", bssid="de:ad:be:ef:00:01", auth="Open")
    ev = ww.diff(base, [imposter])
    assert len(ev) == 1 and ev[0].kind == "EVIL_TWIN" and ev[0].severity == 4


def test_rogue_esp_ap_flagged():
    base = ww.WifiBaseline(home_ssid="MyHomeWiFi", known_bssids={"aa:bb:cc:11:22:33"})
    esp = ww.AP(ssid="pwned", bssid="24:0a:c4:aa:bb:cc", auth="Open")
    ev = ww.diff(base, [esp])
    assert ev[0].kind == "ROGUE_ESP" and ev[0].severity == 4


def test_known_environment_is_quiet_after_learn():
    aps = ww.parse_netsh(_SAMPLE)
    base = ww.WifiBaseline(home_ssid="MyHomeWiFi")
    ww.update_baseline(base, aps)
    assert ww.diff(base, aps) == []       # learned APs don't re-alert


def test_beacon_spam_threshold():
    base = ww.WifiBaseline(home_ssid="Home")
    spam = [ww.AP(ssid=f"free-wifi-{i}", bssid=f"aa:bb:cc:00:00:{i:02x}") for i in range(15)]
    ev = ww.diff(base, spam)
    assert any(e.kind == "BEACON_SPAM" for e in ev)


def test_pmf_hardening_check():
    aps = ww.parse_netsh(_SAMPLE)
    assert ww.home_is_pmf_hardened(aps, "MyHomeWiFi") is False   # WPA2 → not hardened
    assert ww.home_is_pmf_hardened(aps, "NeighborNet") is True           # WPA3 → hardened
