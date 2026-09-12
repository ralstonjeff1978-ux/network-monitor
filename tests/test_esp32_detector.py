"""Tests for ESP32/deauther fingerprinting (pure MAC-prefix logic)."""
import pytest

pytest.importorskip("scapy")   # esp32_detector imports scapy at module load
from modules import esp32_detector


def test_known_esp32_prefix_is_detected():
    det = esp32_detector.ESP32Detector()
    assert det.is_esp32_device("18:FE:34:11:22:33") is True   # Espressif prefix, any case
    assert det.is_esp32_device("dc:4f:22:aa:bb:cc") is True


def test_non_esp32_mac_is_not_flagged():
    det = esp32_detector.ESP32Detector()
    assert det.is_esp32_device("00:11:22:33:44:55") is False


def test_fingerprint_marks_esp32():
    det = esp32_detector.ESP32Detector()
    fp = det.fingerprint_attacker("18:fe:34:00:00:01")
    assert fp["is_esp32"] is True
