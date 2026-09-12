"""Tests for countermeasures — and a guard that they stay SIMULATED (data-only).

These features generate decoy data structures for analysis/experimentation; they
do not transmit RF or broadcast networks. The tests assert that shape so the
behavior (and the honest README claim) can't silently drift into real emission.
"""
import inspect
from modules import countermeasures


def test_honeypot_networks_are_data_only():
    cm = countermeasures.Countermeasures()
    nets = cm.deploy_honeypot_networks(count=10)
    assert len(nets) == 10
    for n in nets:
        assert n["fake_credentials"] is True
        assert "ssid" in n and n["accessed"] is False


def test_credential_trap_shape():
    cm = countermeasures.Countermeasures()
    trap = cm.create_credential_trap("Free_Public_WiFi")
    assert trap["ssid"] == "Free_Public_WiFi"
    assert trap["leads_nowhere"] is True
    assert "fake_password" in trap


def test_countermeasures_do_not_transmit():
    """Guard: the module must not call RF/socket transmission primitives."""
    src = inspect.getsource(countermeasures)
    for forbidden in ("sendp(", "socket.socket", "os.system", "subprocess.",
                      "RadioTap(", "Dot11Deauth"):
        assert forbidden not in src, f"countermeasures must stay simulated: found {forbidden}"
