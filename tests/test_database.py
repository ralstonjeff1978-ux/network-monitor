"""Tests for the SQLite persistence layer — CRUD round-trips against a temp DB."""
from modules import database


def _fresh_db(tmp_path):
    database.DB_PATH = str(tmp_path / "test_monitor.db")
    database.init_db()


def test_init_creates_schema(tmp_path):
    _fresh_db(tmp_path)
    # A fresh DB has empty result sets, not errors.
    assert database.get_recent_attacks() == []
    assert database.get_all_devices() == []


def test_log_and_read_attack(tmp_path):
    _fresh_db(tmp_path)
    database.log_attack("deauth_attack", source_mac="18:fe:34:aa:bb:cc",
                        dest_mac="ff:ff:ff:ff:ff:ff")
    rows = database.get_recent_attacks()
    assert len(rows) == 1
    assert rows[0]["attack_type"] == "deauth_attack"
    assert rows[0]["source_mac"] == "18:fe:34:aa:bb:cc"


def test_upsert_device_is_idempotent(tmp_path):
    _fresh_db(tmp_path)
    database.upsert_device("192.168.1.50", mac="aa:bb:cc:dd:ee:ff", hostname="laptop")
    database.upsert_device("192.168.1.50", mac="aa:bb:cc:dd:ee:ff", hostname="laptop-renamed")
    devices = database.get_all_devices()
    assert len(devices) == 1                       # upsert, not duplicate insert
    assert devices[0]["hostname"] == "laptop-renamed"


def test_log_and_read_bluetooth(tmp_path):
    _fresh_db(tmp_path)
    database.log_bluetooth("11:22:33:44:55:66", "Unknown", -60, "near")
    rows = database.get_recent_bluetooth()
    assert len(rows) == 1
    assert rows[0]["device_mac"] == "11:22:33:44:55:66"


def test_log_and_read_traffic(tmp_path):
    _fresh_db(tmp_path)
    database.log_traffic("192.168.1.2", "8.8.8.8", dst_domain="dns.google",
                         protocol="UDP", size=120, flagged=False)
    rows = database.get_recent_traffic()
    assert len(rows) == 1
    assert rows[0]["dst_ip"] == "8.8.8.8"


def test_recent_limit_orders_newest_first(tmp_path):
    _fresh_db(tmp_path)
    for i in range(5):
        database.log_attack(f"type_{i}", source_mac=f"00:00:00:00:00:0{i}")
    rows = database.get_recent_attacks(limit=3)
    assert len(rows) == 3                           # honors the limit
