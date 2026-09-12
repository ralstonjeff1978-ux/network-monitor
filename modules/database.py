#!/usr/bin/env python3
"""
SQLite database for persistent attack logging and device tracking.
"""

import sqlite3
import json
from datetime import datetime
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from config import DB_PATH


def get_conn():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_conn()
    c = conn.cursor()
    c.executescript('''
        CREATE TABLE IF NOT EXISTS attacks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            attack_type TEXT NOT NULL,
            source_mac TEXT,
            destination_mac TEXT,
            threat_level TEXT DEFAULT 'medium',
            details TEXT,
            evidence_path TEXT,
            bt_correlated INTEGER DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS bluetooth_sightings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            device_mac TEXT NOT NULL,
            device_name TEXT,
            rssi INTEGER,
            proximity TEXT,
            is_known_attacker INTEGER DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS network_devices (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT UNIQUE NOT NULL,
            mac TEXT,
            hostname TEXT,
            device_type TEXT DEFAULT 'unknown',
            vendor TEXT,
            first_seen TEXT,
            last_seen TEXT,
            is_blocked INTEGER DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS traffic_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            src_ip TEXT,
            dst_ip TEXT,
            dst_domain TEXT,
            protocol TEXT,
            size INTEGER,
            flagged INTEGER DEFAULT 0
        );
    ''')
    conn.commit()
    conn.close()


def log_attack(attack_type, source_mac=None, dest_mac=None,
               threat_level='medium', details=None, evidence_path=None, bt_correlated=False):
    conn = get_conn()
    conn.execute(
        '''INSERT INTO attacks
           (timestamp, attack_type, source_mac, destination_mac, threat_level, details, evidence_path, bt_correlated)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)''',
        (datetime.now().isoformat(), attack_type, source_mac, dest_mac,
         threat_level, json.dumps(details) if details else None,
         evidence_path, 1 if bt_correlated else 0)
    )
    conn.commit()
    conn.close()


def log_bluetooth(device_mac, device_name, rssi, proximity, is_known_attacker=False):
    conn = get_conn()
    conn.execute(
        '''INSERT INTO bluetooth_sightings
           (timestamp, device_mac, device_name, rssi, proximity, is_known_attacker)
           VALUES (?, ?, ?, ?, ?, ?)''',
        (datetime.now().isoformat(), device_mac, device_name,
         rssi, proximity, 1 if is_known_attacker else 0)
    )
    conn.commit()
    conn.close()


def upsert_device(ip, mac=None, hostname=None, device_type=None, vendor=None):
    conn = get_conn()
    now = datetime.now().isoformat()
    conn.execute(
        '''INSERT INTO network_devices (ip, mac, hostname, device_type, vendor, first_seen, last_seen)
           VALUES (?, ?, ?, ?, ?, ?, ?)
           ON CONFLICT(ip) DO UPDATE SET
               mac=COALESCE(excluded.mac, mac),
               hostname=COALESCE(excluded.hostname, hostname),
               device_type=COALESCE(excluded.device_type, device_type),
               vendor=COALESCE(excluded.vendor, vendor),
               last_seen=excluded.last_seen''',
        (ip, mac, hostname, device_type, vendor, now, now)
    )
    conn.commit()
    conn.close()


def get_recent_attacks(limit=50):
    conn = get_conn()
    rows = conn.execute(
        'SELECT * FROM attacks ORDER BY timestamp DESC LIMIT ?', (limit,)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_recent_bluetooth(limit=100):
    conn = get_conn()
    rows = conn.execute(
        'SELECT * FROM bluetooth_sightings ORDER BY timestamp DESC LIMIT ?', (limit,)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_all_devices():
    conn = get_conn()
    rows = conn.execute(
        'SELECT * FROM network_devices ORDER BY last_seen DESC'
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_recent_traffic(limit=100):
    conn = get_conn()
    rows = conn.execute(
        'SELECT * FROM traffic_log ORDER BY timestamp DESC LIMIT ?', (limit,)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def log_traffic(src_ip, dst_ip, dst_domain=None, protocol=None, size=0, flagged=False):
    conn = get_conn()
    conn.execute(
        '''INSERT INTO traffic_log (timestamp, src_ip, dst_ip, dst_domain, protocol, size, flagged)
           VALUES (?, ?, ?, ?, ?, ?, ?)''',
        (datetime.now().isoformat(), src_ip, dst_ip, dst_domain, protocol, size, 1 if flagged else 0)
    )
    conn.commit()
    conn.close()
