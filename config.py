#!/usr/bin/env python3
"""
Network Monitor Configuration
Edit these values to customize your setup.
"""

import os
import secrets

CONFIG_FILE = os.path.join(os.path.dirname(__file__), '.config_state')

def _load_topic():
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, 'r') as f:
            for line in f:
                if line.startswith('NTFY_TOPIC='):
                    return line.strip().split('=', 1)[1]
    topic = 'shieldwatch-' + secrets.token_hex(6)
    with open(CONFIG_FILE, 'a') as f:
        f.write(f'NTFY_TOPIC={topic}\n')
    return topic

# Phone push notifications (free — install ntfy app on your phone)
# Subscribe to this topic in the ntfy app to get alerts on your phone
NTFY_TOPIC = _load_topic()
NTFY_ENABLED = True

# Router SSH access (optional — enables channel hop and MAC block)
# Leave blank to disable router commands
ROUTER_IP = ''
ROUTER_USER = ''
ROUTER_PASSWORD = ''
ROUTER_TYPE = 'openwrt'  # openwrt, ddwrt, asus

# Bluetooth scanning interval (seconds)
BT_SCAN_INTERVAL = 10

# RSSI threshold for proximity alert (approaching devices)
BT_PROXIMITY_ALERT_RSSI = -70

# How many consecutive scans getting stronger = "approaching" alert
BT_APPROACHING_THRESHOLD = 2

# Known attacker devices — add MAC addresses here after first attack
# Example: KNOWN_ATTACKERS = ['18:fe:34:xx:xx:xx', 'aa:bb:cc:dd:ee:ff']
KNOWN_ATTACKERS = []

# Evidence directory
EVIDENCE_DIR = os.path.join(os.path.dirname(__file__), 'evidence')

# Database path
DB_PATH = os.path.join(os.path.dirname(__file__), 'monitor.db')

# Threat intel — IPs from these countries trigger yellow alerts
SUSPICIOUS_COUNTRY_CODES = ['RU', 'CN', 'KP', 'IR']

# Dashboard port
DASHBOARD_PORT = 5000
