#!/usr/bin/env python3
"""
Alerting module — Windows toast notifications + phone push via ntfy.sh
"""

import threading
import requests
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from config import NTFY_TOPIC, NTFY_ENABLED

try:
    from winotify import Notification, audio
    TOAST_AVAILABLE = True
except ImportError:
    TOAST_AVAILABLE = False

SEVERITY_ICONS = {
    'info':     'MS-AppX:///Assets/StoreLogo.png',
    'warning':  'MS-AppX:///Assets/StoreLogo.png',
    'critical': 'MS-AppX:///Assets/StoreLogo.png',
}

NTFY_PRIORITIES = {
    'info':     'default',
    'warning':  'high',
    'critical': 'urgent',
}


def _send_toast(title, message, severity='warning'):
    if not TOAST_AVAILABLE:
        return
    try:
        toast = Notification(
            app_id='Network Monitor',
            title=title,
            msg=message,
            duration='short'
        )
        if severity == 'critical':
            toast.set_audio(audio.Reminder, loop=False)
        toast.show()
    except Exception as e:
        print(f'[ALERT] Toast failed: {e}')


def _send_ntfy(title, message, severity='warning'):
    if not NTFY_ENABLED or not NTFY_TOPIC:
        return
    try:
        requests.post(
            f'https://ntfy.sh/{NTFY_TOPIC}',
            data=message.encode('utf-8'),
            headers={
                'Title': title,
                'Priority': NTFY_PRIORITIES.get(severity, 'default'),
                'Tags': 'rotating_light' if severity == 'critical' else 'warning',
            },
            timeout=5
        )
    except Exception as e:
        print(f'[ALERT] ntfy.sh failed: {e}')


def send_alert(title, message, severity='warning', phone=True):
    """
    Send alert via toast notification and optionally phone push.
    severity: 'info', 'warning', 'critical'
    """
    print(f'[{severity.upper()}] {title}: {message}')
    threading.Thread(target=_send_toast, args=(title, message, severity), daemon=True).start()
    if phone:
        threading.Thread(target=_send_ntfy, args=(title, message, severity), daemon=True).start()


def attack_alert(attack_type, source_mac, threat_level='high'):
    title = 'NETWORK ATTACK DETECTED'
    msg = f'Attack type: {attack_type}\nSource: {source_mac}\nThreat: {threat_level.upper()}'
    send_alert(title, msg, severity='critical', phone=True)


def proximity_alert(device_name, rssi, is_known_attacker=False):
    if is_known_attacker:
        title = 'KNOWN ATTACKER APPROACHING'
        msg = f'Known threat device detected nearby.\nDevice: {device_name}\nSignal: {rssi} dBm'
        severity = 'critical'
    else:
        title = 'Unknown Device Approaching'
        msg = f'Unknown device detected nearby.\nDevice: {device_name}\nSignal: {rssi} dBm'
        severity = 'warning'
    send_alert(title, msg, severity=severity, phone=is_known_attacker)


def all_clear_alert():
    send_alert('Network Secure', 'No active threats detected. All clear.', severity='info', phone=False)


def print_ntfy_setup():
    print(f'\n{"="*50}')
    print('PHONE ALERTS SETUP')
    print(f'{"="*50}')
    print('1. Install the "ntfy" app on your phone (iOS or Android)')
    print(f'2. Subscribe to topic: {NTFY_TOPIC}')
    print('3. You will get instant alerts when attacks are detected')
    print(f'{"="*50}\n')
