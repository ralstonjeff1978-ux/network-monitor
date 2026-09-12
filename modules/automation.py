#!/usr/bin/env python3
"""
Automation Controller — real event-driven responses to detected threats.
"""

import time
import threading
from collections import defaultdict


class AutomationController:
    def __init__(self):
        self.event_handlers = defaultdict(list)
        self.attack_start_time = None
        self.last_deauth_time = 0
        self.attack_active = False
        self.all_clear_timer = None
        self.socketio = None  # injected by app.py

    def set_socketio(self, sio):
        self.socketio = sio

    def on_event(self, event_type, handler):
        self.event_handlers[event_type].append(handler)

    def trigger_event(self, event_type, data=None):
        for handler in self.event_handlers.get(event_type, []):
            try:
                handler(event_type, data)
            except Exception as e:
                print(f'[AUTO] Handler error for {event_type}: {e}')

        if self.socketio and data:
            try:
                self.socketio.emit(event_type, data)
            except Exception:
                pass

    def on_deauth_detected(self, source_mac, threat_level, details=None):
        from modules.alerting import attack_alert
        from modules.evidence import start_capture

        self.last_deauth_time = time.time()

        if not self.attack_active:
            self.attack_active = True
            self.attack_start_time = time.time()
            attack_alert('Deauthentication Attack', source_mac, threat_level)
            start_capture('deauth', source_mac)
            print(f'[AUTO] Attack started from {source_mac}')

        if self.all_clear_timer:
            self.all_clear_timer.cancel()
        self.all_clear_timer = threading.Timer(60.0, self._check_all_clear)
        self.all_clear_timer.daemon = True
        self.all_clear_timer.start()

        self.trigger_event('attack_update', {
            'type': 'deauth',
            'source_mac': source_mac,
            'threat_level': threat_level,
            'details': details,
            'timestamp': time.time()
        })

    def on_esp32_detected(self, source_mac, findings):
        from modules.alerting import send_alert
        from modules.evidence import start_capture

        send_alert(
            'ESP32 DEAUTHER DETECTED',
            f'Known attack hardware detected\nMAC: {source_mac}',
            severity='critical',
            phone=True
        )
        start_capture('esp32_deauth', source_mac)

        self.trigger_event('esp32_detected', {
            'source_mac': source_mac,
            'findings': findings,
            'timestamp': time.time()
        })

    def on_arp_spoof_detected(self, ip, old_mac, new_mac):
        from modules.alerting import send_alert

        send_alert(
            'ARP Spoofing Attempt',
            f'IP {ip} changed MAC\nFrom: {old_mac}\nTo: {new_mac}',
            severity='warning',
            phone=True
        )
        self.trigger_event('arp_spoof', {
            'ip': ip, 'old_mac': old_mac, 'new_mac': new_mac,
            'timestamp': time.time()
        })

    def on_bluetooth_proximity(self, device_info, is_known_attacker):
        from modules.alerting import proximity_alert
        from modules.database import log_bluetooth

        log_bluetooth(
            device_info['mac'], device_info['name'],
            device_info['rssi'], device_info['proximity'], is_known_attacker
        )
        if is_known_attacker or device_info['rssi'] >= -65:
            proximity_alert(device_info['name'], device_info['rssi'], is_known_attacker)

        self.trigger_event('bluetooth_update', {
            'device': device_info,
            'is_known_attacker': is_known_attacker,
            'timestamp': time.time()
        })

    def on_bluetooth_approaching(self, device_info, trend):
        from modules.alerting import send_alert

        send_alert(
            'Device Approaching',
            f'{device_info["name"]} is getting closer\n'
            f'Signal: {device_info["rssi"]} dBm ({device_info["proximity"]})',
            severity='warning',
            phone=device_info['is_known_attacker']
        )

    def _check_all_clear(self):
        if time.time() - self.last_deauth_time >= 60:
            from modules.alerting import all_clear_alert
            from modules.evidence import stop_capture
            from modules.bluetooth_tracker import tracker

            self.attack_active = False
            recent_bt = tracker.get_last_results()
            evidence_path = stop_capture(bt_sightings=recent_bt)
            all_clear_alert()
            self.trigger_event('all_clear', {
                'evidence_path': evidence_path,
                'timestamp': time.time()
            })
            print('[AUTO] All clear — attack ended, evidence saved')

    def get_system_status(self):
        return {
            'attack_active': self.attack_active,
            'attack_start_time': self.attack_start_time,
            'last_deauth_time': self.last_deauth_time,
            'handlers_registered': sum(len(v) for v in self.event_handlers.values())
        }


automation = AutomationController()
