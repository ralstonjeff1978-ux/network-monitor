#!/usr/bin/env python3
"""
Bluetooth Proximity Tracker — early warning system.
Detects attacker devices approaching before WiFi attack starts.
"""

import asyncio
import time
from collections import defaultdict
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from config import (BT_SCAN_INTERVAL, BT_PROXIMITY_ALERT_RSSI,
                    BT_APPROACHING_THRESHOLD, KNOWN_ATTACKERS)

try:
    from bleak import BleakScanner
    BLEAK_AVAILABLE = True
except ImportError:
    BLEAK_AVAILABLE = False


class BluetoothTracker:
    def __init__(self):
        self.known_attackers = set(mac.lower() for mac in KNOWN_ATTACKERS)
        self.scan_history = defaultdict(list)  # mac -> list of {rssi, timestamp, name}
        self.tracking_active = False
        self.on_proximity_alert = None    # callback(device_info, is_known_attacker)
        self.on_approaching_alert = None  # callback(device_info, trend)
        self.last_scan_results = []

    def add_known_attacker(self, mac_address):
        self.known_attackers.add(mac_address.lower())
        print(f'[BT] Tracking known attacker: {mac_address}')

    def estimate_proximity(self, rssi):
        if rssi >= -50:
            return 'very_close'   # within ~10 feet
        elif rssi >= -65:
            return 'close'        # within ~30 feet
        elif rssi >= -75:
            return 'near'         # within ~60 feet
        elif rssi >= -85:
            return 'medium'       # within ~100 feet
        else:
            return 'far'

    def _check_approaching(self, mac):
        history = self.scan_history[mac]
        if len(history) < BT_APPROACHING_THRESHOLD + 1:
            return False, 0
        recent = history[-(BT_APPROACHING_THRESHOLD + 1):]
        rssi_values = [h['rssi'] for h in recent]
        # Signal getting stronger (less negative) = approaching
        improvements = sum(
            1 for i in range(1, len(rssi_values))
            if rssi_values[i] > rssi_values[i - 1]
        )
        is_approaching = improvements >= BT_APPROACHING_THRESHOLD
        trend = rssi_values[-1] - rssi_values[0]
        return is_approaching, trend

    async def _scan_once(self):
        if not BLEAK_AVAILABLE:
            return []
        try:
            # return_adv=True gives us AdvertisementData which contains rssi (bleak 0.21+)
            scan_results = await BleakScanner.discover(timeout=5.0, return_adv=True)
            results = []
            for addr, (device, adv) in scan_results.items():
                rssi = adv.rssi if adv.rssi is not None else -100
                name = device.name or adv.local_name or 'Unknown'
                info = {
                    'mac': addr.lower(),
                    'name': name,
                    'rssi': rssi,
                    'timestamp': time.time(),
                    'proximity': self.estimate_proximity(rssi),
                    'is_known_attacker': addr.lower() in self.known_attackers
                }
                results.append(info)
                self.scan_history[info['mac']].append({
                    'rssi': info['rssi'],
                    'timestamp': info['timestamp'],
                    'name': info['name']
                })
                if len(self.scan_history[info['mac']]) > 20:
                    self.scan_history[info['mac']] = self.scan_history[info['mac']][-20:]
            return results
        except Exception as e:
            print(f'[BT] Scan error: {e}')
            return []

    async def continuous_tracking(self):
        self.tracking_active = True
        print('[BT] Bluetooth tracking started')
        while self.tracking_active:
            try:
                devices = await self._scan_once()
                self.last_scan_results = devices

                for device in devices:
                    mac = device['mac']
                    rssi = device['rssi']
                    is_known = device['is_known_attacker']

                    # Alert on known attacker or strong unknown signal
                    if is_known or rssi >= BT_PROXIMITY_ALERT_RSSI:
                        if self.on_proximity_alert:
                            self.on_proximity_alert(device, is_known)

                    # Alert on approaching trend
                    is_approaching, trend = self._check_approaching(mac)
                    if is_approaching and trend > 5:
                        if self.on_approaching_alert:
                            self.on_approaching_alert(device, trend)

                await asyncio.sleep(BT_SCAN_INTERVAL)
            except Exception as e:
                print(f'[BT] Tracking error: {e}')
                await asyncio.sleep(30)

    def stop_tracking(self):
        self.tracking_active = False

    def get_device_history(self, mac, hours_back=24):
        cutoff = time.time() - (hours_back * 3600)
        return [
            s for s in self.scan_history.get(mac.lower(), [])
            if s['timestamp'] >= cutoff
        ]

    def get_last_results(self):
        return self.last_scan_results


tracker = BluetoothTracker()
