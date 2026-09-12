#!/usr/bin/env python3
"""
ESP32 Deauther Detector
Module for detecting and fingerprinting ESP32-based deauther devices
"""

import re
import time
from scapy.all import *

class ESP32Detector:
    def __init__(self):
        # Known ESP32 MAC address prefixes commonly used in DIY deauthers
        self.esp32_mac_prefixes = [
            "18:fe:34",  # Espressif Systems
            "24:0a:c4",  # Espressif Systems
            "2c:3a:e8",  # Espressif Systems
            "30:ae:a4",  # Espressif Systems
            "3c:71:bf",  # Espressif Systems
            "54:5a:a6",  # Espressif Systems
            "5c:cf:7f",  # Espressif Systems
            "60:01:94",  # Espressif Systems
            "68:c6:3a",  # Espressif Systems
            "84:0d:8e",  # Espressif Systems
            "90:97:d5",  # Espressif Systems
            "a4:7b:9d",  # Espressif Systems
            "ac:d0:74",  # Espressif Systems
            "b4:e6:2d",  # Espressif Systems
            "c4:4f:33",  # Espressif Systems
            "cc:50:e3",  # Espressif Systems
            "d8:a0:1d",  # Espressif Systems
            "dc:4f:22",  # Espressif Systems
            "ec:fa:bc",  # Espressif Systems
        ]

        # Known beacon spam signatures
        self.beacon_signatures = [
            "FREE_WIFI",
            "FREE_WIFI_Extender",
            "Free Internet",
            "Hack_Lab",
            "Evil_Twin",
            "Starbucks_WiFi",
            "Free_Public_WiFi",
        ]

        # Known deauther firmware identifiers
        self.firmware_signatures = [
            "esp8266_deauther",
            "WiFi_Deauther",
            "Beacon_Spammer",
            "Evil_Twin_AP",
        ]

    def is_esp32_device(self, mac_address):
        """Check if MAC address belongs to an ESP32 device"""
        mac_prefix = mac_address.lower()[:8]
        return mac_prefix in self.esp32_mac_prefixes

    def detect_deauther_activity(self, packet):
        """Detect ESP32-based deauther activity"""
        findings = {
            'is_esp32': False,
            'is_deauth_frame': False,
            'is_beacon_spam': False,
            'suspicious': False,
            'threat_level': 'low'
        }

        try:
            # Check if packet has 802.11 layer
            if packet.haslayer(Dot11):
                # Check source MAC address
                src_mac = packet.addr2
                if src_mac and self.is_esp32_device(src_mac):
                    findings['is_esp32'] = True

                # Check for deauth/disassoc frames
                if packet.type == 0 and packet.subtype in [0xC, 0xA]:
                    findings['is_deauth_frame'] = True
                    findings['threat_level'] = 'high'

                # Check for beacon spam patterns
                if packet.haslayer(Dot11Beacon):
                    ssid = packet[Dot11Elt].info.decode('utf-8', errors='ignore')
                    for signature in self.beacon_signatures:
                        if signature.lower() in ssid.lower():
                            findings['is_beacon_spam'] = True
                            findings['threat_level'] = 'medium'

                # Check for suspicious packet patterns
                if findings['is_esp32'] and (findings['is_deauth_frame'] or findings['is_beacon_spam']):
                    findings['suspicious'] = True

        except Exception as e:
            pass

        return findings

    def fingerprint_attacker(self, mac_address, packet_patterns=None):
        """Create a fingerprint of the attacker device"""
        fingerprint = {
            'mac_address': mac_address,
            'is_esp32': self.is_esp32_device(mac_address),
            'first_seen': time.time(),
            'packet_patterns': packet_patterns or [],
            'attack_frequency': 0,
            'preferred_targets': [],
            'signature_match': None
        }

        # Try to identify specific firmware
        if fingerprint['is_esp32']:
            # This would be expanded with more detailed fingerprinting
            fingerprint['signature_match'] = "ESP32-based deauther suspected"

        return fingerprint

# Singleton instance
detector = ESP32Detector()