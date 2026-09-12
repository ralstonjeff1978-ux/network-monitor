#!/usr/bin/env python3
"""
Evidence collection — saves pcap files, JSON summaries, and packages them for law enforcement.
"""

import os
import json
import zipfile
from datetime import datetime
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from config import EVIDENCE_DIR

try:
    from scapy.all import wrpcap, PacketList
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

os.makedirs(EVIDENCE_DIR, exist_ok=True)

_current_capture = []
_capture_active = False
_current_session = None


def start_capture(attack_type, source_mac):
    global _current_capture, _capture_active, _current_session
    _current_capture = []
    _capture_active = True
    _current_session = {
        'attack_type': attack_type,
        'source_mac': source_mac,
        'start_time': datetime.now().isoformat(),
        'frames_captured': 0
    }
    print(f'[EVIDENCE] Capture started for {attack_type} from {source_mac}')


def add_packet(packet):
    if _capture_active:
        _current_capture.append(packet)
        if _current_session:
            _current_session['frames_captured'] += 1


def stop_capture(bt_sightings=None):
    global _capture_active
    _capture_active = False
    if not _current_session:
        return None
    return _save_evidence(bt_sightings or [])


def _save_evidence(bt_sightings):
    if not _current_session:
        return None

    ts = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
    session_dir = os.path.join(EVIDENCE_DIR, ts)
    os.makedirs(session_dir, exist_ok=True)

    pcap_path = None
    if _current_capture and SCAPY_AVAILABLE:
        pcap_path = os.path.join(session_dir, 'capture.pcap')
        try:
            wrpcap(pcap_path, PacketList(_current_capture))
        except Exception as e:
            print(f'[EVIDENCE] pcap save failed: {e}')
            pcap_path = None

    summary = {
        **_current_session,
        'end_time': datetime.now().isoformat(),
        'pcap_file': 'capture.pcap' if pcap_path else None,
        'bluetooth_nearby': bt_sightings,
    }
    summary_path = os.path.join(session_dir, 'summary.json')
    with open(summary_path, 'w') as f:
        json.dump(summary, f, indent=2)

    zip_path = os.path.join(EVIDENCE_DIR, f'{ts}_evidence.zip')
    with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zf:
        zf.write(summary_path, 'summary.json')
        if pcap_path and os.path.exists(pcap_path):
            zf.write(pcap_path, 'capture.pcap')
        readme = (
            'NETWORK ATTACK EVIDENCE PACKAGE\n'
            f'Generated: {datetime.now().isoformat()}\n\n'
            'Contents:\n'
            '  summary.json  — Attack details, timestamps, source MAC address\n'
            '  capture.pcap  — Raw packet capture (open with Wireshark)\n\n'
            'This evidence was collected by Network Monitor running on the\n'
            'victim machine. Timestamps are local system time.\n'
        )
        zf.writestr('README.txt', readme)

    print(f'[EVIDENCE] Saved: {zip_path}')
    return zip_path


def list_evidence():
    packages = []
    for fname in os.listdir(EVIDENCE_DIR):
        if fname.endswith('_evidence.zip'):
            fpath = os.path.join(EVIDENCE_DIR, fname)
            packages.append({
                'filename': fname,
                'path': fpath,
                'size_kb': round(os.path.getsize(fpath) / 1024, 1),
                'created': datetime.fromtimestamp(os.path.getmtime(fpath)).isoformat()
            })
    return sorted(packages, key=lambda x: x['created'], reverse=True)
