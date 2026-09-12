#!/usr/bin/env python3
"""
Network Monitor — God Mode
Real-time home network security with attack detection, early warning, and evidence collection.
"""

import os
import sys
import threading
import asyncio
import time
import json
from datetime import datetime
from collections import defaultdict, deque

try:
    from scapy.all import (sniff, get_if_list, conf, Dot11, Dot11Beacon,
                            Dot11Elt, ARP, IP, DNS, DNSRR, UDP, wrpcap)
    SCAPY_OK = True
except ImportError:
    print('ERROR: scapy not installed. Run: pip install scapy')
    sys.exit(1)

from flask import Flask, render_template, jsonify, request, send_file
from flask_socketio import SocketIO

from modules.esp32_detector import ESP32Detector
from modules.countermeasures import Countermeasures
from modules.bluetooth_tracker import tracker as bt_tracker
from modules.automation import automation
from modules.database import init_db, log_attack, upsert_device, log_traffic, \
    get_recent_attacks, get_all_devices, get_recent_traffic, get_recent_bluetooth
from modules.evidence import add_packet, list_evidence
from modules.alerting import print_ntfy_setup
from config import DASHBOARD_PORT, EVIDENCE_DIR

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)
socketio = SocketIO(app, async_mode='eventlet', cors_allowed_origins='*')

automation.set_socketio(socketio)

esp32_detector = ESP32Detector()
countermeasures = Countermeasures()

monitoring_active = False
monitoring_thread = None
dot11_frames_seen = 0
monitor_mode_active = False

# In-memory state for dashboard (also persisted to SQLite)
state = {
    'devices': {},
    'recent_alerts': deque(maxlen=50),
    'stats': {
        'total_packets': 0,
        'deauth_count': 0,
        'arp_spoof_count': 0,
        'esp32_count': 0,
        'dot11_frames': 0,
    },
    'status': 'secure',   # secure / warning / attack
    'bt_devices': [],
}

DEVICE_ICONS = {
    'tv':      '📺',
    'phone':   '📱',
    'laptop':  '💻',
    'camera':  '📷',
    'speaker': '🔊',
    'router':  '📡',
    'unknown': '❓',
}

VENDOR_TYPES = {
    'samsung':  'tv',
    'lg elec':  'tv',
    'vizio':    'tv',
    'roku':     'tv',
    'apple':    'phone',
    'google':   'speaker',
    'amazon':   'speaker',
    'ring':     'camera',
    'nest':     'camera',
    'hikvisi':  'camera',
    'dahua':    'camera',
    'intel':    'laptop',
    'dell':     'laptop',
    'lenovo':   'laptop',
    'tp-link':  'router',
    'netgear':  'router',
    'asus':     'router',
}


def guess_device_type(vendor, hostname):
    if vendor:
        v = vendor.lower()
        for key, dtype in VENDOR_TYPES.items():
            if key in v:
                return dtype
    if hostname:
        h = hostname.lower()
        if any(x in h for x in ['tv', 'samsung', 'vizio', 'roku']):
            return 'tv'
        if any(x in h for x in ['iphone', 'android', 'pixel', 'phone']):
            return 'phone'
        if any(x in h for x in ['camera', 'cam', 'ring', 'nest']):
            return 'camera'
    return 'unknown'


def plain_english_alert(attack_type, source_mac, threat_level):
    messages = {
        'deauth': f'A device ({source_mac}) is trying to disconnect you from your WiFi.',
        'arp_spoof': f'A device is pretending to be your router. Possible man-in-the-middle attack from {source_mac}.',
        'esp32_deauth': f'Known attack hardware (ESP32 deauther) detected nearby. Source: {source_mac}.',
    }
    return messages.get(attack_type, f'{attack_type} detected from {source_mac}')


# ── Packet Handlers ──────────────────────────────────────────────────────────

def handle_deauth(packet):
    global dot11_frames_seen
    if not packet.haslayer(Dot11):
        return
    dot11_frames_seen += 1
    state['stats']['dot11_frames'] += 1

    if packet.type == 0 and packet.subtype in [0xC, 0xA]:
        src = getattr(packet, 'addr2', None) or 'unknown'
        dst = getattr(packet, 'addr1', None) or 'broadcast'
        state['stats']['deauth_count'] += 1

        alert = {
            'timestamp': datetime.now().isoformat(),
            'type': 'deauth',
            'message': plain_english_alert('deauth', src, 'high'),
            'source': src,
            'destination': dst,
            'threat_level': 'high',
        }
        state['recent_alerts'].appendleft(alert)
        state['status'] = 'attack'

        add_packet(packet)
        log_attack('deauth', source_mac=src, dest_mac=dst, threat_level='high',
                   details={'dst': dst})
        automation.on_deauth_detected(src, 'high', details=alert)
        socketio.emit('new_alert', alert)
        socketio.emit('status_change', {'status': 'attack'})


def handle_arp(packet):
    if not packet.haslayer(ARP):
        return
    if packet[ARP].op != 2:
        return

    src_ip = packet[ARP].psrc
    src_mac = packet[ARP].hwsrc

    upsert_device(src_ip, mac=src_mac)

    if src_ip in state['devices']:
        old_mac = state['devices'][src_ip].get('mac')
        if old_mac and old_mac != src_mac:
            state['stats']['arp_spoof_count'] += 1
            alert = {
                'timestamp': datetime.now().isoformat(),
                'type': 'arp_spoof',
                'message': plain_english_alert('arp_spoof', src_mac, 'high'),
                'ip': src_ip,
                'old_mac': old_mac,
                'new_mac': src_mac,
                'threat_level': 'high',
            }
            state['recent_alerts'].appendleft(alert)
            state['status'] = 'warning' if state['status'] == 'secure' else state['status']
            log_attack('arp_spoof', source_mac=src_mac, threat_level='high',
                       details={'ip': src_ip, 'old_mac': old_mac})
            automation.on_arp_spoof_detected(src_ip, old_mac, src_mac)
            socketio.emit('new_alert', alert)

    state['devices'][src_ip] = {
        'mac': src_mac,
        'ip': src_ip,
        'last_seen': datetime.now().isoformat(),
        'device_type': guess_device_type(None, None),
        'icon': DEVICE_ICONS.get('unknown'),
    }


def handle_dns(packet):
    if not packet.haslayer(DNS):
        return
    src_ip = packet[IP].src if packet.haslayer(IP) else None
    if not src_ip:
        return
    dns = packet[DNS]
    if dns.qr == 1 and dns.an:
        try:
            domain = dns.qd.qname.decode('utf-8', errors='ignore').rstrip('.')
            log_traffic(src_ip, dst_ip='dns', dst_domain=domain, protocol='DNS', size=len(packet))
            socketio.emit('traffic_update', {
                'src_ip': src_ip,
                'domain': domain,
                'timestamp': datetime.now().isoformat()
            })
        except Exception:
            pass


def handle_esp32(packet):
    if not packet.haslayer(Dot11):
        return
    findings = esp32_detector.detect_deauther_activity(packet)
    if findings['suspicious']:
        src = getattr(packet, 'addr2', None) or 'unknown'
        state['stats']['esp32_count'] += 1
        alert = {
            'timestamp': datetime.now().isoformat(),
            'type': 'esp32_attack',
            'message': plain_english_alert('esp32_deauth', src, 'critical'),
            'source': src,
            'threat_level': 'critical',
            'details': findings,
        }
        state['recent_alerts'].appendleft(alert)
        state['status'] = 'attack'
        log_attack('esp32_deauth', source_mac=src, threat_level='critical', details=findings)
        automation.on_esp32_detected(src, findings)
        socketio.emit('new_alert', alert)
        socketio.emit('status_change', {'status': 'attack'})


def packet_handler(packet):
    state['stats']['total_packets'] += 1
    add_packet(packet)
    handle_deauth(packet)
    handle_arp(packet)
    handle_dns(packet)
    handle_esp32(packet)


# ── Monitor Mode Check ────────────────────────────────────────────────────────

def check_monitor_mode(interface=None):
    global monitor_mode_active, dot11_frames_seen
    dot11_frames_seen = 0
    print('[MONITOR] Checking for 802.11 frame capture (3 second test)...')
    try:
        sniff(iface=interface, prn=lambda p: None, store=0,
              lfilter=lambda p: p.haslayer(Dot11), timeout=3,
              stop_filter=lambda p: dot11_frames_seen > 0)
        # Run a separate short sniff just to count dot11
        test_pkts = sniff(iface=interface, timeout=3,
                          lfilter=lambda p: p.haslayer(Dot11), store=1)
        if len(test_pkts) > 0:
            monitor_mode_active = True
            print('[MONITOR] 802.11 monitoring ACTIVE — deauth detection enabled')
        else:
            monitor_mode_active = False
            print('[MONITOR] WARNING: No 802.11 frames captured.')
            print('[MONITOR] Deauth detection is INACTIVE.')
            print('[MONITOR] Fix: Buy an ALFA AWUS036ACS adapter (~$35 on Amazon)')
            print('[MONITOR] and put it in monitor mode before starting.')
    except Exception:
        monitor_mode_active = False


def start_monitoring(interface=None):
    global monitoring_active
    if monitoring_active:
        return
    monitoring_active = True
    check_monitor_mode(interface)
    print(f'[MONITOR] Packet capture started on interface: {interface or "default"}')
    try:
        sniff(iface=interface, prn=packet_handler, store=0,
              stop_filter=lambda x: not monitoring_active)
    except Exception as e:
        print(f'[MONITOR] Capture error: {e}')
        if 'npcap' in str(e).lower() or 'winpcap' in str(e).lower():
            print('[MONITOR] Install Npcap from https://nmap.org/npcap/')
        monitoring_active = False


# ── Bluetooth Background Thread ───────────────────────────────────────────────

def run_bluetooth():
    bt_tracker.on_proximity_alert = automation.on_bluetooth_proximity
    bt_tracker.on_approaching_alert = automation.on_bluetooth_approaching

    def bt_loop():
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        loop.run_until_complete(bt_tracker.continuous_tracking())

    t = threading.Thread(target=bt_loop, daemon=True)
    t.start()
    print('[BT] Bluetooth tracking thread started')


# ── System Tray ───────────────────────────────────────────────────────────────

def run_tray():
    try:
        import pystray
        from PIL import Image, ImageDraw

        def make_icon(color):
            img = Image.new('RGB', (64, 64), color=color)
            d = ImageDraw.Draw(img)
            d.ellipse([8, 8, 56, 56], fill='white')
            d.ellipse([16, 16, 48, 48], fill=color)
            return img

        icons = {
            'secure':  make_icon('#22c55e'),
            'warning': make_icon('#f59e0b'),
            'attack':  make_icon('#ef4444'),
        }

        def open_dashboard(icon, item):
            import webbrowser
            webbrowser.open(f'http://localhost:{DASHBOARD_PORT}')

        def exit_app(icon, item):
            global monitoring_active
            monitoring_active = False
            bt_tracker.stop_tracking()
            icon.stop()
            os._exit(0)

        icon = pystray.Icon(
            'NetworkMonitor',
            icons['secure'],
            'Network Monitor — Secure',
            menu=pystray.Menu(
                pystray.MenuItem('Open Dashboard', open_dashboard),
                pystray.MenuItem('Exit', exit_app),
            )
        )

        def tray_update():
            while True:
                status = state['status']
                icon.icon = icons.get(status, icons['secure'])
                labels = {
                    'secure':  'Network Monitor — Secure',
                    'warning': 'Network Monitor — WARNING',
                    'attack':  'Network Monitor — UNDER ATTACK',
                }
                icon.title = labels.get(status, 'Network Monitor')
                time.sleep(2)

        threading.Thread(target=tray_update, daemon=True).start()
        icon.run()
    except ImportError:
        print('[TRAY] pystray/Pillow not installed — tray icon disabled')


# ── Flask Routes ──────────────────────────────────────────────────────────────

@app.route('/')
def index():
    return render_template('index.html',
                           ntfy_topic=__import__('config').NTFY_TOPIC)


@app.route('/api/status')
def api_status():
    return jsonify({
        'status': state['status'],
        'stats': state['stats'],
        'monitor_mode_active': monitor_mode_active,
        'monitoring_active': monitoring_active,
        'devices': list(state['devices'].values()),
        'alerts': list(state['recent_alerts']),
    })


@app.route('/api/start', methods=['POST'])
def api_start():
    global monitoring_thread
    iface = request.json.get('interface') if request.json else None
    if not monitoring_thread or not monitoring_thread.is_alive():
        monitoring_thread = threading.Thread(
            target=start_monitoring, args=(iface,), daemon=True)
        monitoring_thread.start()
    return jsonify({'status': 'started'})


@app.route('/api/stop', methods=['POST'])
def api_stop():
    global monitoring_active
    monitoring_active = False
    return jsonify({'status': 'stopped'})


@app.route('/api/lockdown', methods=['POST'])
def api_lockdown():
    from modules.alerting import send_alert
    send_alert('NETWORK LOCKDOWN', 'Manual lockdown activated', severity='critical', phone=True)
    state['status'] = 'warning'
    socketio.emit('status_change', {'status': 'warning', 'message': 'Lockdown active'})
    return jsonify({'status': 'lockdown_activated'})


@app.route('/api/all_clear', methods=['POST'])
def api_all_clear():
    state['status'] = 'secure'
    socketio.emit('status_change', {'status': 'secure'})
    return jsonify({'status': 'cleared'})


@app.route('/api/add_attacker', methods=['POST'])
def api_add_attacker():
    mac = request.json.get('mac', '').strip()
    if mac:
        bt_tracker.add_known_attacker(mac)
        from config import KNOWN_ATTACKERS
        KNOWN_ATTACKERS.append(mac)
        return jsonify({'status': 'added', 'mac': mac})
    return jsonify({'error': 'MAC required'}), 400


@app.route('/api/devices')
def api_devices():
    return jsonify(get_all_devices())


@app.route('/api/attacks')
def api_attacks():
    return jsonify(get_recent_attacks(50))


@app.route('/api/traffic')
def api_traffic():
    return jsonify(get_recent_traffic(100))


@app.route('/api/bluetooth')
def api_bluetooth():
    return jsonify({
        'live': bt_tracker.get_last_results(),
        'history': get_recent_bluetooth(50),
    })


@app.route('/api/evidence')
def api_evidence():
    return jsonify(list_evidence())


@app.route('/api/evidence/download/<filename>')
def api_evidence_download(filename):
    path = os.path.join(EVIDENCE_DIR, filename)
    if os.path.exists(path) and filename.endswith('.zip'):
        return send_file(path, as_attachment=True)
    return jsonify({'error': 'Not found'}), 404


@app.route('/api/interfaces')
def api_interfaces():
    try:
        ifaces = get_if_list()
    except Exception:
        ifaces = []
    return jsonify(ifaces)


# ── SocketIO Events ───────────────────────────────────────────────────────────

@socketio.on('connect')
def on_connect():
    socketio.emit('status_change', {'status': state['status']})
    socketio.emit('stats_update', state['stats'])


@socketio.on('request_bluetooth')
def on_bt_request():
    socketio.emit('bluetooth_snapshot', bt_tracker.get_last_results())


# ── Main ──────────────────────────────────────────────────────────────────────

if __name__ == '__main__':
    print('\n' + '=' * 60)
    print('  NETWORK MONITOR — GOD MODE')
    print('=' * 60)

    init_db()
    print_ntfy_setup()

    run_bluetooth()

    tray_thread = threading.Thread(target=run_tray, daemon=True)
    tray_thread.start()

    print(f'\n[SERVER] Dashboard: http://localhost:{DASHBOARD_PORT}')
    print('[SERVER] Starting...\n')

    socketio.run(app, host='0.0.0.0', port=DASHBOARD_PORT, debug=False)
