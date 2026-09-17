# Home Guardian — local, always-on home-network protector

A single, private, **100% local** home-network security package: it inventories every device,
tells you what's exposed, watches for intrusion and surveillance, and alerts your phone — all
without a cloud account and **without adding latency to gaming** (the monitoring is passive and
out-of-band). One launch (`Home-Guardian.cmd`) starts the dashboard **and** the always-on watchers.

> **Status & responsible use.** Personal/defensive project for a network you own or are explicitly
> authorized to protect. It performs **no attacks** — it detects, reports, and (optionally, on your
> own router) blocks. The experimental *countermeasures* (honeypots, channel-hopping) are simulated
> and do not transmit. Check local laws before enabling any active defense.

## What it does

**Always-on watchers (no special hardware, gaming-safe):**
- **Device presence + inventory** — accurate make/vendor via the full IEEE OUI registry; alerts the moment an unknown device joins.
- **Exposure audit** — per-device risky-port scan (Telnet/DVRIP/RTSP/SMB/UPnP/…) with a prioritized, plain-English hardening plan.
- **Internet-exposure self-check** — your public IP + your router's UPnP port-forwards, so you know if a camera/service is reachable from the outside world (gaming-console forwards are recognized as expected).
- **Wi-Fi environment watch** — evil-twin (your SSID from a rogue radio), ESP32/ESP8266 deauther APs, beacon spam, and WPA2-vs-WPA3/PMF posture — all via an ordinary adapter (`netsh`).
- **Microphone / webcam access** — alerts when any app starts using your mic or camera (reads Windows' own usage ledger).

**Plus (from the original monitor):** real-time packet monitoring (deauth/ARP/DNS/ESP32, needs a monitor-mode adapter), Bluetooth proximity tracking, a web dashboard (loopback-only), system tray, phone push via ntfy, and a local event database.

## Quick start

```
python app.py            # the full package: dashboard + always-on watchers + tray
python guardian.py       # just the headless watchers (network + Wi-Fi + mic/cam)
python guardian_audit.py --sweep   # one-shot exposure + internet + hardening report
python scripts/update_oui.py       # refresh the device-vendor database
```

## Prerequisites

- Python 3.6+
- Required Python packages:
  - scapy
  - flask
  - bleak (for Bluetooth functionality)
- Npcap (for Windows packet capture): https://nmap.org/npcap/

## Installation

1. Install required packages:
   ```
   pip install scapy flask bleak
   ```

2. Install Npcap (Windows):
   - Download from: https://nmap.org/npcap/
   - Run installer with default settings
   - Restart your computer if prompted

3. Clone or download this repository

## Usage

1. Run the application:
   ```
   python app.py
   ```

2. Open your web browser and navigate to:
   ```
   http://localhost:5000
   ```

3. Click the "Start Monitoring" button to begin monitoring network traffic

## Enhanced Features

### ESP32 Deauther Detection
This application specifically detects ESP32-based deauther devices commonly used in DIY attack tools. It identifies:
- Known ESP32 MAC address patterns
- Beacon spam signatures
- Deauthentication frame patterns
- Firmware fingerprinting

### Countermeasures (experimental — simulated)
> **These countermeasures are *simulated*.** They generate decoy data structures
> (fake-network descriptors, credential traps, channel plans) for analysis and
> experimentation — they **do not transmit RF or broadcast anything**, and nothing
> is emitted onto the air. Detection is entirely **passive** (read-only sniffing).
> This keeps the project firmly on the defensive/legal side; a test
> (`tests/test_countermeasures.py`) guards against any drift into real emission.

When attacks are detected, the application can *model* deploying:
- Honeypot networks to waste attacker time
- Battery drain tactics to exhaust attacker device batteries
- Channel hopping to avoid targeted attacks
- Fake success indicators to make attacks appear effective

### Attacker Profiling
The application builds behavioral profiles of attackers including:
- Attack frequency and timing patterns
- Preferred attack methods
- Device fingerprinting
- Effectiveness tracking

### Automation
The system runs continuously in the background:
- Zero-conflict with gaming/work activities
- Set-and-forget monitoring
- Automated response triggers
- Self-maintenance features

## How This Application Protects You

This application detects:
- Deauthentication frames that disconnect users
- Disassociation frames that force reconnections
- Suspicious ARP traffic indicating spoofing attempts
- ESP32-based deauther device signatures
- Unusual network patterns

When threats are detected, they appear in the "Security Alerts" section of the dashboard.

## Installing Npcap for Full Functionality

On Windows, this application requires Npcap to capture and analyze network packets in real-time:

1. Download Npcap installer from: https://nmap.org/npcap/
2. Run the installer with default settings
3. Restart your computer if prompted
4. Launch the Network Monitor application again

Without Npcap, the application can still display the dashboard and show statistics, but it won't be able to capture live network packets for analysis.

## Troubleshooting

If you encounter issues:
1. Ensure you're running the application as Administrator (right-click shortcut → "Run as administrator")
2. Verify Npcap is properly installed
3. Check that your firewall isn't blocking the application

## Legal Considerations

This application implements only defensive measures that are legally acceptable:
- Does not cause permanent damage to devices
- Does not violate privacy laws
- Does not interfere with emergency services
- Remains within acceptable use policies
- Focuses on defensive time-wasting rather than offensive disruption
## Testing

A pytest suite covers the persistence layer, the (simulated) countermeasures, and
the ESP32/deauther fingerprinting logic:

```bash
pip install pytest scapy
python -m pytest tests/ -q
```

- `tests/test_database.py` — SQLite CRUD round-trips against a temp database
- `tests/test_countermeasures.py` — decoy structures + a guard that countermeasures stay **simulated** (no RF/socket transmission)
- `tests/test_esp32_detector.py` — MAC-prefix ESP32 detection and fingerprinting

All tests run offline with no network access.
