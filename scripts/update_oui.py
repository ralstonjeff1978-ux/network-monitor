#!/usr/bin/env python3
"""Refresh the IEEE OUI registry used for device identification (public data, free)."""
import os, urllib.request
DEST = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "oui.csv")
URL = "https://standards-oui.ieee.org/oui/oui.csv"
os.makedirs(os.path.dirname(DEST), exist_ok=True)
print(f"downloading {URL} ...")
urllib.request.urlretrieve(URL, DEST)
print(f"saved {os.path.getsize(DEST)} bytes -> {DEST}")
