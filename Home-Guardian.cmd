@echo off
title Home Guardian
cd /d "%~dp0"
REM Combined package: dashboard (loopback:5000) + always-on watchers (network, Wi-Fi, mic/cam)
REM + Bluetooth tracker + opt-in packet monitor + system tray. One launch = the whole protector.
python app.py
