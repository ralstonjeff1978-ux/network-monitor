@echo off
title Network Monitor — God Mode
cd /d "F:\network_monitor"

echo ============================================================
echo  NETWORK MONITOR — GOD MODE
echo ============================================================
echo.

if exist venv\Scripts\activate.bat (
    call venv\Scripts\activate.bat
)

echo [CHECK] Verifying dependencies...
python -c "import scapy, flask, flask_socketio, bleak, winotify, pystray" 2>nul
if errorlevel 1 (
    echo [INSTALL] Installing required packages...
    pip install -r requirements.txt
    if errorlevel 1 (
        echo [ERROR] Package installation failed. Check your internet connection.
        pause
        exit /b 1
    )
)

echo [CHECK] Npcap check...
python -c "from scapy.all import get_if_list; get_if_list()" 2>nul
if errorlevel 1 (
    echo.
    echo [WARNING] Npcap may not be installed.
    echo           Download from: https://nmap.org/npcap/
    echo           Install with default settings then restart.
    echo.
)

echo.
echo [INFO] Dashboard will open at: http://localhost:5000
echo [INFO] Check the console for your phone alert topic.
echo [INFO] Minimize this window - monitor runs in system tray.
echo.
echo Press Ctrl+C to stop.
echo.

python app.py

pause
