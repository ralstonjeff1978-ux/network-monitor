@echo off
title Home Guardian - Network Exposure Audit
cd /d "%~dp0"
python guardian_audit.py --sweep
echo.
pause
