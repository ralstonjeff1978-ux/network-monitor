@echo off
title Home Guardian - Protecting
cd /d "%~dp0"
REM Always-on protector: learns your devices, then alerts (phone + desktop) on anything new.
python guardian.py --interval 60
