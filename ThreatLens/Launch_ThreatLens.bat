@echo off
cd /d "%~dp0"
echo Starting ThreatLens on http://127.0.0.1:5000 ...
start "" "http://127.0.0.1:5000"
py app.py
pause
