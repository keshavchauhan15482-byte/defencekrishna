@echo off
cd /d "%~dp0"
py -3 start_main_console.py
if errorlevel 1 python start_main_console.py
pause
