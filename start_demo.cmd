@echo off
cd /d "%~dp0"
py -3.12 demo.py
if errorlevel 1 pause
