@echo off
REM Starts the Phishing Link Detector silently in the background
cd /d "%~dp0"
start javaw -cp "lib\*;out" com.phishing.Main
