@echo off
REM Starts the Phishing Link Detector silently in the background
cd /d "%~dp0"
start javaw -jar "target\phishing-detector-1.0-SNAPSHOT.jar"
