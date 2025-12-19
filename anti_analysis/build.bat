@echo off
echo Building with garble...
garble -ldflags="-s -w" build -o "AntiAnalysis.exe" main.go
echo Build finished.
pause
