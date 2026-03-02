@echo off
setlocal
cd /d "%~dp0"

echo [1/4] Cleaning old files...
del /q *.syso 2>nul
del /q program.exe 2>nul

echo [2/4] Generating resource file...
rsrc -manifest app.manifest -arch amd64 -o rsrc_windows_amd64.syso

if not exist "rsrc_windows_amd64.syso" (
    echo [ERROR] Failed to generate .syso
    pause
    exit /b 1
)

echo [3/4] Building executable...
set CGO_ENABLED=0
set GOOS=windows
set GOARCH=amd64
go build -ldflags="-s -w -H=windowsgui -X 'main.manifest=rsrc_windows_amd64.syso'" -o program.exe .

if not exist "program.exe" (
    echo [ERROR] Build failed
    pause
    exit /b 1
)

echo [4/4] Verifying...
powershell -Command "if((Get-Content program.exe -Raw -Encoding Byte | ForEach-Object {[System.Text.Encoding]::ASCII.GetString($_)}) -match 'requireAdministrator'){Write-Host '[OK] Manifest embedded' -ForegroundColor Green}else{Write-Host '[FAIL] Manifest NOT embedded' -ForegroundColor Red}"

echo.
echo [SUCCESS] program.exe created
echo.
pause