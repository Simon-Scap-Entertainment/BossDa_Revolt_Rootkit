@echo off
REM ============================================
REM PE Loader Build Script (Windows)
REM Complete workflow: Encode + Build
REM ============================================

echo [*] LeCatchu PE Loader - Complete Build Script
echo [*] ============================================
echo.

REM ============================================
REM Step 1: Check Prerequisites
REM ============================================

echo [*] Step 1: Checking prerequisites...

where python >nul 2>&1
if errorlevel 1 (
    echo [!] Error: Python not found in PATH
    exit /b 1
)

where ghc >nul 2>&1
if errorlevel 1 (
    echo [!] Error: GHC not found in PATH
    exit /b 1
)

if not exist "Main.hs" (
    echo [!] Error: Main.hs not found
    exit /b 1
)

echo [*] Prerequisites satisfied.
echo.

REM ============================================
REM Step 2: Get Target PE File
REM ============================================

if "%~1"=="" (
    set /p TARGET_PE="Enter PE file path: "
) else (
    set TARGET_PE=%~1
)

if not exist "%TARGET_PE%" (
    echo [!] Error: File not found: %TARGET_PE%
    exit /b 1
)

echo [*] Target: %TARGET_PE%
echo.

REM ============================================
REM Step 3: Encode PE File
REM ============================================

echo [*] Step 3: Encoding PE file...
set PAYLOAD_FILE=payload.bin

if exist "%PAYLOAD_FILE%" del /Q %PAYLOAD_FILE%

python encoder.py "%TARGET_PE%" "%PAYLOAD_FILE%"

if errorlevel 1 (
    echo [!] Encoding failed
    exit /b 1
)

if not exist "%PAYLOAD_FILE%" (
    echo [!] Error: payload.bin was not generated
    exit /b 1
)

echo [*] Encoding successful (%PAYLOAD_FILE% created)
echo.

REM ============================================
REM Step 4: Build Loader
REM ============================================

echo [*] Step 4: Building executable...

cabal build

if errorlevel 1 (
    echo [!] Build failed
    exit /b 1
)

REM Find and copy the executable
set EXE_PATH=
for /r "dist-newstyle" %%F in (*.exe) do (
    if "%%~nF"=="packer" (
        set EXE_PATH="%%F"
    )
)

if not defined EXE_PATH (
    echo [!] Could not find the built executable.
    exit /b 1
)

echo [*] Found executable at %EXE_PATH%
copy /Y %EXE_PATH% "loader.exe" >nul
echo [*] Copied to loader.exe

REM Cleanup intermediate payload (to respect "no disk" preference)
del /Q "%PAYLOAD_FILE%"
echo [*] Removed temporary payload file.

echo.
echo [*] ============================================
echo [*] BUILD COMPLETE: loader.exe
echo [*] ============================================
echo.

echo Would you like to run the loader now? (Y/N)
set /p RUN_NOW="Run loader? "
if /i "%RUN_NOW%"=="Y" (
    loader.exe
)
