@echo off
REM ============================================
REM PE Loader Build Script (Windows)
REM Complete workflow: Encode + Build + Run
REM ============================================

echo [*] LeCatchu PE Loader - Complete Build Script
echo [*] ============================================
echo.

REM ============================================
REM Step 1: Check Prerequisites
REM ============================================

echo [*] Step 1: Checking prerequisites...
echo.

REM Check Python
where python >nul 2>&1
if errorlevel 1 (
    echo [!] Error: Python not found in PATH
    echo [!] Please install Python 3.7+ from https://www.python.org/
    exit /b 1
)

echo [*] Python version:
python --version
echo.

REM Check if encoder.py exists
if not exist "encoder.py" (
    echo [!] Error: encoder.py not found
    echo [!] Please ensure encoder.py is in the current directory
    exit /b 1
)

REM Check if lecatchu.py exists
if not exist "lecatchu.py" (
    echo [!] Warning: lecatchu.py not found in current directory
    echo [!] Make sure the LeCatchu Python library is accessible
    pause
)

REM Check if GHC is installed
where ghc >nul 2>&1
if errorlevel 1 (
    echo [!] Error: GHC not found in PATH
    echo [!] Please install GHC via GHCup or Haskell Platform
    echo [!] Download from: https://www.haskell.org/ghcup/
    exit /b 1
)

echo [*] GHC version:
ghc --version
echo.

REM Check if required Haskell files exist
if not exist "LeCatchu.hs" (
    echo [!] Error: LeCatchu.hs not found
    exit /b 1
)

if not exist "Main.hs" (
    echo [!] Error: Main.hs not found
    exit /b 1
)

echo [*] All prerequisites satisfied
echo.

REM ============================================
REM Step 2: Get Target PE File
REM ============================================

echo [*] Step 2: Select PE file to encode
echo.

REM Check if user provided file as argument
if "%~1"=="" (
    echo Enter the path to the PE file you want to encode:
    echo Examples:
    echo   - C:\Windows\System32\calc.exe
    echo   - C:\Windows\System32\notepad.exe
    echo   - .\myprogram.exe
    echo.
    set /p TARGET_PE="PE file path: "
) else (
    set TARGET_PE=%~1
    echo [*] Using provided file: %TARGET_PE%
)

REM Validate file exists
if not exist "%TARGET_PE%" (
    echo.
    echo [!] Error: File not found: %TARGET_PE%
    exit /b 1
)

REM Get file size
for %%A in ("%TARGET_PE%") do (
    echo [*] Target file: %%~nxA
    echo [*] File size: %%~zA bytes
)
echo.

REM Ask for confirmation
echo Is this the correct file? (Y/N)
set /p CONFIRM="Confirm: "
if /i not "%CONFIRM%"=="Y" (
    echo [*] Operation cancelled
    exit /b 0
)
echo.

REM ============================================
REM Step 3: Encode PE File
REM ============================================

echo [*] Step 3: Encoding PE file with LeCatchu...
echo.

REM Delete old EncodedPayload.hs if it exists
if exist "EncodedPayload.hs" (
    echo [*] Removing old EncodedPayload.hs...
    del /Q EncodedPayload.hs
)

REM Run encoder
python encoder.py "%TARGET_PE%" EncodedPayload.hs

if errorlevel 1 (
    echo.
    echo [!] Encoding failed
    echo [!] Check error messages above
    exit /b 1
)

REM Verify EncodedPayload.hs was created
if not exist "EncodedPayload.hs" (
    echo.
    echo [!] Error: EncodedPayload.hs was not generated
    exit /b 1
)

echo.
echo [*] Encoding successful!

REM Display EncodedPayload.hs size
for %%A in (EncodedPayload.hs) do echo [*] EncodedPayload.hs size: %%~zA bytes
echo.

REM ============================================
REM Step 4: Build Loader
REM ============================================

echo [*] Step 4: Building loader.exe...
echo [*] This may take a few minutes on first build...
echo.

REM Clean up old build artifacts
if exist "loader.exe" (
    echo [*] Removing old loader.exe...
    del /Q loader.exe
)

echo [*] Cleaning old object files...
del /Q *.hi *.o 2>nul

echo [*] Compiling with GHC (optimizations enabled)...
echo.

ghc -O2 -threaded ^
    -rtsopts ^
    -with-rtsopts=-N ^
    -Wall ^
    -fno-warn-unused-imports ^
    -fno-warn-unused-matches ^
    Main.hs ^
    LeCatchu.hs ^
    EncodedPayload.hs ^
    -o loader.exe

if errorlevel 1 (
    echo.
    echo [!] Build failed
    echo [!] Check error messages above
    exit /b 1
)

echo.
echo [*] Build successful!

REM Display file size
for %%A in (loader.exe) do echo [*] Loader size: %%~zA bytes
echo.

REM Clean up intermediate files
echo [*] Cleaning up intermediate files...
del /Q *.hi *.o 2>nul
echo [*] Done!
echo.

REM ============================================
REM Step 5: Summary and Run Options
REM ============================================

echo [*] ============================================
echo [*] BUILD COMPLETE
echo [*] ============================================
echo.
echo [*] Summary:
echo [*]   Target PE: %TARGET_PE%
for %%A in ("%TARGET_PE%") do echo [*]   Original size: %%~zA bytes
for %%A in (EncodedPayload.hs) do echo [*]   Encoded module: %%~zA bytes
for %%A in (loader.exe) do echo [*]   Loader size: %%~zA bytes
echo.

echo Would you like to run the loader now? (Y/N)
set /p RUN_NOW="Run loader: "

if /i "%RUN_NOW%"=="Y" (
    echo.
    echo [*] ============================================
    echo [*] RUNNING LOADER
    echo [*] ============================================
    echo.
    loader.exe
    echo.
    echo [*] Loader execution finished
    echo [*] Check output above for results
) else (
    echo.
    echo [*] To run the loader manually, execute:
    echo [*]   loader.exe
)

echo.
echo [*] Build script complete!
pause
exit /b 0
