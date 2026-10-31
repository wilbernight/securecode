@echo off
REM ============================================================================
REM SecureCode — protected build of the PROTECTOR (vendor admin console)
REM
REM WHAT THIS DOES
REM   Compiles the protector GUI (dashboard, serial generation, license
REM   management) with Nuitka into a single self-contained EXE. Same
REM   guarantees as the demo build: native machine code, zero .pyc bytecode.
REM
REM   Data bundled INTO the EXE:
REM     * protector/assets/fonts   — Vazirmatn (SIL OFL) for Persian text
REM     * demo-assets/demo_keypair.sec — the shipped demo keypair, so
REM       "Import shipped demo keypair" also works on a fresh machine
REM
REM   NOT bundled (dev-only): protector/tools (excluded on purpose).
REM
REM RUNTIME STATE (created on first launch, outside the EXE):
REM   %APPDATA%\SecureCode\Protector\  — keystore.dat, settings.dat,
REM   licenses.db, logs\protector.log. The EXE uses YOUR existing keystore:
REM   same passphrase unlock as the source-run app.
REM ============================================================================
setlocal
cd /d "%~dp0"

echo [1/2] building protector with Nuitka (this can take several minutes)...
python -m nuitka ^
  --assume-yes-for-downloads ^
  --onefile ^
  --standalone ^
  --enable-plugin=pyside6 ^
  --windows-console-mode=disable ^
  --company-name="SecureCode Ltd." ^
  --product-name="SecureCode Protector" ^
  --file-version=1.0.0.0 ^
  --product-version=1.0.0.0 ^
  --file-description="SecureCode Protector - licensing management console" ^
  --copyright="Copyright (c) SecureCode Ltd." ^
  --windows-icon-from-ico=target_demo\assets\app.ico ^
  --output-filename=SecureCodeProtector.exe ^
  --include-package=protector ^
  --nofollow-import-to=protector.tools ^
  --include-package=shared ^
  --include-data-dir=protector\assets\fonts=protector\assets\fonts ^
  --include-data-file=demo-assets\demo_keypair.sec=demo-assets\demo_keypair.sec ^
  --output-dir=dist ^
  --remove-output ^
  protector\main.py

if errorlevel 1 (
    echo [error] build failed - see the Nuitka messages above.
    exit /b 1
)

echo [2/2] done. Result: dist\SecureCodeProtector.exe (single-file)
echo.
echo  First launch on a new machine: create keystore (optionally import the
echo  shipped demo keypair to pair with dist\SecureNotepad.exe).
endlocal
