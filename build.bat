@echo off
REM ============================================================================
REM  SecureCode — protected build of the demo application (SecureNotepad)
REM
REM  WHAT THIS DOES
REM    Nuitka translates the Python sources to C and compiles them to native
REM    machine code, then packs a single self-extracting EXE (--onefile).
REM    There is ZERO .pyc / marshal bytecode in the result, so:
REM       * pyinstxtractor / pyinstxtractor-ng find nothing to extract
REM       * uncompyle6 / decompyle3 / pycdc have nothing to decompile
REM
REM  PREREQUISITES
REM    pip install -r requirements.txt
REM    (nuitka + zstandard are required; a C compiler is auto-detected or
REM     downloaded by Nuitka on first run — needs internet ONCE for the
REM     toolchain only, the built app itself is fully offline)
REM
REM  BEFORE RELEASING (release pipeline — see docs/SECURITY.md)
REM    1. python protector\tools\build_strings_table.py      (rotate string layer)
REM    2. python target_demo\tools\gen_demo_keypair.py       (DEMO ONLY — real
REM       products generate the keypair INSIDE the protector, never in a repo)
REM    3. python protector\tools\make_integrity_manifest.py  (Layer 4 manifest)
REM    4. build.bat (this file)
REM ============================================================================
setlocal
cd /d "%~dp0"

echo [1/3] regenerating assets if missing...
if not exist target_demo\assets\app.ico (
    python target_demo\tools\make_icon.py || echo [warn] icon tool failed, building without icon
)

echo [2/3] building with Nuitka (this can take several minutes)...
rem --assume-yes-for-downloads: one-time, cached download of the analysis
rem toolchain (Dependency Walker / MinGW gcc when no MSVC is installed).
python -m nuitka ^
  --assume-yes-for-downloads ^
  --onefile ^
  --standalone ^
  --enable-plugin=pyside6 ^
  --windows-console-mode=disable ^
  --company-name="SecureCode Ltd." ^
  --product-name="SecureNotepad" ^
  --file-version=1.0.0.0 ^
  --product-version=1.0.0.0 ^
  --file-description="SecureNotepad - protected demo application" ^
  --copyright="Copyright (c) SecureCode Ltd." ^
  --windows-icon-from-ico=target_demo\assets\app.ico ^
  --output-filename=SecureNotepad.exe ^
  --include-package=shared ^
  --include-package=target_demo ^
  --output-dir=dist ^
  --remove-output ^
  target_demo\main.py

if errorlevel 1 (
    echo [error] build failed - see the Nuitka messages above.
    exit /b 1
)

echo [3/3] done. Result: dist\SecureNotepad.exe (single-file, ~25 MB)
echo.
echo  Smoke-test checklist before shipping:
echo   1. Run the EXE - activation dialog must appear with a machine code.
echo   2. Generate a serial in the protector (import the demo keypair first
echo      if you want the shipped demo keys: Settings -^> Import shipped demo keypair).
echo   3. Activate, restart the EXE, verify the "Licensed to ..." badge.
echo   4. Set the system clock +2 years forward -^> expiry error screen.
echo   5. Set it back -^> clock-tamper handling (grace + block after allowance).
endlocal
