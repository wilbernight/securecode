#!/usr/bin/env bash
# ============================================================================
# SecureCode — protected build of the PROTECTOR on macOS (vendor admin console)
#
# WHAT THIS DOES
#   The macOS equivalent of build_protector.bat: compiles the protector GUI
#   (dashboard, serial generation, license management) with Nuitka into a
#   self-contained .app bundle. Same guarantees as the Windows build:
#   native machine code, zero .pyc bytecode.
#
#   Data bundled INTO the .app:
#     * protector/assets/fonts       — Vazirmatn (SIL OFL) for Persian text
#     * demo-assets/demo_keypair.sec — the shipped demo keypair, so
#       "Import shipped demo keypair" also works on a fresh machine
#
#   NOT bundled (dev-only): protector/tools (excluded on purpose).
#
# RUNTIME STATE (created on first launch, outside the .app):
#   ~/Library/Application Support/SecureCode/Protector/ — keystore.dat,
#   settings.dat, licenses.db, logs/protector.log. The .app uses YOUR
#   existing keystore: same passphrase unlock as the source-run app.
#
# PREREQUISITES
#   macOS 12+ (Apple Silicon and Intel both supported)
#   Python 3.11+ from python.org (framework build), then:
#     xcode-select --install          # clang toolchain for Nuitka
#     python3 -m pip install -r requirements.txt
#   (the env markers in requirements.txt skip the Windows-only
#    wmi/pywin32/py-cpuinfo automatically — the protector needs only
#    pyside6 + cryptography on macOS)
# ============================================================================
set -euo pipefail
cd "$(dirname "$0")"

APP="dist/SecureCode Protector.app"

echo "[1/4] building protector with Nuitka (this can take several minutes)..."
# macOS notes:
#   * --standalone (NOT --onefile): on macOS a GUI app wants a real .app
#     bundle. --onefile here produced only a bare binary + an empty bundle
#     skeleton, which is not double-clickable / installable into /Applications.
#   * --disable-ccache: Nuitka auto-downloads an x86_64 ccache that fails to
#     invoke the arm64 `xcrun` on Apple Silicon ("missing compatible
#     architecture ... need x86_64"). Skipping ccache uses clang directly.
#   * --macos-app-icon: the shield app icon (protector/assets/AppIcon.icns,
#     extracted from AppIcon_AllSizes.zip). Without it the bundle has no
#     Contents/Resources icon and Finder/Dock show a blank generic app.
python3 -m nuitka \
  --assume-yes-for-downloads \
  --disable-ccache \
  --standalone \
  --macos-create-app-bundle \
  --enable-plugin=pyside6 \
  --macos-app-name="SecureCode Protector" \
  --macos-app-icon=protector/assets/AppIcon.icns \
  --include-package=protector \
  --nofollow-import-to=protector.tools \
  --include-package=shared \
  --include-data-dir=protector/assets/fonts=protector/assets/fonts \
  --include-data-file=demo-assets/demo_keypair.sec=demo-assets/demo_keypair.sec \
  --output-dir=dist \
  --remove-output \
  protector/main.py

echo "[2/4] naming the bundle (Nuitka names it after main.py -> main.app)..."
rm -rf "$APP"
mv "dist/main.app" "$APP"
if [ ! -f "$APP/Contents/Resources/AppIcon.icns" ] && ! ls "$APP/Contents/Resources/"*.icns >/dev/null 2>&1; then
    echo "      [warn] no .icns in the bundle — the app will show a generic icon"
fi

echo "[3/4] ad-hoc code signing (lets the local build launch through Gatekeeper)..."
if codesign --force --deep --sign - "$APP" 2>/dev/null; then
    echo "      signed (ad-hoc). For distribution, sign with a Developer ID:"
    echo "      codesign --force --deep --sign \"Developer ID Application: ...\" \"$APP\""
else
    echo "      [warn] codesign failed — right-click -> Open may be needed on first launch"
fi

echo "[4/4] done. Result: $APP"
echo
echo "  First launch on a new machine: create keystore (optionally import the"
echo "  shipped demo keypair to pair with the Windows demo app's serials)."
echo
echo "  Install: cp -R \"$APP\" /Applications/"
echo "  Tip: xattr -dr com.apple.quarantine \"$APP\""
echo "       (clears the downloaded-from-internet flag if you moved the bundle)"
