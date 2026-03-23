#!/usr/bin/env bash
# packaging/macos/create-app.sh
#
# Wraps PyInstaller's dist/PIIScrub/ (COLLECT output) into a proper macOS
# .app bundle, then packages it into a drag-to-Applications DMG.
#
# Key layout requirement:
#   Contents/MacOS/  — everything from COLLECT, including all data and the
#                      spaCy model. sys._MEIPASS points here at runtime so
#                      Python's import system can find en_core_web_lg.
#   Contents/Frameworks/ — libpython3.11.dylib only. The PyInstaller bootloader
#                          burns @executable_path/../Frameworks/libpython*.dylib
#                          into its rpath, so the dylib must live here.
#
# Prerequisites (installed by release.yml):
#   brew install create-dmg
#
# Run from repo root after: uv run pyinstaller piiscrub.spec --clean
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
DIST_DIR="$REPO_ROOT/dist/PIIScrub"
APP_BUNDLE="$REPO_ROOT/dist/PIIScrub.app"
STAGING_DIR="$REPO_ROOT/dist/dmg-staging"
DMG_PATH="$REPO_ROOT/PIIScrub-macOS.dmg"
PLIST_SRC="$REPO_ROOT/packaging/macos/Info.plist"

if [ ! -d "$DIST_DIR" ]; then
    echo "ERROR: $DIST_DIR not found. Run: uv run pyinstaller piiscrub.spec --clean"
    exit 1
fi

echo "==> Creating .app bundle at $APP_BUNDLE"
rm -rf "$APP_BUNDLE" "$STAGING_DIR"

mkdir -p "$APP_BUNDLE/Contents/MacOS"
mkdir -p "$APP_BUNDLE/Contents/Frameworks"
mkdir -p "$APP_BUNDLE/Contents/Resources"

# Copy the entire COLLECT output into Contents/MacOS/
# This keeps sys._MEIPASS == Contents/MacOS/ so Python's import system
# can find the bundled spaCy model (en_core_web_lg/) and all other packages.
cp -R "$DIST_DIR/"* "$APP_BUNDLE/Contents/MacOS/"

# Move libpython to Contents/Frameworks/ — the bootloader's rpath is
# @executable_path/../Frameworks/libpython*.dylib so it must live there.
for _dylib in "$APP_BUNDLE/Contents/MacOS/libpython"*.dylib; do
    if [ -f "$_dylib" ]; then
        mv "$_dylib" "$APP_BUNDLE/Contents/Frameworks/"
        echo "  Moved $(basename "$_dylib") -> Contents/Frameworks/"
    fi
done

# Verify the main binary is executable
chmod +x "$APP_BUNDLE/Contents/MacOS/PIIScrub"

# Install the Info.plist
cp "$PLIST_SRC" "$APP_BUNDLE/Contents/Info.plist"

echo "==> Bundle structure:"
echo "  MacOS/PIIScrub     : $(ls -lh "$APP_BUNDLE/Contents/MacOS/PIIScrub" | awk '{print $5}')"
echo "  Frameworks/        : $(ls "$APP_BUNDLE/Contents/Frameworks/" | tr '\n' ' ')"
echo "  MacOS/en_core_web_lg: $([ -d "$APP_BUNDLE/Contents/MacOS/en_core_web_lg" ] && echo 'present' || echo 'MISSING')"

# ---------------------------------------------------------------------------
# Staging directory for create-dmg
# ---------------------------------------------------------------------------
mkdir -p "$STAGING_DIR"
cp -R "$APP_BUNDLE" "$STAGING_DIR/"

echo "==> Building DMG: $DMG_PATH"
rm -f "$DMG_PATH"

create-dmg \
    --volname "PIIScrub" \
    --window-pos 200 120 \
    --window-size 600 400 \
    --icon-size 100 \
    --icon "PIIScrub.app" 150 200 \
    --hide-extension "PIIScrub.app" \
    --app-drop-link 430 200 \
    --no-internet-enable \
    "$DMG_PATH" \
    "$STAGING_DIR"

echo "==> DMG ready: $DMG_PATH"
ls -lh "$DMG_PATH"
