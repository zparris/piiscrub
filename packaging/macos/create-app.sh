#!/usr/bin/env bash
# packaging/macos/create-app.sh
#
# Packages PyInstaller's dist/PIIScrub.app into a drag-to-Applications DMG.
# PyInstaller BUNDLE (in piiscrub.spec) already created the .app with the
# correct Contents/Frameworks/libpython3.11.dylib layout — don't touch it.
#
# Prerequisites (installed by release.yml):
#   brew install create-dmg
#
# Run from repo root after: uv run pyinstaller piiscrub.spec --clean
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
APP_BUNDLE="$REPO_ROOT/dist/PIIScrub.app"
STAGING_DIR="$REPO_ROOT/dist/dmg-staging"
DMG_PATH="$REPO_ROOT/PIIScrub-macOS.dmg"

if [ ! -d "$APP_BUNDLE" ]; then
    echo "ERROR: $APP_BUNDLE not found. Run: uv run pyinstaller piiscrub.spec --clean"
    exit 1
fi

echo "==> .app bundle:"
ls -lh "$APP_BUNDLE/Contents/MacOS/PIIScrub"
echo "==> libpython location:"
ls -lh "$APP_BUNDLE/Contents/Frameworks/libpython"*.dylib 2>/dev/null || echo "  (no libpython in Frameworks — check spec)"

# Staging directory — create-dmg needs a folder containing the .app
rm -rf "$STAGING_DIR"
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
