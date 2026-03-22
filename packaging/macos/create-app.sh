#!/usr/bin/env bash
# packaging/macos/create-app.sh
#
# Wraps PyInstaller's dist/PIIScrub/ output into a proper macOS .app bundle,
# then packages it into a drag-to-Applications DMG.
#
# Prerequisites (installed by release.yml):
#   brew install create-dmg
#
# Run from repo root after: uv run pyinstaller piiscrub.spec --clean
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
DIST_DIR="$REPO_ROOT/dist/PIIScrub"
APP_NAME="PIIScrub"
APP_BUNDLE="$REPO_ROOT/dist/${APP_NAME}.app"
STAGING_DIR="$REPO_ROOT/dist/dmg-staging"
DMG_PATH="$REPO_ROOT/PIIScrub-macOS.dmg"
PLIST_SRC="$REPO_ROOT/packaging/macos/Info.plist"

echo "==> Creating .app bundle at $APP_BUNDLE"

# Clean any previous .app and staging dir
rm -rf "$APP_BUNDLE" "$STAGING_DIR"

# Create bundle structure
mkdir -p "$APP_BUNDLE/Contents/MacOS"
mkdir -p "$APP_BUNDLE/Contents/Resources"

# Copy the entire PyInstaller output into the bundle
# The main binary (PIIScrub) is a self-contained Mach-O — no launcher script needed
cp -R "$DIST_DIR/"* "$APP_BUNDLE/Contents/MacOS/"

# Ensure the main binary is executable
chmod +x "$APP_BUNDLE/Contents/MacOS/PIIScrub"

# Info.plist — CFBundleExecutable points directly at the PIIScrub Mach-O binary
# (macOS Sonoma/Ventura reject shell scripts as CFBundleExecutable in unsigned apps)
cp "$PLIST_SRC" "$APP_BUNDLE/Contents/Info.plist"

echo "==> Bundle contents:"
ls -lh "$APP_BUNDLE/Contents/MacOS/PIIScrub"

# ---------------------------------------------------------------------------
# Staging directory — create-dmg needs a FOLDER containing the .app,
# not the .app itself, to produce a DMG with a draggable app icon.
# ---------------------------------------------------------------------------
mkdir -p "$STAGING_DIR"
cp -R "$APP_BUNDLE" "$STAGING_DIR/"

# ---------------------------------------------------------------------------
# Build DMG with drag-to-Applications layout
# ---------------------------------------------------------------------------
echo "==> Building DMG: $DMG_PATH"

rm -f "$DMG_PATH"

create-dmg \
    --volname "PIIScrub" \
    --window-pos 200 120 \
    --window-size 600 400 \
    --icon-size 100 \
    --icon "${APP_NAME}.app" 150 200 \
    --hide-extension "${APP_NAME}.app" \
    --app-drop-link 430 200 \
    --no-internet-enable \
    "$DMG_PATH" \
    "$STAGING_DIR"

echo "==> DMG ready: $DMG_PATH"
ls -lh "$DMG_PATH"
