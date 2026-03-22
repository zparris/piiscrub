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
DMG_PATH="$REPO_ROOT/PIIScrub-macOS.dmg"
PLIST_SRC="$REPO_ROOT/packaging/macos/Info.plist"

echo "==> Creating .app bundle at $APP_BUNDLE"

# Clean any previous .app
rm -rf "$APP_BUNDLE"

# Create bundle structure
mkdir -p "$APP_BUNDLE/Contents/MacOS"
mkdir -p "$APP_BUNDLE/Contents/Resources"

# Copy the entire PyInstaller output into the bundle
cp -R "$DIST_DIR/"* "$APP_BUNDLE/Contents/MacOS/"

# Main launcher script — Finder runs this when the user double-clicks
cat > "$APP_BUNDLE/Contents/MacOS/PIIScrub-launcher" <<'LAUNCHER'
#!/usr/bin/env bash
# Resolve the real directory of this script (handles symlinks)
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec "$DIR/PIIScrub"
LAUNCHER
chmod +x "$APP_BUNDLE/Contents/MacOS/PIIScrub-launcher"

# Info.plist — tells macOS what this app is
# Update CFBundleExecutable to point at our launcher script
sed 's|<string>PIIScrub</string>.*<!-- CFBundleExecutable -->|<string>PIIScrub-launcher</string>|' \
    "$PLIST_SRC" > "$APP_BUNDLE/Contents/Info.plist" 2>/dev/null \
    || cp "$PLIST_SRC" "$APP_BUNDLE/Contents/Info.plist"

# Patch CFBundleExecutable in the copied plist
/usr/libexec/PlistBuddy -c \
    "Set :CFBundleExecutable PIIScrub-launcher" \
    "$APP_BUNDLE/Contents/Info.plist"

echo "==> .app bundle created: $APP_BUNDLE"

# ---------------------------------------------------------------------------
# Build DMG with drag-to-Applications layout
# ---------------------------------------------------------------------------
echo "==> Building DMG: $DMG_PATH"

rm -f "$DMG_PATH"

create-dmg \
    --volname "PIIScrub" \
    --volicon "$APP_BUNDLE/Contents/Resources/AppIcon.icns" 2>/dev/null \
    --window-pos 200 120 \
    --window-size 600 400 \
    --icon-size 100 \
    --icon "${APP_NAME}.app" 150 200 \
    --hide-extension "${APP_NAME}.app" \
    --app-drop-link 430 200 \
    --no-internet-enable \
    "$DMG_PATH" \
    "$APP_BUNDLE" \
    || \
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
    "$APP_BUNDLE"

echo "==> DMG ready: $DMG_PATH"
ls -lh "$DMG_PATH"
