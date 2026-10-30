#!/usr/bin/env bash
# Build store-ready zips for Chrome and Firefox from the runtime files only (no test/, demo/, tools/,
# README or the other platform's manifest). Output lands in extension/dist/.
#   ./tools/pack.sh
set -euo pipefail
cd "$(dirname "$0")/.."

VER=$(python3 -c "import json;print(json.load(open('manifest.json'))['version'])")
RUNTIME=(inject.js content.js background.js popup.html popup.js options.html options.js welcome.html icons)
OUT=dist
rm -rf "$OUT"
mkdir -p "$OUT/chrome" "$OUT/firefox"

for t in chrome firefox; do
  for f in "${RUNTIME[@]}"; do cp -R "$f" "$OUT/$t/"; done
done
cp manifest.json         "$OUT/chrome/manifest.json"
cp manifest.firefox.json "$OUT/firefox/manifest.json"     # Firefox uses its manifest AS manifest.json

( cd "$OUT/chrome"  && zip -qr "../scouter-browser-defense-chrome-$VER.zip"  . )
( cd "$OUT/firefox" && zip -qr "../scouter-browser-defense-firefox-$VER.zip" . )

echo "built:"
ls -1 "$OUT"/*.zip
echo
echo "Chrome:  upload dist/scouter-browser-defense-chrome-$VER.zip to the Chrome Web Store dashboard."
echo "Firefox: upload dist/scouter-browser-defense-firefox-$VER.zip to AMO (or: web-ext sign)."
