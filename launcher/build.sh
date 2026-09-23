#!/bin/bash
# Build launcher/ScouterAgent.app — the process macOS charges the background service's Full Disk
# Access to (see scouter-launcher.c for why it exists and why it is so inflexible).
#
#   launcher/build.sh                                   ad-hoc signed (what the repository ships)
#   SIGN_IDENTITY="Developer ID Application: …" launcher/build.sh
#
# Ad-hoc signing gives the launcher an identity tied to this exact build, so a rebuilt launcher needs
# Full Disk Access granted again and a new MDM profile. A Developer ID signature gives it a stable
# identity (bundle id + team) that survives rebuilds — use one before shipping to customers.
#
# OUT and EXTRA_CFLAGS exist for the test suite (a separately-named test build); leave them unset.
set -euo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APP="${OUT:-$DIR/ScouterAgent.app}"
IDENTITY="${SIGN_IDENTITY:--}"
BUNDLE_ID="com.scouter.agent.launcher"

rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS"
cp "$DIR/Info.plist" "$APP/Contents/Info.plist"
plutil -lint "$APP/Contents/Info.plist" >/dev/null

# Universal, so the same bundle runs on Apple silicon and Intel. Warnings are errors: this is a
# small, security-sensitive program and should compile cleanly.
clang -std=c11 -O2 -Wall -Wextra -Werror -arch arm64 -arch x86_64 -mmacosx-version-min=11.0 \
      ${EXTRA_CFLAGS:-} -o "$APP/Contents/MacOS/scouter-agent" "$DIR/scouter-launcher.c"

sign=(codesign --force --options runtime --identifier "$BUNDLE_ID" --sign "$IDENTITY")
[ "$IDENTITY" = "-" ] || sign+=(--timestamp)          # notarization needs a secure timestamp
"${sign[@]}" "$APP"
codesign --verify --strict --verbose=1 "$APP"

echo "built: $APP"
echo "archs: $(lipo -archs "$APP/Contents/MacOS/scouter-agent")"
codesign -dv "$APP" 2>&1 | grep -E '^(Identifier|Signature|TeamIdentifier|CDHash)=' | sed 's/^/  /'
