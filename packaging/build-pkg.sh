#!/bin/bash
# Build a macOS installer package (.pkg) for the Scouter endpoint agent, for MDM mass-deployment.
#
# An MDM (Jamf Pro, Kandji, Microsoft Intune, Mosyle, …) pushes a .pkg — it does not run
# `sudo python3 agent.py --install-service` on each Mac. This script produces that .pkg. The package
# lays the agent's code under /Library/Application Support/Scouter/agent-install and its postinstall
# runs the SAME, already-vetted installer (`agent.py --install-service --yes`): it copies the code to
# its service directory, builds the Full Disk Access launcher, writes the LaunchDaemon, generates the
# MDM Full-Disk-Access profile, and starts the service. Nothing here duplicates that logic.
#
# Full Disk Access still cannot be granted by an installer — Apple reserves it for the user or an MDM
# profile. Push the generated Scouter-FullDiskAccess.mobileconfig alongside this .pkg (see README.md).
#
# USAGE
#   packaging/build-pkg.sh                       # unsigned component .pkg (local testing only)
#   APP_IDENTITY="Developer ID Application: Your Co (TEAMID)" \
#   INSTALLER_IDENTITY="Developer ID Installer: Your Co (TEAMID)" \
#   NOTARY_PROFILE="scouter-notary" \
#     packaging/build-pkg.sh                     # signed + notarized (release / production MDM)
#
# ENV
#   APP_IDENTITY        Developer ID Application identity — signs the launcher (stable FDA identity).
#   INSTALLER_IDENTITY  Developer ID Installer identity — signs the .pkg (required for notarization).
#   NOTARY_PROFILE      `xcrun notarytool` keychain profile; set to notarize + staple the .pkg.
#   OUT_DIR             where to write the .pkg (default: packaging/dist).
#
# An UNSIGNED package installs only where Gatekeeper is told to allow it (a test Mac, or an MDM that
# installs unsigned packages). Ship a signed + notarized package to production — that is the 2nd pass
# once you have an Apple Developer ID (see README.md → "Signing and notarization").
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/.." && pwd)"
OUT_DIR="${OUT_DIR:-$HERE/dist}"

PKG_ID="com.scouter.agent.pkg"
INSTALL_ROOT="/Library/Application Support/Scouter/agent-install"   # where the payload lands
VERSION="$(sed -n 's/^__version__ = "\(.*\)".*/\1/p' "$REPO/agent.py" | head -1)"
[ -n "$VERSION" ] || { echo "could not read __version__ from agent.py" >&2; exit 1; }

BUILD="$(mktemp -d /tmp/scouter-pkg.XXXXXX)"
trap 'rm -rf "$BUILD"' EXIT
PAYLOAD="$BUILD/payload"
STAGE="$PAYLOAD$INSTALL_ROOT"
mkdir -p "$STAGE" "$OUT_DIR"

echo "Scouter agent packaging — v$VERSION"

# 1) Stage the agent code. Ship the program and its data templates; never the local host's runtime
#    state, caches, secrets, logs or VCS metadata (those are per-host and some are sensitive).
echo "  • staging code → $INSTALL_ROOT"
_copy() { [ -e "$REPO/$1" ] && cp -R "$REPO/$1" "$STAGE/$1"; }
# Program + console + the committed detection/data templates the agent reads on first run.
for item in agent.py index.html linux launcher extension docs \
            attack-data.json builtins-macos.json builtins-linux.json \
            collectors-macos.json collectors-linux.json \
            alert-lifecycle.json agent-access-policy.example.json \
            README.md LICENSE NOTICE CHANGELOG.md SECURITY.md; do
  _copy "$item"
done
# Belt-and-braces: never let a host-specific or secret file ride along even if copied by a glob above.
find "$STAGE" \( -name '*.log' -o -name '*-cache.json' -o -name '*-baseline.json' \
     -o -name 'ext-token.json' -o -name 'mesh-settings.json' -o -name 'decoys.json' \
     -o -name 'incidents.json' -o -name 'ia-cache.json' -o -name '*.db' \
     -o -name '__pycache__' -o -name '.DS_Store' \) -prune -exec rm -rf {} + 2>/dev/null || true

# 2) Build the Full Disk Access launcher. A Developer ID signature gives it a STABLE identity, so the
#    MDM FDA profile survives agent updates; ad-hoc (unsigned) ties the profile to this exact build.
echo "  • building launcher$([ -n "${APP_IDENTITY:-}" ] && echo " (Developer ID signed)" || echo " (ad-hoc)")"
if [ -n "${APP_IDENTITY:-}" ]; then
  SIGN_IDENTITY="$APP_IDENTITY" OUT="$STAGE/launcher/ScouterAgent.app" "$REPO/launcher/build.sh" >/dev/null
else
  OUT="$STAGE/launcher/ScouterAgent.app" "$REPO/launcher/build.sh" >/dev/null
fi

# 3) The postinstall that runs the real installer on each managed Mac.
SCRIPTS="$BUILD/scripts"
mkdir -p "$SCRIPTS"
cp "$HERE/scripts/postinstall" "$SCRIPTS/postinstall"
chmod 0755 "$SCRIPTS/postinstall"

# 4) Build the component package. (The payload may carry ._AppleDouble sidecars for files with
#    extended attributes; `installer` strips them on extraction, so they never reach the target — a
#    normal, harmless artifact of macOS packaging.)
RAW="$BUILD/Scouter-Agent-$VERSION-unsigned.pkg"
echo "  • pkgbuild"
pkgbuild --root "$PAYLOAD" --scripts "$SCRIPTS" \
         --identifier "$PKG_ID" --version "$VERSION" \
         --install-location "/" "$RAW" >/dev/null

FINAL="$OUT_DIR/Scouter-Agent-$VERSION.pkg"
if [ -n "${INSTALLER_IDENTITY:-}" ]; then
  echo "  • productsign (Developer ID Installer)"
  productsign --sign "$INSTALLER_IDENTITY" "$RAW" "$FINAL" >/dev/null
  if [ -n "${NOTARY_PROFILE:-}" ]; then
    echo "  • notarytool submit + staple"
    xcrun notarytool submit "$FINAL" --keychain-profile "$NOTARY_PROFILE" --wait
    xcrun stapler staple "$FINAL"
  else
    echo "  ! signed but NOT notarized — set NOTARY_PROFILE to notarize (required for production)."
  fi
else
  cp "$RAW" "$FINAL"
  echo "  ! UNSIGNED package — test only. Set APP_IDENTITY + INSTALLER_IDENTITY (+ NOTARY_PROFILE)."
fi

echo "built: $FINAL"
pkgutil --check-signature "$FINAL" 2>/dev/null | sed 's/^/  /' || true
echo
echo "Next: push this .pkg AND the Full Disk Access profile through your MDM — see packaging/README.md."
