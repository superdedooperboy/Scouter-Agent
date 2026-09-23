#!/bin/bash
# Mac Scouter — installer.
#   1. Offers to install Scouter as a BACKGROUND SERVICE (recommended): runs as root so every sensor
#      has full visibility, starts at boot, restarts itself if it stops. No terminal to keep open.
#   2. Adds "scouter" (and "scouter-mesh") commands to your PATH. With the service installed,
#      "scouter" simply opens its UI.
#
# Double-click in Finder, or run:   ./install.command
# Remove them again with:           ./install.command --uninstall
#
# No hardcoded paths: it links to the launcher in THIS folder, wherever that is.

set -u

# --- resolve this script's real directory (follow symlinks) ---
SOURCE="${BASH_SOURCE[0]}"
while [ -h "$SOURCE" ]; do
  SDIR="$(cd -P "$(dirname "$SOURCE")" && pwd)"
  SOURCE="$(readlink "$SOURCE")"
  [ "${SOURCE#/}" = "$SOURCE" ] && SOURCE="$SDIR/$SOURCE"
done
DIR="$(cd -P "$(dirname "$SOURCE")" && pwd)"
LAUNCHER="$DIR/Launch Mac Scouter.command"
CMD="scouter"

echo "Mac Scouter installer"
echo "  tool folder: $DIR"

if [ ! -f "$LAUNCHER" ]; then
  echo "  ✗ launcher not found: $LAUNCHER"; exit 1
fi
chmod +x "$LAUNCHER" 2>/dev/null || true
[ -f "$MESH" ] && chmod +x "$MESH" 2>/dev/null || true

# --- uninstall (both commands, across every common bin dir) ---
if [ "${1:-}" = "--uninstall" ]; then
  removed=0
  for d in /usr/local/bin /opt/homebrew/bin "$HOME/.local/bin" "$HOME/bin"; do
    for cmd in "$CMD" "$MESHCMD"; do
      if [ -L "$d/$cmd" ] || [ -e "$d/$cmd" ]; then
        if [ -w "$d" ]; then rm -f "$d/$cmd"; else sudo rm -f "$d/$cmd"; fi
        if [ ! -e "$d/$cmd" ] && [ ! -L "$d/$cmd" ]; then echo "  removed $d/$cmd"; removed=1
        else echo "  ✗ could not remove $d/$cmd  (try: sudo rm -f \"$d/$cmd\")"; fi
      fi
    done
  done
  [ "$removed" = 0 ] && echo "  nothing to remove."
  if [ -f /Library/LaunchDaemons/com.scouter.agent.plist ]; then
    printf "Also remove Scouter's background service? Your data is kept. [y/N] "
    read -r ans
    case "${ans:-N}" in [Yy]*) sudo python3 "$DIR/agent.py" --uninstall-service ;; esac
  fi
  exit 0
fi

# --- background service (recommended) ---
if [ "$(uname)" = "Darwin" ] && [ -f "$DIR/agent.py" ]; then
  echo
  if [ -f /Library/LaunchDaemons/com.scouter.agent.plist ]; then
    printf "Scouter's background service is installed. Upgrade it to this folder's version? [Y/n] "
  else
    echo "Recommended: install Scouter as a background service."
    echo "  • runs as root, so every sensor has full visibility"
    echo "  • starts automatically at boot, and restarts itself if it ever stops"
    echo "  • nothing to keep open — just type 'scouter' or visit http://127.0.0.1:8787/"
    printf "Install the background service now? (asks for your password) [Y/n] "
  fi
  read -r ans
  case "${ans:-Y}" in
    [Nn]*) echo "  skipped — install it any time with:  sudo python3 \"$DIR/agent.py\" --install-service" ;;
    *) sudo python3 "$DIR/agent.py" --install-service || echo "  ✗ the service install did not finish — see the messages above." ;;
  esac
  echo
fi

# --- already installed? ---
if command -v "$CMD" >/dev/null 2>&1; then
  echo "  ✓ '$CMD' is already on your PATH → $(command -v "$CMD")"
  printf "  Reinstall / repoint it to this folder? [y/N] "; read -r ans
  case "${ans:-N}" in [Yy]*) : ;; *) echo "  left as-is."; exit 0 ;; esac
fi

printf "Add '%s' and '%s' commands to your PATH so you can launch from any terminal? [Y/n] " "$CMD" "$MESHCMD"
read -r ans
case "${ans:-Y}" in [Nn]*) echo "Skipped — you can still double-click 'Launch Mac Scouter.command'."; exit 0 ;; esac

link_into() {
  ln -sf "$LAUNCHER" "$1/$CMD" && echo "  ✓ installed: $1/$CMD"
}

# 1) /usr/local/bin if we can write it (directly or via sudo)
if { [ -d /usr/local/bin ] && [ -w /usr/local/bin ]; } || mkdir -p /usr/local/bin 2>/dev/null; then
  if [ -w /usr/local/bin ]; then
    link_into /usr/local/bin; echo "Done. Open a new terminal (or now) and run:  $CMD   ·   aggregator:  $MESHCMD"; exit 0
  fi
fi
if command -v sudo >/dev/null 2>&1; then
  echo "  /usr/local/bin needs admin rights — you may be prompted for your password."
  if sudo mkdir -p /usr/local/bin && sudo ln -sf "$LAUNCHER" "/usr/local/bin/$CMD"; then
    echo "  ✓ installed: /usr/local/bin/$CMD (via sudo)"
    if [ -f "$MESH" ]; then sudo ln -sf "$MESH" "/usr/local/bin/$MESHCMD" && echo "  ✓ installed: /usr/local/bin/$MESHCMD (via sudo)"; fi
    echo "Done. Run:  $CMD   ·   aggregator:  $MESHCMD"; exit 0
  fi
  echo "  (sudo declined or failed — falling back to a per-user location)"
fi

# 2) per-user fallback: ~/.local/bin, add to PATH if needed
BIN="$HOME/.local/bin"; mkdir -p "$BIN"; link_into "$BIN"
case ":$PATH:" in
  *":$BIN:"*) ;;
  *)
    case "$(basename "${SHELL:-/bin/zsh}")" in       # the user's LOGIN shell, not this script's
      zsh)  rc="$HOME/.zshrc" ;;
      bash) rc="$HOME/.bashrc" ;;
      *)    rc="$HOME/.profile" ;;
    esac
    line='export PATH="$HOME/.local/bin:$PATH"'
    grep -qsF "$line" "$rc" 2>/dev/null || printf '\n# added by Mac Scouter installer\n%s\n' "$line" >> "$rc"
    echo "  ✓ added ~/.local/bin to PATH in $rc"
    echo "Open a NEW terminal, then run:  $CMD   ·   aggregator:  $MESHCMD"
    exit 0
    ;;
esac
echo "Done. Run:  $CMD   ·   aggregator:  $MESHCMD"
