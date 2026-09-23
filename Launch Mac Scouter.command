#!/bin/bash
# Mac Scouter — double-click this file in Finder to launch, or run it from any
# terminal. If you installed the PATH command (see install.command) you can also
# just type:  scouter
#
# You do NOT need to cd into the project directory: this script locates its own
# folder (following symlinks, so the PATH command works too), runs the agent from
# there so all data files resolve correctly, and elevates to root for full
# system visibility. Any extra arguments are passed through to agent.py.

# --- resolve this script's real directory, even when invoked via a symlink ---
SOURCE="${BASH_SOURCE[0]}"
while [ -h "$SOURCE" ]; do
  SDIR="$(cd -P "$(dirname "$SOURCE")" && pwd)"
  SOURCE="$(readlink "$SOURCE")"
  [ "${SOURCE#/}" = "$SOURCE" ] && SOURCE="$SDIR/$SOURCE"   # relative link → make absolute
done
DIR="$(cd -P "$(dirname "$SOURCE")" && pwd)"

cd "$DIR" || { echo "Can't enter Mac Scouter directory: $DIR"; read -r -n1 -p "Press any key to close… "; exit 1; }
if [ ! -f agent.py ]; then
  echo "agent.py not found in $DIR — is this the Mac Scouter folder?"; read -r -n1 -p "Press any key to close… "; exit 1
fi

# If Scouter is installed as a background service, just open it — never start a second agent that
# would fight the service for the port. Any arguments (e.g. --service-status) still go to agent.py.
SERVICE_PLIST="/Library/LaunchDaemons/com.scouter.agent.plist"
if [ $# -eq 0 ] && [ -f "$SERVICE_PLIST" ]; then
  PORT=$(python3 -c 'import plistlib,sys
a=plistlib.load(open(sys.argv[1],"rb"))["ProgramArguments"]
print(a[a.index("--port")+1] if "--port" in a else 8787)' "$SERVICE_PLIST" 2>/dev/null || echo 8787)
  if curl -fsS -m 3 "http://127.0.0.1:$PORT/api/sensors" >/dev/null 2>&1; then
    echo "▶ Scouter is running as a background service — opening http://127.0.0.1:$PORT/"
    open "http://127.0.0.1:$PORT/"
    exit 0
  fi
  echo "▶ Scouter's background service is installed but not answering on port $PORT."
  echo "  Restarting it (you may be asked for your password)…"
  if sudo python3 agent.py --restart-service; then open "http://127.0.0.1:$PORT/"; fi
  exit $?
fi

echo "▶ Launching Mac Scouter from: $DIR"
if [ "$(id -u)" -ne 0 ]; then
  echo "  Requesting administrator access for full system visibility (Ctrl-C to stop the agent later)…"
  exec sudo python3 agent.py "$@"
else
  exec python3 agent.py "$@"
fi
