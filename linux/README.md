# Linux Scouter

A local, read-only, EDR-style telemetry collector and live graph for personal Linux
machines. Linux Scouter snapshots the running system — processes and their parent
trees, network connections, persistence surfaces (cron, systemd units/timers, XDG
autostart), local accounts and privileges, remote-access exposure, and security
posture — scores everything with lightweight heuristics tagged with
[MITRE ATT&CK](https://attack.mitre.org/) technique IDs, and serves a force-directed
relationship graph to a self-contained web UI over `127.0.0.1`.

It is built for **personal, defensive use**: understanding what is running on *your own*
machine and spotting the unusual. It is read-only against the system and binds to
loopback only. Local telemetry stays on the machine; the only outbound traffic is
opt-in threat-intel enrichment (VirusTotal lookups and inbound IOC feeds), each of
which is off until you configure it.

Linux Scouter is a port of **Mac Scouter** (the macOS original). The portable core —
graph UI, scoring pipeline, history database, IOC/VirusTotal enrichment, GeoIP, and
detection rules — is shared in design; the OS-touching collector layer is rewritten
against Linux primitives (`/proc`, `systemd`, `dpkg`, `journald`, `/etc`).

## Status

🚧 **Port in progress.** Tracking which subsystems have been moved off macOS primitives:

| Subsystem | macOS source | Linux source | State |
| --- | --- | --- | --- |
| Graph UI / server / history / scoring | — (portable) | — (portable) | ✅ ported |
| IOC feeds / VirusTotal / GeoIP | — (portable) | — (portable) | ✅ ported |
| Processes + parent tree | `ps` | `/proc/<pid>` | ✅ ported |
| Network connections | `lsof -i` | `/proc/net/*` + inode→pid | ✅ ported |
| Binary integrity | `codesign` / `spctl` | dpkg `.list`/`.md5sums` | ✅ ported |
| Persistence | cron + launchd + BTM | cron + systemd + XDG autostart + ld.so.preload | ✅ ported |
| Accounts / privilege | `dscl` + sudoers | `/etc/passwd` + sudo group | ✅ ported |
| Remote access | SSH/ARD/VNC plists | sshd + authorized_keys + VNC/xrdp | ✅ ported |
| Security posture | firewall/SIP/Gatekeeper/FileVault | ufw/AppArmor/Secure Boot/LUKS | ✅ ported |
| Auth telemetry | `last`/`who` + unified log | `last`/`wtmp` + `journalctl` | ✅ ported |
| Downloads (Mark-of-the-Web) | `com.apple.quarantine` xattr | `user.xdg.origin.url` xattr | ✅ ported |
| Shell history collector | bash/zsh | bash/zsh (portable) | ✅ ported |
| Behavioral detection rules | macOS TTPs | Linux TTPs | ✅ ported |
| Automatic response / AI / Velociraptor | native | nftables/systemctl/signals | 🅿️ phase 2 |

Frontend (`index.html`) is functionally compatible — signature badges render the new
`packaged`/`unpackaged`/`modified` categories generically. Some macOS-flavored UI copy
(the now-disabled TCC panel, "keychain" wording) remains as cosmetic follow-up.

## Supported distributions

First-cut target is the **Debian/Ubuntu family** (Ubuntu, Debian, Linux Mint,
Pop!_OS). It expects `systemd`, the `/proc` filesystem, and `dpkg` for package
integrity. Other distributions (Fedora, Arch, openSUSE) are out of scope for the
initial release; their package-verification and MAC stacks differ and are tracked as
follow-up work.

## Requirements

- Python 3.8+ (standard library only — no pip dependencies)
- A `systemd`-based Linux desktop in the Debian/Ubuntu family
- Run as your user for a user-level view, or with `sudo` for full-system visibility

## Usage

```bash
python3 agent.py            # user-level view (your processes/sockets/jobs)
sudo python3 agent.py       # full-system view (all processes, every socket, units)
```

Then open <http://127.0.0.1:8787/>. See `python3 agent.py --help` for the full set of
flags (snapshot interval, per-collector toggles, VirusTotal/IOC configuration).

### Run as a background service (recommended)

For always-on protection, install Scouter as a systemd service. It runs as root, so every sensor has
full visibility; it starts at boot; and systemd restarts it if it ever stops.

```bash
sudo python3 agent.py --install-service    # add --port / --mesh-url to bake them into the service
```

What the installer does, and why:

- **Runs a root-owned copy** at `/opt/scouter/agent`, never your checkout — a root service executing
  code you can edit without a password would be a privilege escalation. Only committed code is
  installed; reinstalling upgrades the service, and never rolls back one that is already newer.
- **Carries over your state and secrets** — baselines, rules, history, Mesh enrollment, quarantine,
  and API keys from your desktop keyring — so nothing re-alerts as new and the Mesh keeps hearing
  from the host. The service reads secrets from a root-only file rather than a keyring, because a
  user's Secret Service keyring only exists inside their login session and isn't there at boot. A
  `--mesh-token` given to the installer goes into that store, never into the unit file, which anyone
  can read with `systemctl cat`.
- **Hands over** from an agent you started by hand, after asking.
- **Checks that every sensor has access** before calling the install done.

The unit deliberately has no `ProtectSystem`/`ProtectHome` sandboxing: the agent's job is to see
the whole host, and sandboxing it would blind the sensors. It requires systemd; on other init
systems, run `python3 agent.py --daemon` under your own supervisor.

Managing the service:

```bash
sudo python3 agent.py --service-status      # running? restarts? is any sensor still limited?
sudo python3 agent.py --restart-service
sudo python3 agent.py --uninstall-service   # stop and remove it; data is kept (--purge deletes it)
journalctl -u scouter-agent -f              # logs (the journal rotates them)
```

Uninstalling refuses to leave containment actions in place unless you pass `--force` — once the agent
is gone, nothing is left to reverse them — and never deletes quarantined files, which are yours.

### Decoys (deception)

Scouter plants **decoys** — bait credentials that no real user or service has a reason to use. Any use
of one is an intrusion signal rather than a judgement call, which is what makes them worth having:
nothing legitimate authenticates with a name that exists nowhere.

Each host gets its own set, generated at install time — its own file names, its own contents and its
own bait username — because the code is public and a fixed layout would be trivial to recognise:

| Decoy | Looks like |
|---|---|
| `~/.aws/credentials-<env>` | an extra AWS profile |
| `~/.ssh/id_rsa_<env>` | a spare private key |
| `~/.kube/config-<env>` | a cluster config with a service user |
| `~/.pgpass-<svc>` | database credentials |
| `~/.ssh/config.<env>` | a saved host entry with a username |

Two things raise alerts:

- **A bait credential is used** — critical. The login logs Scouter already reads are matched against the
  bait names; a failed SSH attempt for a user that does not exist is exactly the signal. Connected to a
  Mesh, each agent also recognises bait planted on *other* hosts, so the alert reads "taken on web-01,
  used here" (T1078, T1110, T1021).
- **A decoy is deleted or edited** — medium. Nothing legitimate touches these files, though a user
  tidying up can cause it (T1070.004).

Rules the planting follows: only ever *new* files (an existing file is never touched), never inside a
synced folder (Dropbox, OneDrive, Nextcloud, Google Drive), owned by the user whose home they sit in and
mode `0600`, with backdated timestamps. Scouter hides its own decoys from the graph, and the registry
that maps them lives in a root-only `decoys.json`.

**On by default.** Turn them off for a host with `--no-decoys`, from the **Decoys** panel in the left
pane, or across a scope from the Mesh's Config tab. Turning them off removes what was planted, and
`--uninstall-service` removes them too.

## Privacy & safety

- **Read-only** against the system in the default Scouting Mode.
- **Loopback only** — the server binds to `127.0.0.1` and is never exposed.
- **No outbound telemetry by default.** VirusTotal is off until you add a key and only
  ever sends SHA-256 hashes / public IPs you have opted to look up. IOC feeds are
  inbound-only (they download indicator lists and send nothing about your machine).

## License

[MIT](LICENSE)
