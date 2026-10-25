# Changelog

All notable changes to Scouter are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/). This repository ships the macOS and Linux
agents, versioned independently.

## [Unreleased]

## macOS agent 1.11.0 / Linux agent 1.11.0 — 2026-10-25

### Added

**Webshell content scanner (T1505.003), both platforms.** A new read-only collector that reads file
*contents* and flags webshells across PHP, JSP (Java), ASP/ASPX (.NET + classic), Perl/CGI and
Python-CGI. It scans two kinds of location with a different bar in each, so it stays near-zero-FP:

- **Drop zones** — PHP session dirs, `/tmp`, `/var/tmp`, `/dev/shm` (places a web script should never
  live): the *loose* bar. A **session file** (`sess_*`) holding script code is the php2shell
  `PHP_SESSION_UPLOAD_PROGRESS` drop → **CRITICAL**. Code + a command/eval sink in a **non-script
  file** (a `.txt`, an image, a log) is a disguised shell → **HIGH**.
- **Webroots** — `/Library/WebServer/Documents`, `/var/www`, `/srv/www`, `~/Sites`, `~/public_html`,
  the Homebrew/MAMP/XAMPP/nginx docroots, etc. (where scripts live legitimately): the *strict* bar
  only. A framework's ordinary `system()` / `eval()` does **not** fire — only the shapes that are
  rare-to-nonexistent in real code: attacker input (a superglobal / request param) passed straight
  into a command/eval sink, a superglobal called as a function (`$_GET['f'](…)`), a variable function
  called on a superglobal (`$fn($_GET[…])`), obfuscated `eval(base64_decode(…))`, the `preg_replace
  /e` trick, and the JSP/ASP/Perl/Python equivalents → **CRITICAL**.
- **Obfuscated code execution** (the PHP shells that hide their sink entirely): a code-exec call next
  to a packed base64/compressed payload, a `chr()`-assembled string, a nested decoder chain, or an
  obfuscated superglobal (`${'_GET'}`, `$$var`) → **CRITICAL**. Each path requires a real `eval` /
  `assert` / `create_function` beside the obfuscation, so a file that merely embeds a base64 blob (a
  font, an image, a cert) does not trip it.

Plus a curated set of **named-shell signatures** (c99, r57, WSO, b374k, FilesMan, China Chopper
`@eval($_POST…)`, GIF/PHP polyglot headers, reversed/nested decoders) that flag **CRITICAL** in any
zone or language. A real application file and benign serialized session data are deliberately not
flagged. Bounded throughout: file-size and per-pass caps, a webroot walk capped by depth that skips
`.git`/`node_modules` and reads non-script files only when recently modified. Each file is read as a
128 KB head **plus** a 64 KB tail on larger files, so a shell appended after a benign image is still
caught. A finding is kept ~24h for triage even if the attacker deletes the file. Flags:
`--no-webshell-scan`, `--webshell-interval`, `--webshell-dir` (extra drop dir), `--webshell-webroot`
(extra docroot). Surfaces as a file node carrying language, zone, confidence, matched sinks and any
signature markers; no new rules/builtins, no Mesh change.

**Anti-forensics detection — forensic-store wipes (T1070 / T1562).** Two new high-confidence built-in
rules close the FSEvents anti-forensics gap and its Linux analog:
- macOS `b-forensic-wipe`: flags deleting or clearing a macOS forensic store — the FSEvents
  filesystem-change log (`/.fseventsd`), the unified-log backing store (`/var/db/diagnostics`,
  `/var/db/uuidtext`), the download-provenance DB (`QuarantineEventsV2`) or the privacy-permission DB
  (`TCC.db`). Nothing legitimate removes these; `tccutil reset` (the supported way to reset
  permissions) is deliberately not matched.
- Linux `b-audit-tamper`: flags `auditctl -D` (flush all audit rules) / `auditctl -e 0` (disable
  auditing while auditd keeps running) and deletion of `/var/log/audit/`.

Both rated confidence 4 (near-zero FP). No Mesh change — new rules propagate through the factory
rule-library seed.

**VQL (Velociraptor) twins for the auto-hunts and advisory hunts.** Both hunt families were
SQL-only — they query Scouter's recorded history. Each now also carries a VQL query that hunts the
**live** system through Velociraptor's own plugins (`pslist()`, `netstat()`, `glob()`+`hash()`), the
complementary lens: the SQL asks "where has this been seen", the VQL asks "is it here / running now".
- Advisory hunts (PHP2Shell, LiteLLM): every hunt gets a hand-written VQL twin; the Hunt-tab panel now
  shows a **▶ SQL** and a **🦖 VQL** button per hunt (VQL runs locally via the existing Velociraptor
  runner).
- Auto-hunts (raised when an alert is validated malicious): a new `autohunt_vql(kind, value)` mirrors
  `autohunt_sql` for every indicator kind (hash / ip / domain / url / cmdline / path), and the VQL is
  stored on each hunt record alongside the SQL. IOC values are regex- and string-escaped so an
  attacker-controlled value can't break out of the VQL literal.
  (Fleet-wide VQL in the Mesh console — `foreach(clients())` — is a separate follow-up.)

**Automatic-login detection (both platforms).** A new standing-state Security-posture check flags a
host configured for automatic login — it boots straight into a session with no password prompt
(T1552.001 / weak physical-access posture). macOS reads `autoLoginUser` and `/etc/kcpassword` (where
the login password is stored only XOR-obfuscated, recoverable by anyone who can read it). Linux reads
GDM / LightDM / SDDM and systemd getty console-autologin configs (commented defaults don't trip it).
Surfaces as a ⚙ Security-posture finding and in `meta.config`.

**Download provenance from the system quarantine log (macOS).** The provenance collector now
change-detects new entries in each user's `QuarantineEventsV2` database (a third `provenance`
category, `download`). It surfaces the download events the Downloads-folder watcher can't: a file
fetched by a **non-browser process** (curl / osascript / Terminal / a script — classic malware
staging), or an executable/installer/archive pulled from a **raw-code / paste / IP-literal** source.
Ordinary browser downloads of documents and images stay silent `info`; the stable per-event id is the
baseline key, so re-reads never churn. (No Linux equivalent — Linux has no system quarantine log.)

## macOS agent 1.10.1 / Linux agent 1.10.1 — 2026-10-23

### Fixed

**"Check for updates" button returned a stale answer.** The update check only ran on a 24h timer, and
both the `/api/update` endpoint and the version-pill click returned the *cached* result — so after
upgrading (e.g. to 1.9.3 while `main` was at 1.9.3), a version pushed within the next 24h read as "up
to date" no matter how many times the button was clicked. The button now forces a fresh check:
`/api/update?refresh=1` re-queries GitHub synchronously (bounded 10s timeout; last good state kept on
failure), and the UI click calls it and shows the result (or an "update available" banner even if a
prior banner was dismissed). This completes the 1.9.2 source-version fix, which was correct but only
took effect when a check actually ran.

Note: an agent still on ≤1.10.0 won't have the button fix until it updates. To unstick one now, delete
its `update-check.json` (next to the agent) and restart — that clears the cache so the next background
check (which already reads `main`) sees the new version.

## Linux agent 1.10.0 — 2026-10-23

### Added

**Provenance collector — Linux parity.** The counterpart to the macOS provenance collector, with
Linux-native sources, same `provenance` node type (📦 "Installs & Media"), and the same near-zero-FP,
baseline-diff + 24h TTL model. `--no-provenance` / `--provenance-interval` (default 600s).

- **Install history (T1195).** Change-detects installed packages via dpkg/rpm/apk (reusing the
  software-inventory parsers), enriched best-effort from `/var/log/dpkg.log`. Keyed on package **name**,
  so routine `apt upgrade` version bumps stay silent and only genuinely new software surfaces.
- **Volume mounts (T1052 / T1091 / T1021).** Reads `/proc/mounts` and classifies via `lsblk` (USB /
  removable) and `losetup` (loop-backed disk images), plus network filesystems. A disk image mounted
  from a Downloads/tmp path is elevated; snap squashfs loop mounts, pseudo filesystems and internal
  fixed disks are ignored.

No new rules/builtins, no network indicators, no Mesh change. (macOS shipped this in its own 1.10.0.)

## macOS agent 1.10.0 — 2026-10-23

### Added

**Provenance collector — install history and removable/disk-image/network mounts.** A new read-only
collector (`--no-provenance` / `--provenance-interval`, default 600s) closes two FOR518 gaps the
cron/launchd and FIM walks miss, surfaced as a new `provenance` node type (📦 "Installs & Media" in the
tree, filters, graph, health card, and the rule editor):

- **Install receipts (T1195).** Change-detects installer-package receipts via `pkgutil`, enriched
  best-effort from `/var/log/install.log`. A newly-appearing third-party receipt surfaces once; Apple
  OS-update receipts stay silent `info` unless the package installs from a user/temporary location.
- **Volume mounts (T1052 / T1091 / T1021).** Change-detects volumes mounting under `/Volumes` via
  `mount` + `diskutil` + `hdiutil`, classified as USB/removable, disk image (DMG), or network share. A
  DMG mounted from Downloads/tmp — the usual macOS malware lure — is elevated; internal fixed volumes
  are ignored.

Baseline-diff like persistence: what is present on first run is silent, a new receipt or mount flags
once and ages out after 24h. Calibrated for near-zero FP — benign OS installs and internal volumes are
silent. No new network indicators. (macOS only this release; a Linux equivalent is separate work.)

## macOS agent 1.9.4 / Linux agent 1.9.4 — 2026-10-23

### Changed

**`b-lin-server-shell` now covers the Node runtime family (node, deno, bun).** A shell spawned by an
internet-facing service is one of the highest-fidelity RCE/webshell signals there is, but the two
agents' ancestry lists had drifted — macOS already listed `node`, Linux did not, which is backwards
from where Node web apps actually run. Both agents now include `node`, `deno` and `bun`, so a Node app
RCE that lands a shell — Node2Shell (CVE-2026-111497, the out-of-bounds write in Node's bundled Brotli
decoder) or any other — is caught exactly as a PHP2Shell shell is. The exploit itself is in-process
memory corruption with no host-level IOCs; this catches the post-exploitation shell. No new collector,
no network indicators. The Mesh refreshes the broadened rule automatically on its next reconcile via
the stored `factory_sig` (unedited copies only; operator-tuned rules are left alone).

## macOS agent 1.9.3 / Linux agent 1.9.3 — 2026-10-22

### Fixed

**Investigation storm: the correlator minted a new investigation every snapshot for recurring
activity.** `reconcile()` re-identified an incident by its member node ids, but those ids are
ephemeral by construction — a `proc:<pid>` dies with each short-lived exec, and a
`listen:<pid>:<proto>:<addr>:<port>` carries a port that rotates on every rebind. So a cluster that
recurred each ~3s snapshot (a daemon rebinding dynamic ports, a parent respawning children) shared
zero members between snapshots, reconcile saw a brand-new cluster, and it created a fresh
investigation every cycle — hundreds per hour, pruned only after seven days. An incident now carries
a **stable signature derived from the correlation keys that actually tie the cluster** (root process,
file hash, public IP, URL, run payload, path) rather than from the volatile member ids, and reconcile
matches on that first (member overlap remains the fallback). The same recurring cluster now stays a
single investigation, and closing it sticks.

**Listeners on ephemeral/dynamic ports were raised as network-reachable alerts.** A process listening
on `0.0.0.0` on a dynamic port (≥ 49152) scored a full 40-point "reachable from the network" alert,
so daemons that rebind dynamic ports constantly (NordVPN's content filter, browser helpers) produced
an endless stream of them and fed the storm above. Such a bind is now informational (weight 0); a
listener on a real service port still alerts.

**`argv[0]` ≠ executable (T1036 masquerade) fired on legitimately-signed/packaged binaries.** Updaters
(GoogleUpdater), Electron/Chrome helpers and multi-call tool launchers routinely set their own
`argv[0]`. The mismatch is now a signal only when the binary is **not** validly signed (macOS:
apple/developer-id) or **not** from an intact installed package (Linux: dpkg-verified) — where a
renamed-to-hide binary actually lives.

## macOS agent 1.9.2 / Linux agent 1.9.2 — 2026-10-22

### Fixed

**Break-glass command broke on a spaced install path.** The copyable `sudo … --break-glass` line from
the console embedded the interpreter and script paths unquoted, so a macOS install under
`/Library/Application Support/Scouter/` split at the space in "Application Support" and the command
failed. The paths are now shell-quoted (`shlex.quote`), so the line pastes and runs as-is; a path with
no spaces is left unquoted.

**"Check for updates" reported up to date when a newer version was out.** The update check compared the
running version only against tagged **GitHub releases**, but versions ship as pushed commits that bump
`__version__` on `main` (releases are cut rarely), so the newest release it could see (`*-v1.0.0`) was
older than a running 1.9.x and it always said "up to date." The check now reads the authoritative
version straight from `__version__` on the release branch, so a newer version is surfaced the moment it
lands; a matching tagged release, when one exists, still enriches the notice with its notes and link,
and otherwise the notice links to the repository.

## macOS agent 1.9.1 / Linux agent 1.9.1 — 2026-10-22

### Fixed

**KEV hunt panel "on host" false positives.** The "Hunt from recent KEV" panel marked a CVE as present
on this host using a loose two-way substring test, so a keyword like "networks" (from a PAN-OS entry)
matched a host's "network" token, and "plex" matched inside "complex"/"duplex" — flagging software that
isn't installed. It now matches the keyword against the host's **whole words**, and the keyword
extractor drops "networks"/"media" so Plex derives the real keyword (`plex`) instead of `media`.

## macOS agent 1.9.0 / Linux agent 1.9.0 — 2026-10-21

### Added

**Clearable advisory hunts, pinned to the top of the Hunt tab.** A new panel surfaces curated,
ready-to-run hunts for specific emerging threats at the top of the Threat Hunt tab. An operator runs
any hunt on demand, and can **clear** an advisory they don't need — the dismissal persists per host,
and cleared advisories can be restored. Ships with two advisories (below). Code-maintained set
(`ADVISORY_HUNTS`); new `GET`/`POST /api/advisory-hunts`.

**Coverage for two current, high-profile threats:**

- **PHP2Shell (CVE-2026-109618 / CVE-2026-109619)** — critical unauthenticated RCE in PHP ≤ 8.5.11.
  *Vulnerability coverage:* built-in advisories flag a vulnerable Homebrew PHP (per-branch ranges, so
  8.5.12 / 8.4.27 / 8.3.36 / 8.2.35 read as patched). *Detection:* the critical `b-lin-server-shell`
  rule (a web worker spawning a shell) now covers the full PHP worker set — php-fpm, php-cgi,
  FrankenPHP, LiteSpeed, and mod_php via apache — so a PHP2Shell RCE that lands a shell is caught.
  *Hunts:* find PHP web workers, find a worker that spawned a shell, find outbound from workers.
  (Linux distro PHP is covered by the detection, hunts and apt-currency rather than a version
  advisory, since distros backport the fix without changing the upstream version.)
- **LiteLLM 1.107.0 PyPI supply-chain backdoor** — *Vulnerability coverage:* a built-in
  malicious-package advisory flags an installed `litellm==1.107.0` (pip/npm/gem packages are now
  matched against the advisory feed too, not just OSV). *Detection:* new `b-litellm-c2` (C2
  indicators — the GitHub dead-drop, `/codepy`, the lock file, the lookalike `www.litellm.dev`) and
  `b-litellm-artifact` (the `/tmp/remote_code_loader.lock` marker, `cook.pth`). *Hunts:* find
  processes that loaded litellm, find the on-disk artifacts, find C2/loader indicators.

Both agents. The Mesh console gets the fleet-facing versions of these in a follow-up.

## macOS agent 1.8.1 / Linux agent 1.8.1 — 2026-10-20

### Fixed

**KEV threat-hunt keyword extraction.** The query generator picked the longest word from a KEV entry's
product name, which for real CISA-KEV entries produced over-broad, near-useless hunts — "SMA1000
Appliances" became a hunt for `appliances`, "Remote Support" for `support`, "Secure Email Gateway" for
`secure`. It now gathers candidates from the product, name and vendor, drops generic infrastructure and
vulnerability-description words, and prefers a specific model/version token (one carrying a digit, like
`sma1000` or `log4j2`) before the longest — so "SMA1000 Appliances" hunts `sma1000`, and an entry with
no specific token (e.g. "Windows") correctly yields no auto-hunt rather than a junk one.

## macOS agent 1.8.0 / Linux agent 1.8.0 — 2026-10-20

### Added

**Alerts are now cross-referenced with vulnerability data, and re-prioritized by it.** When an alert
fires on a process, Scouter ties the process's binary back to any vulnerable software on the host and
carries it on the alert — the implicated component(s), their CVEs, and whether any is known-exploited
(KEV). The alert gains an **effective severity**: the worst of its own severity and the
vulnerability's, with a KEV floor (known-exploited → at least high; ransomware-linked → at least
critical). A flaw being exploited in the wild outranks a theoretical score, so a "medium" behavioural
alert on a process running KEV software rises to the top of the queue. The detection's **base severity
is preserved** (shown as "↑base") and stays authoritative for surfacing and auto-response — a
vulnerability cross-reference re-prioritizes triage, it never by itself creates an alert or triggers
containment. The alert list sorts and badges by effective severity (🛑 for KEV, ⚠ for vulnerable), the
detail panel shows the implicated components, and the effective severity rides the fleet check-in so
the Mesh orders by it too.

**Pre-built threat hunts from recently-exploited CVEs.** The KEV feed is now read for CVEs added in the
last 14 days and, where a usable product keyword can be derived, turns each into a ready-to-run,
read-only hunt query over this host's process and execution history. They surface in two places: a
**"Hunt from recent KEV"** panel in the Threat Hunt tab (queries whose software is present on this host
are marked "on host" and sorted first, ransomware-linked next), and a **"▶ Hunt for this"** button on
recent-KEV findings in the Vulnerabilities tab. New `GET /api/kev-hunts`. The KEV feed now also captures
each entry's vendor/product.

## macOS agent 1.7.0 / Linux agent 1.7.0 — 2026-10-19

### Added

**Exploitation-aware prioritization (KEV).** Vulnerability findings are now ranked by whether the CVE is
**known exploited in the wild**, not just by CVSS — an exploited "medium" outranks a theoretical
"critical". A new `KevFeed` pulls the **VulnCheck KEV** catalogue daily (community-tier API token, a
superset of CISA KEV that carries exploitation evidence) and, with no token, falls back to the free
**CISA KEV** — either way the full set is downloaded once a day and matched entirely locally (nothing
about the inventory leaves the host). KEV flags apply to **both internal findings** (OS currency,
inventory/OSV, advisory feed) **and external ones** (the Shodan attack-surface CVEs): each exploited CVE
shows a **🛑 KEV** badge (with a ransomware note where applicable), floats to the top of its list, adds a
"known exploited" tile, and — new in this release — **raises an EDR alert regardless of CVSS**. Set a
VulnCheck token from the Vulnerabilities tab (or `$VULNCHECK_API_TOKEN`); `GET`/`POST /api/kev`.

KEV flags also ride the compact vulnerability rollup pushed to the Mesh on check-in, so the fleet
console (Mesh 0.7.45+) prioritizes known-exploited components the same way — fleet-wide.

## macOS agent 1.6.1 / Linux agent 1.6.1 — 2026-10-18

### Added

**Location line in the External attack surface section.** The Vulnerabilities tab's External section now
shows where this host's public (egress) IP geolocates — e.g. "📍 Fremont, United States · Linode" — using
Shodan's own location in Full mode, and falling back to the host's resolved geo (the opt-in auth-map
resolver) otherwise. (The fleet-wide world-map view lives in the Mesh; for a single host this one line
is the proportional treatment.)

## macOS agent 1.6.0 / Linux agent 1.6.0 — 2026-10-14

### Added

**External attack surface via Shodan (opt-in, CTEM-Lite).** The Vulnerabilities tab now has an
**External attack surface** panel that shows what the public internet sees of this host — the
outside-in view that OS currency and the local inventory can't give. It looks up this host's own
public IP on Shodan and surfaces the open ports, exposed services and versions, known CVEs, tags, and
any screenshots Shodan captured, all in the console so you don't have to pivot out to shodan.io.

Two modes: **Full**, using the operator's own Shodan API key (a paid Membership) for the complete host
view including screenshots; and **Lite**, the keyless InternetDB API (ports / CVEs / CPEs / tags only,
no screenshots, refreshed weekly — free for non-commercial use). **Off by default**: enabling it is a
deliberate choice, since it makes outbound requests to Shodan; nothing about the local inventory is
sent, and the public IP is resolved with the same opt-in resolver the Authentications map uses. The
API key is held in the SecretStore (Keychain/file), never written to settings and never sent to the
browser (`SHODAN_API_KEY` is a read-only fallback). Agent-only — none of this rides the mesh check-in.
Shodan's CVE list is inferred from service version strings, so findings are flagged as leads to verify.
New `GET/POST /api/shodan` and `--shodan-interval` (default 12h).

## macOS agent 1.5.0 / Linux agent 1.5.0 — 2026-10-11

### Added

**High-severity vulnerabilities now raise EDR alerts.** When a new finding at or above a configurable
severity appears (default **critical**, plus any **vulnerable-and-running "high"**), the agent fires the
same pathways a detection does — a phone/chat notification and a SIEM/SOAR event (`event:
"vulnerability"` via the webhook + JSONL sink). The first scan on a fresh host baselines silently (no
backlog replay) and the alerted set persists, so a restart doesn't re-alert; a finding that's resolved
or disappears is forgotten, so a later recurrence alerts again. `--vuln-alert-severity
critical|high|off`. The Vulnerabilities tab still shows everything regardless.

**Linux: RPM and Alpine support (not just Debian/Ubuntu).** The Linux agent now detects the distro
family from `/etc/os-release` and uses the right tooling: **dnf** update currency + `rpm -qa`
inventory on RHEL/Fedora/Rocky/AlmaLinux/Amazon, and **apk** currency + inventory on Alpine, alongside
the existing apt/dpkg path. Security updates are flagged where the distro exposes them (apt pockets,
`dnf updateinfo --security`), and reboot-required is read per family. The fleet view shows each host's
native package count (dpkg/rpm/apk). _New RPM/Alpine paths are validated against synthetic fixtures;
confirm on a live RHEL/Alpine host before relying on them._

## macOS agent 1.4.0 / Linux agent 1.4.0 — 2026-10-11

### Added

**Vulnerability detail panel + remediation.** The Vulnerabilities tab is now a two-pane view: click a
finding and an in-console detail panel shows the full advisory — description, CVSS, fixed-in, published
date, aliases, and source links — so you no longer have to click out to an external site to understand
it. Findings now carry that detail end-to-end (sourced from OSV, the advisory feed, and the OS-update
check).

**Remediate a finding without actually patching it yet.** Each finding can be marked **Patched /
Mitigated / Accepted / False positive** with a note; remediated findings drop out of the active counts
and severity tiles (and move under a "show resolved" toggle), with a running `resolved` tally.
Decisions persist across rescans and restarts (`vuln-remediation.json`, keyed by a version-independent
finding signature). **"Patched" auto-verifies**: it stays suppressed until the next scan, which either
confirms it (the finding is gone) or **re-opens it as a conflict** if the fix is still missing. A new
`POST /api/vulns` (`?sig&status&note`) records the decision and applies it live; the Mesh can drive it
fleet-wide over the management relay (Scouter Mesh 0.7.37). The compact mesh rollup now carries each
finding's signature + remediation state.

## Linux agent 1.3.0 — 2026-10-09

### Added

**In-agent vulnerability scanning (CTEM-Lite) for Linux.** The Linux agent gains the same
Vulnerabilities tab and `GET /api/vulns` as macOS, Debian/Ubuntu-first and entirely local:

- **APT update currency** — distro/kernel (`/etc/os-release`, `uname`), pending package updates
  parsed from a simulated `apt-get -s upgrade` against the cached lists (no network), with the
  **security-pocket** ones flagged (`*-security`), plus a reboot-required check. This is the
  authoritative Linux exposure signal — a distro security update exists precisely when a CVE has a fix
  available.
- **Inventory** — installed dpkg packages (a pure read of `/var/lib/dpkg/status`, no `dpkg-query`
  spawns) plus pip/npm globals.
- **Advisory matching** — the shared GeoIP-style engine: a JSON advisory feed (`--vuln-feed-url`, with
  a small flagged example set) matched against dpkg packages, and offline **OSV** language-ecosystem
  matching (`--vuln-osv auto|off|LIST`), downloaded per-ecosystem and indexed only for installed
  packages.

A dpkg finding is flagged **"vulnerable and live"** (⚡, sorted first) when a running process is owned
by that package, resolved through the agent's existing dpkg index. The compact rollup rides the mesh
check-in so a mixed macOS/Linux fleet shows one unified Vulnerabilities view (Scouter Mesh 0.7.35). On
by default; `--no-vuln` / `--vuln-interval`. New tests in `linux/tests/test_vuln_scanner.py`.

## macOS agent 1.3.0 — 2026-10-08

### Added

**In-agent vulnerability scanning (CTEM-Lite), macOS-first.** The agent now scans itself for exposure,
all pure-stdlib and entirely local — nothing about the inventory ever leaves the machine. Three pieces,
surfaced on a new **Vulnerabilities** tab and `GET /api/vulns`:

- **OS update currency** — macOS version/build, pending Apple updates (parsed from `softwareupdate`,
  with the security/recommended/restart ones flagged), and the XProtect data version. The single
  highest-value, most authoritative Mac signal; no third-party database required.
- **Software inventory** — top-level `.app` bundles (bundle id + version), Homebrew formulae, and
  globally-installed language packages (pip / npm), the latter queried as the console user when the
  agent runs as root.
- **Advisory matching** — a GeoIP-style feed engine. A JSON advisory feed (`--vuln-feed-url`, with a
  small built-in **example** set so the pipeline works offline, flagged so nothing is passed off as a
  confirmed CVE) is matched against apps/Homebrew; and **OSV** language-ecosystem data is fetched
  offline (`--vuln-osv auto|off|LIST`) — the per-ecosystem archive is downloaded daily and indexed
  *only for the packages actually installed*, then matched locally.

Findings are severity-ranked and prioritized **"vulnerable **and** live"**: a finding whose software is
currently running (an executing process inside the app bundle) is marked ⚡ and sorted first. A compact
rollup (OS currency + severity counts + top findings) rides the mesh check-in for the fleet
Vulnerabilities view (Scouter Mesh 0.7.34). On by default; disable with `--no-vuln`, tune with
`--vuln-interval`. The scan runs on a long timer (softwareupdate/brew are slow), never on the
per-snapshot path.

## macOS agent 1.2.0 / Linux agent 1.2.0 — 2026-10-08

### Added

**XDR syslog collector + mesh-coordinated election.** An optional edge collector for third-party
network telemetry (firewall / AP / router), off by default (`--syslog`). It listens for LAN syslog on
UDP (and optional TCP), parses the RFC3164/5424 envelope, routes each line to a device profile
(pfSense/OPNsense, FortiGate, SonicWall, dnsmasq DHCP, hostapd Wi-Fi, plus a generic fallback),
normalizes it to the mesh's common event schema, keeps only the security-relevant events — denies,
identity, auth failures, config changes, and allows that cross the trust boundary (touch a public IP)
— and forwards them in batches to the mesh over the agent's authenticated relay.

So enabling it fleet-wide doesn't make every host forward at once, the mesh elects one Designated
Collector per site plus a backup: each agent reports its collector capability and a `--syslog-priority`
on check-in, learns its role in the response, and only the designated collector forwards; a backup
holds a warm buffer and takes over on failover. Pairs with Scouter Mesh 0.7.33 (`/api/logs`,
`/api/collectors`, `/api/net-context`).

## macOS agent 1.1.0 / Linux agent 1.1.0 — 2026-10-04

### Added

**Authentications map — see where logins come from.** A new **Authentications** tab (just after
Process Tree) plots this host's logins on an offline world map. **Remote** logins plot at the source
IP's location; **device** logins (console, sudo, terminal) plot at this machine's own external-IP
location, so a device that shows up somewhere unexpected stands out. Successful only by default, with
a toggle to reveal failed attempts (brute-force sources); remote/device layer toggles; a
7/30/90/365-day window; and point drill-in to the underlying events (time, user, source, method,
status).

Resolving this host's own external IP is **opt-in** — one outbound lookup over `urllib`, off by
default — so nothing leaves the machine unless the operator asks. The base map (`worldmap.json`,
country paths + centroids) is served locally and embedded, so nothing is fetched to draw it. The
agent exposes the data on `/api/auth-map` (including raw `device_events`), which the Scouter Mesh
consumes to build a fleet-wide map that places each host by its observed connection IP.

**Detection-flow Sankeys on the Metrics page.** Five selectable three-column flows over the alerts
in the current window, band width = alert count, ribbons tinted by their source:

- **Signal** — severity → confidence → disposition (noise paths like weak → auto-closed vs the
  high → certain → malicious spine).
- **ATT&CK** — tactic → technique → disposition (techniques colored by tactic; the long tail folds
  into "other").
- **Response** — confidence → handling (automatic vs operator) → outcome (contained / reversed /
  closed).
- **Lifecycle** — every alert raised → auto-closed / investigated / untouched → where it ended up.
- **Correlation** — detection source → correlated into a case? → that case's severity.

Each lifecycle record now also carries its peak confidence, primary ATT&CK technique, detection
source and final disposition; records written before this still bucket sensibly. A quiet or
newly-spun-up host shows a placeholder instead of an empty chart. The Metrics tab reclaims the unused
node-inspector rail on the right so the charts and cards get full width.

## macOS agent 1.0.1 / Linux agent 1.0.1 — 2026-09-30

### Fixed

**On a Mesh-managed host, the Detections page now shows every rule the Mesh pushes.** The built-in live-rule library (100+ node rules) was filtered out of the "Mesh-managed rules" list while the built-in SQL detections were shown, so the live rules looked missing. All Mesh-pushed rules now appear together under "Mesh-managed rules", with the large built-in library collapsed by default and expandable — the SQL detections and any Mesh-authored customs stay visible.

## macOS agent 1.0.0 / Linux agent 1.0.0 — 2026-09-28

The first public, open-source release of Scouter — a dependency-free (pure Python 3 standard
library) EDR/XDR toolkit for macOS and Linux. A local, read-only sensor that draws your live system as
an interactive graph, scores findings against a continuously curated library of MITRE ATT&CK-mapped
detections, enriches with threat intelligence, correlates incidents, and can take opt-in reversible
containment — with the UI bound to localhost and telemetry kept on the machine.

See the [README](README.md) for the full feature set and quick start.

_This is the first public release; Scouter’s earlier development history is not reproduced here._
