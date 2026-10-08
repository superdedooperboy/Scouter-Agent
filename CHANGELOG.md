# Changelog

All notable changes to Scouter are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/). This repository ships the macOS and Linux
agents, versioned independently.

## [Unreleased]

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
