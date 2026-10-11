# Changelog

All notable changes to Linux Scouter are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added
- **Vulnerability detail panel + remediation, 1.4.0** — click a finding for an
  in-console detail panel (description, CVSS, fixed-in, aliases, sources — no
  external redirect); mark findings Patched/Mitigated/Accepted/False positive
  with a note (`POST /api/vulns`, persisted, keyed by a version-independent
  signature). "Patched" auto-verifies on the next scan; remediated findings
  leave the active counts. Drivable fleet-wide from Scouter Mesh.
- **In-agent vulnerability scanning (CTEM-Lite), 1.3.0** — APT update currency
  (pending updates with security-pocket ones flagged + reboot-required), a
  dpkg + pip/npm inventory, and local advisory/OSV matching, on a new
  Vulnerabilities tab and `/api/vulns`; dpkg findings flagged "live" when a
  running process is owned by the package. On by default (`--no-vuln`).
- Initial repository scaffold ported from the Mac Scouter base: MIT license,
  README, `.gitignore`, and this changelog.
- Portable core carried over unchanged: graph UI (`index.html`), HTTP snapshot
  server, SQLite history database, scoring pipeline with MITRE ATT&CK tagging,
  IOC/STIX-TAXII feeds, VirusTotal enrichment, and GeoIP.

### Changed
- Rebranded user-facing strings from "Mac Scouter" to "Linux Scouter".
- Renamed the history database from `mtv-history.db` to `scouter-history.db`.

### In progress
- Rewriting the collector layer against Linux primitives (`/proc`, `systemd`,
  `dpkg`, `journald`). See the status table in the README.
