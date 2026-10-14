# Changelog

All notable changes to Linux Scouter are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added
- **External attack surface via Shodan (opt-in, CTEM-Lite), 1.6.0** — a new
  "External attack surface" panel on the Vulnerabilities tab shows what the
  public internet sees of this host: it looks up the host's own public IP on
  Shodan and surfaces open ports, exposed services/versions, known CVEs, tags,
  and any screenshots, in-console. Two modes — Full (operator's own Shodan key,
  incl. screenshots) and Lite (keyless InternetDB; ports/CVEs/CPEs/tags, no
  screenshots, non-commercial). Off by default; outbound to Shodan only, local
  inventory never leaves the host; key in the SecretStore (file;
  `SHODAN_API_KEY` env fallback), never sent to the browser. Agent-only.
  `GET/POST /api/shodan`, `--shodan-interval` (12h).
- **EDR alerts for high-severity findings + RPM/Alpine support, 1.5.0** — a new
  critical (or vulnerable-and-running high) finding fires a notification + SIEM
  export (`--vuln-alert-severity`). The agent now detects the distro family and
  uses dnf/rpm (RHEL/Fedora/Rocky/Alma) or apk (Alpine) in addition to apt/dpkg
  for update currency + inventory. (RPM/Alpine validated on synthetic fixtures;
  confirm on a live host.)
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
