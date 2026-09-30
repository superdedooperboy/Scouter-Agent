# Changelog

All notable changes to Scouter are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/). This repository ships the macOS and Linux
agents, versioned independently.

## [Unreleased]

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
