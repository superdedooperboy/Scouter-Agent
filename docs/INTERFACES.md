# External interfaces

Reference for the external interfaces of the Scouter agent — how a user or another system provides
input to it and consumes its output. Scouter ships two agents (macOS and Linux) that behave
identically at the interface level; where they differ, the Linux specifics are in
[`linux/README.md`](../linux/README.md).

There are three external interfaces: the **command-line interface** (input), the **web console**
(primary interactive interface — input and output), and a set of **integration outputs** (machine
-readable output to other systems). The `/api/*` HTTP endpoints are an *internal* interface between
the shipped console and the agent, not a published API — see the note at the end.

---

## 1. Command-line interface (input)

The agent is launched and configured entirely through command-line options. The **authoritative,
always-current list** is the auto-generated help:

```
python3 agent.py --help
```

Because the help text is generated from the argument parser, it never drifts from the code. The
most common options are also documented, with defaults and descriptions, in the **Options** table of
the [README](../README.md#options). The main groups:

- **Serving** — `--port N` (localhost only), `--no-open` (don't open a browser), and the
  service-management actions `--install-service` / `--restart-service` / `--uninstall-service`.
- **Sensor scope** — e.g. `--no-esf` (disable real-time Endpoint Security events), interval and
  collector toggles.
- **Response posture** — e.g. `--no-response` (disable the containment/response subsystem); the
  live/dry-run/scouting posture is otherwise chosen in the UI.
- **Control plane** — `--local-control` (ignore any Mesh and keep full local authority) and the
  enrollment options that point an agent at a Mesh.
- **Enrichment & intel** — threat-intel, Geo/ASN, and related feature flags.
- **Opt-in intelligence** — e.g. `--ai-audit` (local-only AI-transcript audit; off by default).
- **Diagnostics** — `--version`.

Run `--help` for the complete set, exact spellings, and defaults.

## 2. Web console (input and output)

The agent serves a single-page console on `http://localhost:<port>` (default `8787`). This is the
primary interactive interface: the live telemetry graph, alerts, incident cases, the Hunt tab, the
ATT&CK coverage matrix, AI Surface, response controls, and configuration are all driven from it.

Its use is documented throughout the README — start at
[Using the visualizer](../README.md#using-the-visualizer), with a feature-by-feature walk-through in
the sections that follow it. The console is read-only by default; state-changing actions
(triage, containment, configuration) are gated and audited.

## 3. Integration outputs (machine-readable output)

Scouter emits structured output to other systems. These formats are the stable, documented output
interface:

- **Alert export (SIEM / SOAR)** — webhook POST and JSONL stream of alert records. Format and setup:
  [Alert export](../README.md#alert-export-siem--soar).
- **Chat alerts** — Slack, Microsoft Teams, Discord, Google Chat, and Mattermost webhook messages:
  [Chat alerts](../README.md#chat-alerts-slack-teams-discord-google-chat-mattermost).
- **Detection content** — built-in rules, the ATT&CK coverage layer, and SQL/VQL hunts are described
  under [Detection engineering](../README.md#detection-engineering) and
  [Deep DFIR — Velociraptor](../README.md#deep-dfir--velociraptor).

## Note on the HTTP `/api/*` endpoints

The agent's `/api/*` HTTP endpoints exist to serve its own bundled console (the single-page app
loaded from `/`). They are an **internal interface**, versioned together with the console that
consumes them, and are **not** a supported third-party API — their shapes may change between
releases without notice. Integrators should use the documented **integration outputs** above
(alert export, chat webhooks) rather than calling `/api/*` directly. When an agent is Mesh-managed,
write access to these endpoints is additionally restricted to a whitelist and gated by the Mesh
authority / break-glass model described in [SECURITY.md](../SECURITY.md).
