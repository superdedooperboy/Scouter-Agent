# Contributing to Scouter

Thanks for your interest in improving Scouter. This is a defensive security toolkit that
people run on their own machines — often as root — so the bar for changes is "safe,
auditable, and dependency-free." This guide explains how to work with the codebase.

## The one rule that shapes everything: zero dependencies

Scouter is **pure Python 3, standard library only** — no pip installs, no build step, no
bundlers. A user should be able to read every line of what they're about to run and launch
it with `python3 agent.py`. Please keep it that way:

- **No third-party runtime dependencies.** If you think you need one, open an issue first
  and let's talk about doing it with the stdlib.
- **No build/transpile step.** The web UI is vanilla JS embedded in the server; no
  framework, no bundler.
- Dev-only tooling (a linter, a test helper) is fine as long as the tool still *runs* with
  nothing installed.

## Project layout

| Path | What it is |
|------|-----------|
| `agent.py` + `index.html` | The macOS endpoint agent + its self-contained web UI |
| `linux/agent.py` + `linux/index.html` | The Linux endpoint agent + UI |
| `builtins-*.json`, `collectors-*.json`, `playbook-*.json` | Generated factory data the mesh seeds from — regenerate with `tools/`, don't hand-edit |
| `linux/tests/` | Unit tests for the Linux collectors' pure parsing logic |

The macOS and Linux agents deliberately mirror each other. A change to shared behaviour
usually needs to land in **both** agents (and often the mesh) to keep parity.

## Running it

```bash
# endpoint agent (add sudo for full visibility: ESF/auditd, all processes, system daemons)
python3 agent.py            # macOS
python3 linux/agent.py      # Linux

# the fleet console
```

## Testing & verifying a change

Before you open a PR, please run — and mention the results in the PR:

```bash
# 1) Everything must byte-compile
python3 -m py_compile agent.py linux/agent.py

# 2) Unit tests (Linux collectors)
cd linux && python3 -m unittest discover -s tests

# 3) If you touched the web UI (embedded JS), sanity-check it actually parses.
#    On macOS: extract the <script> blocks and run them through the JS engine, e.g. osascript -l JavaScript.
```

CI runs (1) and (2) on every pull request. If you add behaviour that can be unit-tested
without a live host (a parser, a scoring rule, a state machine), please add a test —
`linux/tests/test_core_collectors.py` shows the synthetic-fixture style.

For anything that changes what the browser renders, verify it in the actual UI (screenshot
in the PR is welcome) rather than assuming — the UIs are the product.

## Code style

- **Match the surrounding code.** Same naming, comment density, and idioms as the file
  you're editing. Consistency beats personal preference here.
- Comments explain *why*, not *what*. The existing code favours a short rationale on
  non-obvious decisions — keep that.
- Keep functions doing one thing; the files are large but the functions are small.

## Security-sensitive areas — extra care

Changes near these get scrutinised harder; call them out explicitly in your PR:

- **The write path** (`/api/*` POST handlers, the CSRF/Host guards, the mesh relay).
- **The enrollment-token and admin-token gates**, and anything touching the read-only
  boundary of hunts / the API relay.
- **Response / containment** (reversibility, the auto-response and AI-in-the-loop
  guardrails, the circuit breaker).
- **Anything that parses attacker-controlled telemetry.** Treat process names, paths,
  connection metadata, and alert content as hostile input — never let it widen what runs
  or blow up memory.
- **Secrets.** API keys and tokens must not reach the browser, the mesh payload, argv, or
  logs. Secrets go over stdin / the Keychain (0600 file fallback), never as command-line
  arguments.

If a change would break the enrollment/wire protocol or a CLI flag, say so — post-1.0
those are compatibility surface.

## Pull requests

1. Fork, branch, and keep the PR focused on one thing.
2. Describe what changed and why, and paste the verification results above.
3. Note explicitly if you touched any security-sensitive area.
4. Be patient and kind in review — see [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).

## Contributor License Agreement

Before your first pull request can be merged you'll need to sign the
[Contributor License Agreement](CLA.md). An automated check posts the instructions on your
PR; signing is a one-line comment and is recorded against your GitHub account, so it's a
one-time step.

It exists because the project needs to be able to change its own licence in future — for
example to relicense a component, or to satisfy an acquirer's or an enterprise customer's IP
diligence. Without a CLA, every outside contribution is a piece of the codebase the
maintainer cannot relicense without tracking down its author years later. It does not take
any rights away from you: you keep full ownership of your work and can use it however you
like elsewhere.

If you're contributing on behalf of an employer, please mention it on the PR before signing.
Employer IP clauses commonly cover side projects, and sorting that out up front protects you
as much as the project.

By contributing, you agree that your contributions are licensed under the project's
[Apache License 2.0](LICENSE).
