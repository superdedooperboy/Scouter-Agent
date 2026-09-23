# Security Policy

Scouter is a defensive security tool. We take the security of the project — and of the
people who run it, often as root on production hosts — seriously.

## Reporting a vulnerability

**Please do not open a public issue for security vulnerabilities.**

Report privately through GitHub's **Private Vulnerability Reporting**:

1. Go to the repository's **Security** tab.
2. Click **Report a vulnerability**.
3. Describe the issue, the impact, affected version(s), and steps to reproduce.

When a fix ships, we're happy to credit you in the release notes (let us know if you'd
prefer to stay anonymous).

## Response commitments

Scouter is maintained by **one person**. These windows are set to what a single maintainer
can genuinely honour rather than to what looks impressive, and they are deliberately
conservative — we would rather beat them than miss them. Business days, Eastern Time.

| Stage | Target |
|---|---|
| Acknowledge your report | **3 business days** |
| Initial assessment (severity, affected components, whether we can reproduce) | **10 business days** |
| Fix or documented mitigation — critical | **14 days** from confirmation |
| Fix or documented mitigation — high | **30 days** from confirmation |
| Fix or documented mitigation — moderate / low | **90 days** from confirmation |

If we are going to miss one of these, we will tell you before it lapses and say why.

**Coordinated disclosure: 90 days.** We ask that you hold public disclosure until a fix is
released or 90 days have passed, whichever comes first. If a vulnerability is being
actively exploited, tell us and we will compress the timeline as far as we can. If you
disagree with our assessment of severity, say so — we would rather argue about it than
have you sit on something serious.

## How fixes reach deployed agents

Relevant to how urgently you should treat a report: a fix does not depend on every operator
noticing a release.

- Agents enrolled in a mesh can be updated **from the console** — the mesh pushes an
  `update` command, and the agent performs a fast-forward pull in its own checkout and
  re-executes in place. An operator can roll a patch to a scope of hosts, or the whole
  fleet, in one action.
- Standalone agents are updated with `git pull` and a restart.
- Release notes call out security fixes explicitly, and the console surfaces an
  update-available indicator.

The practical consequence is that our exposure window after a public disclosure is measured
in **how fast we can produce a correct patch**, not in how long it takes the fleet to adopt
it. Please give us the time to get the patch right.

## What to report

Anything that could compromise a host running Scouter or the mesh, for example:

- A way for a reporting agent, a mesh, or an unauthenticated network peer to execute code,
  read files, or escalate privileges beyond what the trust model intends.
- Bypasses of the write guards (CSRF token / Host validation), the enrollment-token or
  admin-token gates, or the read-only hunt/relay boundaries.
- A path by which attacker-controlled **telemetry** (process names, connection metadata,
  file paths, alert content) causes the agent, the mesh, or a browser client to do
  something it shouldn't — injection, unbounded resource use, or widening an autonomous
  action.
- Secrets (API keys, tokens) leaking into logs, the browser, the mesh payload, or disk in
  a way the design says they should not.

## Trust model (so reports land in the right place)

Some behaviour is **by design**, not a vulnerability — please read
[README → Safety & scope](README.md#safety--scope) first:

- Scouter is **dual-use**: it can take reversible containment and (opt-in) response actions.
  Running it is authorization to act on your own hosts.
- The mesh **admin token is fleet-wide authority** — anyone holding it can push
  configuration and (where remote management is enabled) reversible actions to every
  enrolled host. Treat it like a production credential. This is expected, not a flaw.
- Pointing an agent at a rogue mesh already requires host access (i.e. prior compromise),
  so "a mesh I control can manage my agent" is not a vulnerability.
- The agent is **read-only by default**; response/containment is gated and audited.

## Supported versions

Scouter is pre-1.0 and ships as three components (agent for macOS, agent for Linux, and
the mesh console), **versioned independently** — the agents and the console move on separate
tracks, so their version numbers differ by design.

Security fixes target the **latest released version** of each affected component. There are
no long-term-support branches and no backports to older releases: with one maintainer, a
backport branch that nobody tests is a liability rather than a service. Please upgrade to
the latest release before reporting, and include the exact version (`--version`) in your
report.

## Good-faith research

We will not pursue or support legal action against researchers who:

- Act in good faith and make an effort to avoid privacy violations, data destruction, and
  service disruption.
- Only test against **their own** hosts and meshes.
- Give us reasonable time to remediate before public disclosure.

Thank you for helping keep Scouter and its users safe.
