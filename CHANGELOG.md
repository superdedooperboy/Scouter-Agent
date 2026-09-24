# Changelog

All notable changes to Scouter are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/). This repository ships the macOS and Linux agents, versioned independently.
The Mesh console is a separate product with its own changelog. The project is in
pre-1.0 development; **1.0.0 is reserved for the public open-source launch**.

## [Unreleased]

_Targeting **1.0.0** for the public launch. Roadmap: expanding the Mesh from an EDR fleet
console toward XDR — pluggable connectors for non-endpoint telemetry (firewall, identity, DNS,
cloud), cross-source entity correlation, and cross-source response, with a bounded,
retention-light central store._

## macOS agent 0.9.36 / Linux agent 0.9.33 — 2026-09-23

### Added

**Open investigations are marked as such.** An investigation that is not closed now carries a green
ring and a lit green dot beside its status, matching what the Mesh already showed. Status was only
ever a word at the end of the row, so scanning the list meant reading it; the ring makes the open
work visible at a glance. `.inccard.open` already meant *expanded* in this console, so the new state
is a separate `.openinv` class.

**Break-glass is reachable from the console.** The managed banner — the only place the override is
ever relevant — carries a quiet `break-glass` link that opens the exact command for this install,
with a Copy button and the live state of any open window. The page deliberately cannot arm it: the
command must run as root, and that is the whole authentication. `/api/break-glass` now returns that
command built from the running interpreter and the agent's absolute path, because a service runs
from a directory nobody has open in a terminal.

### Changed

**Tabs say what they are.** `Graph` → **Node Graph**, `Tree` → **Process Tree**, `Timeline` →
**Event Timeline**. The sidebar's `Graph` section follows the same name.

**Sidebar order follows how it is used.** Scouter Mesh moves to the bottom, with Legend and Node
types just above it — reference material and the multi-host link sit below the controls you touch
daily, not above them. Filter, Node Graph and Appearance became collapsible and start collapsed,
like every other section. The "nothing leaves your machine" line stays pinned at the foot of the
sidebar rather than collapsing with Appearance.

## macOS agent 0.9.35 — 2026-09-23

### Fixed

**The console page was cacheable.** It carries a per-process CSRF token and the whole UI's
JavaScript, so a cached copy means a stale token after a restart and stale code after an upgrade —
both of which look like the console being broken rather than being old. It now sends
`Cache-Control: no-store, must-revalidate`, which the Linux agent has always done.

## macOS agent 0.9.34 — 2026-09-23

### Fixed

**Installing the service from a replaced source repository failed outright.** `--install-service`
fast-forwards the service's checkout from the source, so a source whose history does not descend from
what is already deployed stopped with `refusing to merge unrelated histories` and the machine stayed
on its old code. That happens whenever the source repository is replaced rather than advanced — a
repository split, a restore from backup, a move between forks.

The service directory is a deployment, not somewhere anyone edits code, so there is nothing in its
history worth preserving: an unrelated or diverged source now triggers a clean redeploy instead of a
refusal. State is untouched — the redeploy overlays only the files the source actually contains, so
the history database, triage, incidents and baselines living beside the code all survive.

## macOS agent 0.9.33 · Linux agent 0.9.32 — 2026-09-23

### Fixed

**A fleet update from a private repository failed with a git message that explained nothing.** The
agent runs as a service: no terminal, no stored git login. Pulling from a repository that requires
authentication made git try to prompt, fail on the missing tty, and report `could not read Username
for 'https://github.com': Device not configured` — which reads like a broken device rather than
"this repository needs credentials I do not have".

The pull now runs with `GIT_TERMINAL_PROMPT=0` so it fails immediately instead of trying to prompt,
and an authentication failure is translated into what it means: the update source needs credentials
this agent does not have, so point the fleet at a repository the endpoint can read without logging
in, or give the service account a read-only git credential. Every other git failure is still reported
verbatim.

## macOS agent 0.9.32 · Linux agent 0.9.31 · Mesh 0.7.15 — 2026-09-23

### Fixed

**An investigation outlived its evidence, and its members opened onto nothing.** Case #301 on a real
machine listed five `proc:<pid>` members that existed nowhere: the processes had exited, so no live
node, and the alerts table is capped, so the stored records had aged out too. Clicking a member gave
an empty detail pane, which makes the case a list of names.

Investigations now **capture a bounded snapshot of each alert as it joins** — type, severity, score,
ATT&CK techniques, reasons and the detail fields, clamped in size — for auto-correlated members as
well as manually pinned ones. First capture wins, because a later snapshot of the same node is
usually thinner and the point is what it looked like when it mattered. The capture rides in the
`/api/incidents` payload (it used to be stripped as an internal cache), and the detail pane falls back
to it when there is no live node and no stored alert, saying plainly where the record came from.

### Added

**Mesh: investigation members can be inspected.** The drill-in listed a case's members as plain text
with no way to look at any of them. Each is now clickable and expands in place, preferring the host's
live alert and falling back to the investigation's captured snapshot — with the source named either
way. A member with neither says so, and points at the host's own alert archive.

Both are forward-looking: a case whose members have already vanished has nothing to recover. Cases
whose members still alert will capture their evidence on the next snapshot.

## macOS agent 0.9.31 · Linux agent 0.9.30 — 2026-09-23

### Fixed

**The Mesh saw a fraction of a host's open alerts: investigating ones were missing.** A host with 103
alerts in the investigating state reported six to the console, and the fleet Alerts panel and host
Overview agreed with each other and with nothing else — the drill-in Alerts tab, which pulls the host
live, showed all 103.

`recent_alerts(open_only=True)` filtered on the alerts table's own `triage_status` column, but that
column is stale by design: node ids change across restarts, so the live state lives in the triage
store and is overlaid *after* the query. An alert that was closed once (auto-closed, say) and later
moved to investigating still reads `closed` in the column, so the filter removed it before the
overlay could correct it. On the machine this was found on, 101 of 103 investigating alerts were being
dropped that way.

The open-only query now also takes the node ids the triage store still considers live, so those rows
survive the filter and reach the overlay. A genuinely closed alert is still excluded. This corrects
the mesh payload (fleet Alerts, host Overview, severity counts) and `/api/alerts`, which the host's
own left pane polls.

## macOS agent 0.9.30 · Linux agent 0.9.29 — 2026-09-23

### Fixed

**The console ignored an open break-glass window.** The page wraps `fetch` and refuses writes in the
browser whenever the host is managed, so the reason is immediate rather than a 403 — but it never
checked whether a window was open. Break-glass therefore worked over the API and appeared broken in
the one place a person would actually use it: the console still said "read-only" while the agent was
ready to accept the write. The wrapper now polls `/api/break-glass`, lets scoped writes through while
a window is open, and turns the managed banner into a live countdown naming who opened it. The agent
stays the authority — anything outside the window's scope still returns 403, and that error is shown
as-is.

**`--break-glass` printed an "End early" command that only worked from one directory.** It used the
script's basename; it now prints the absolute path.

## macOS agent 0.9.29 · Linux agent 0.9.28 — 2026-09-23

### Fixed

**`SecretStore(file_path=…)` did not isolate a store.** The keychain (macOS) / Secret Service (Linux)
stayed the primary backend regardless, so a throwaway instance created for a test wrote into the
*real* login keychain — which is exactly how five junk `chat-*` webhook entries once landed in a
developer's keychain during a test run. `SecretStore(..., keychain=False)` now forces the file
backend, and the docstring says plainly that a path alone is not isolation.

**A managed host whose mesh was unreachable could never be updated.** `do_POST` checks
`_write_allowed()` before dispatching, and `/api/restart` was in neither `LOCAL_READS` nor
`BREAKGLASS_PATHS` — so on a mesh-managed machine the local Restart button returned 403. Restart is
also how an agent re-reads `agent.py`, so a host whose mesh was down could not pick up a new version
from the console *or* from the mesh: the local path was refused and the remote path was unreachable.
Found on a real agent sitting three versions behind with a newer file already on disk.

`/api/restart` is now covered by break-glass. Restarting to load new code is acting on your own
machine, which is what break-glass is for: it changes no policy, touches no mesh link, and root — the
only thing that can open a window — can kill the process anyway, so refusing it bought nothing and
cost the ability to patch. The mesh link, enrollment token, collection, sensors, rules, suppressions
and response posture all remain out of scope.

The refusal message for a restart now says it is normally the provider's to push, instead of the
generic "ask them to make the change" — which is unhelpful advice on a host whose provider is exactly
what cannot be reached.

## macOS agent 0.9.28 · Linux agent 0.9.27 — 2026-09-23

### Added

**A standalone agent can post alerts to Slack, Teams, Discord, Google Chat and Mattermost.** The Mesh
has had 16 outbound channels for a while, but an agent with no Mesh had only ntfy push and a raw-JSON
webhook — and a raw JSON POST to a Slack webhook is rejected, so there was no way to get a readable
alert into a channel people watch. Each target now gets its native format: Slack blocks, a Teams
MessageCard, a Discord embed, plain text for Chat and Mattermost.

- **A mesh-managed host deliberately does not do this.** The panel says so and offers nothing to
  configure: the Mesh already sees every alert and holds the webhook in one place, and putting the URL
  on every endpoint would spread a credential across machines an intruder may already own — and page
  twice. This is for the install nobody is managing.
- **Noise discipline, because a muted channel looks like coverage:** a severity floor (default high),
  per-alert dedup within the hour, 20-second coalescing so a burst becomes one digest, and closed or
  suppressed alerts are never sent. Delivery runs on its own thread, so a slow webhook never stalls
  collection.
- **The webhook URL is treated as the credential it is:** Keychain (or `0600` file), never the
  settings file, never returned to the browser, `https` required. Per-target Send test.

## macOS agent 0.9.27 · Linux agent 0.9.26 · Mesh 0.7.13 — 2026-09-23

### Added

**Validating an alert as malicious now raises the hunts that follow from it.** Closing an alert as
**Malicious** is a statement that an indicator is bad; the follow-up is always the same — where else
has this hash run, who else talked to this address, what else came from this domain — and it is
exactly what gets skipped at 2am.

The agent now pulls the indicators out of that alert and immediately runs them against its own
history: hashes against `hashes`/`files`/`downloads`, remote addresses against
`connections`/`conn_events`, download domains against `downloads`, and the binary's path against
`processes`/`exec_events`/`connections`/`jobs`. Results land in `/api/auto-hunts`.

- **Only validation triggers it.** A detection firing is not validation — it is the thing being
  validated. A bulk close as Malicious hunts the first ten, so closing 500 alerts does not become
  3,000 queries.
- **Narrow on purpose.** Hashes, addresses, download domains, the binary's own path. Not process
  names or ports, which return the whole machine and bury the rows that mattered.
- **Indicators are attacker-influenced telemetry**, so values are charset-validated before use and
  quoted values escaped — a malformed hash is dropped rather than queried, and a filename containing
  a quote is escaped rather than breaking the query.

**The fleet half: hosts propose, the operator decides.** Each host sends its recent auto-hunts to the
Mesh, where they appear at the top of the Hunt tab with the indicator, which machine validated it,
what it found locally, and Load / Run on the fleet. The same indicator from several hosts collapses
into one row naming them all.

Only the question travels, never the endpoint's telemetry, and the Mesh never runs a proposal by
itself — a single endpoint does not get to make the whole estate execute a query. The Mesh also
refuses any proposal that is not a plain `SELECT`/`WITH`, regardless of what the host claimed.

## macOS agent 0.9.26 · Linux agent 0.9.25 · Mesh 0.7.12 — 2026-09-23

### Added

**Break-glass: a bounded, audited override of Mesh authority on one machine.** Authority makes a
managed endpoint's console read-only, which is right until the mesh is unreachable, alerts are firing
on the machine in front of you, and nobody can act. `sudo python3 agent.py --break-glass 60 --reason
"…"` opens a window; `--break-glass 0` ends it early; it expires by itself and is capped at four hours.

- **The gate is local root**, proven by the grant being a root-owned `0600` file — writing one *is* the
  authentication. A grant owned by anyone else, or writable by anyone else, is refused, so this cannot
  become a privilege-escalation path. Root already had the power to stop the agent entirely; this
  replaces "kill it and lose all telemetry" with a window that ends on its own and is written down.
- **Scoped to acting, not reconfiguring.** Triage, investigations and reversible containment only.
  Never the mesh link, the enrollment token, collection, sensors, rules, suppressions or response
  posture — `/api/respond` is narrowed by op, so a window can contain a process but cannot change how
  the machine behaves afterwards. A break-glass that could turn off monitoring would be a documented
  way to go dark.
- **Loud by construction.** Every window and every action inside it is appended to
  `break-glass-audit.log` and rides every mesh report, so a window opened during an outage is waiting
  in the console the moment the host reconnects: a **⚠ break-glass** badge with time remaining on the
  host card, a quieter "break-glass used" badge afterwards, and a drill-in panel naming who, why, how
  long, and how many actions were taken under it in the last fortnight.
- **No unreachability precondition.** Anyone who can open a window can also cut the network, so
  requiring the mesh to be down would add no security while blocking legitimate use on a flaky link.
  The mesh records the reachability instead — a window opened while it was reachable is the case worth
  asking about.

## macOS agent 0.9.25 · Linux agent 0.9.24 · Mesh 0.7.7 — 2026-09-22

### Added

**Metrics over a timeframe, fleet-wide or per customer.** The Metrics tab aggregated every lifecycle
timing an agent had ever recorded, which answers no question anyone asks. It now takes a period — last
7 or 30 days, this or last month, this or last quarter, the year, or a custom range — and follows the
site switcher, so per-customer metrics use the same control as every other view.

`/api/metrics` accepts `?from=&to=` (epoch ms) and filters against the agent's own lifecycle records,
so the endpoints do the work and only summaries travel. An alert belongs to a period by **when it was
raised**, which keeps it in exactly one period even if its investigation ran past month end.

**The monthly report fills in its own figures.** Machines, response actions, investigations opened and
hunts run are now counted *for the report's period* instead of all time, and the response times
(MTTD/MTTI/MTTR/MTTC) plus alerts raised are pulled live from that customer's endpoints for the same
window. It fills blanks only — anything the analyst typed stays, with a "re-pull and overwrite" link
for when the fresh number is wanted. A period that cannot be parsed ("last month") is called out
instead of being quietly reported as all-time.

**A hunt journal that survives a restart.** "We ran N hunts for you" is a claim in a document sent to
a customer, so it is now recorded to `mesh-hosts.json` as hunts run. Only operator-run hunts are
counted: fleet SQL hunts and Velociraptor queries. The `apiget`/`apipost` relays that carry drill-in
views and config pushes are not hunts — every drill-in tab queues one, so counting the live job table
would have reported thousands of hunts a month.

### Fixed

**Every monthly report has said "0 investigations".** `_report_facts` called `mincidents.snapshot()`,
a method `MeshIncidentStore` has never had, inside a bare `except` — so the count silently fell back
to zero on every report ever generated. Investigations are now matched to a site through their member
hosts (they carry no site of their own) and counted within the report's period.

## macOS agent 0.9.24 · Linux agent 0.9.23 · Mesh 0.7.6 — 2026-09-22

### Fixed

**The host drill-in's Alerts tab counted a different set of alerts than the host holds.** It pulled
`/api/alerts`, which returns only the non-closed set, then labelled its tallies "matches the host's
own view". On a real machine that read *4 closed, 60 suppressed* against a host holding **18,620
closed and 691 suppressed** — the four were alerts the stored table calls open but triage.json has
since closed, and the sixty were suppressed-but-open rows. The host's own Alerts tab asks for
`?all=1` (the full archive); the drill-in now asks for the same thing, through one constant so the
tab's path and its cache key cannot drift apart again.

**Counts described the relay, not the machine.** The relay caps a view at 2,000 rows, so on a large
archive the console was counting what fitted in the transport. `/api/alerts` now also returns `total`,
`closed_total` and `truncated` — one indexed count each, independent of any LIMIT — and the drill-in
says which number is which: *"showing the most recent 2,000 of 9,025 alerts on this host · 9,000
closed in total — the counts below describe this slice."* An agent older than the console sends no
totals, so a full 2,000 rows is reported as a slice without inventing a number for it.

## macOS agent 0.9.23 · Linux agent 0.9.22 · Mesh 0.7.5 — 2026-09-22

### Changed

**Investigations are ordered as a worklist: open above closed, then severity, then most recent
first.** They were sorted by severity alone, so a closed critical outranked an open high and the list
read as unordered to anyone actually working it. Whether a case is still open is the first thing that
matters; severity decides the order within each block.

Applied in the same place for all three consoles — the incident store's own `list()` — so every
caller gets the same order rather than each view sorting differently.

Ties are broken by case number. `updated` / `last_seen` are whole seconds, so cases touched in the
same second previously fell back to dict order, which is precisely the arbitrariness this fixes.

## macOS agent 0.9.22 · Linux agent 0.9.21 — 2026-09-22

### Removed

**The "Join a Scouter Mesh?" startup prompt.** A fresh agent is a single-host tool, and it now stays
one until you go looking for more. The prompt asked every new install to make a decision about fleet
infrastructure it probably did not have, using words ("aggregator", "enrollment token") that mean
nothing until you already run a mesh — confusion at exactly the moment a first-time user should be
looking at their own machine.

Nothing about mesh reporting itself changed. The **Scouter Mesh** panel in the sidebar is unchanged
and still the whole configuration — URL, token, interval, display name, Enable, Save, Test — and
`--mesh-url` / `--mesh-token` still configure a host at launch for a managed deployment. What is gone
is being *asked*.

- `should_prompt()`, `set_prompt()`, the `prompt` field in `mesh-settings.json`, the `prompt` key in
  `/api/mesh`, and the `action=prompt` endpoint are all removed. An existing settings file carrying a
  stale `prompt` key loads fine; the key is ignored and dropped on the next save.
- The panel's blurb no longer says mesh reporting is "read-only", which stopped being true when
  remote containment became an opt-in toggle directly below it. It now says telemetry flows out only
  *unless you opt in to remote containment*.

## macOS agent 0.9.21 · Linux agent 0.9.20 · Mesh 0.7.1 — 2026-09-21

### Added

**Encoded payloads are decoded, and then re-checked by the detection rules.** Attackers wrap the part
of a command that would give them away — base64, hex, percent-encoding, gzip, UTF-16, often layered.
Scouter now unwraps what it finds in command lines, job programs, shell commands, auth messages and
URLs, up to four layers deep, and hands the result back to the rule engine.

- **A rule that cannot see through base64 matches the moment the text is decoded.** The alert then
  carries its own reason — *"Decoded base64 payload matches: Download piped into a shell"* — and takes
  that detection's severity. Layered wrapping is named as such (`base64 → base64`), because the nesting
  is itself a signal.
- **A Decoded payload panel** in the alert detail, in both the endpoint console and the Mesh: each
  layer, which field it came from, its size, and any detection that matched inside it.
- **Severity only moves when a detection matches.** Decoded content on its own changes nothing: a
  base64 config value, a bearer token or a percent-encoded URL is shown in the panel and left at the
  severity it had. It is the rule hit inside the decoded text that raises the alert, and the reason
  line says which rule.
- **Bounded, because this is attacker-controlled input:** 64 KB per layer, four layers, decompression
  capped by output size (a 200 MB gzip bomb costs ~5 MB and is truncated), and results cached per
  source string. 800 nodes decode in about 6 ms. Nothing is executed — only decoded and matched.
- Rules see the whole decoded layer; the copy kept on the node for reading is trimmed to 2,000
  characters and says so, so a big payload doesn't ride along in every snapshot and fleet report.

**CyberChef, served from your own machine (optional).** CyberChef is Apache-2.0 and entirely
client-side, but its release is a ~79 MB zip, so Scouter doesn't ship it. Point `--cyberchef` at a copy,
or drop one in `vendor/cyberchef/`, and it is served from loopback. Every decoded layer then has a
**CyberChef ↗** link that opens it with the original blob loaded and the matching recipe pre-filled.
Without a local copy, the link offers the public instance behind a confirm that explains the trade-off
rather than quietly sending customer data to someone else's page.

**Copy buttons.** Every monospace block in the alert detail, and every value that looks like an
artefact (IP, hash, path, domain, URL), carries a one-click copy.

## macOS agent 0.9.20 · Linux agent 0.9.19 — 2026-09-20

### Changed

**A machine managed by a Mesh now has a read-only local console.** The endpoint console is the window
into that machine; the Mesh is the authority over it. Previously anyone at the keyboard could change
the response mode, disable automated response, close alerts, edit detections or unenroll the host from
its Mesh, which is the wrong arrangement for a monitored endpoint: The service someone is paying for
should make those changes, at their request.

- **Scope:** every state-changing local request is refused while the agent is connected to a mesh, with
  an error that says why. Everything readable stays readable, and hunting, lookups and rule dry-runs
  still work, because they change nothing.
- **The Mesh still writes,** through its own loopback relay. That relay now carries a second token the
  browser never sees, which is what lets the agent tell a mesh-issued change from a local one.
- **The console says so:** A banner across the top reads "Managed by your security provider. This
  console is read-only", and an attempted change explains itself instead of failing silently.
- **`--local-control`** opts out, for anyone running Scouter for themselves. Being read-only is the
  default whenever a mesh is in the picture.

## macOS agent 0.9.19 · Linux agent 0.9.18 · Mesh 0.6.24 — 2026-09-18

### Fixed

**Velociraptor results with more than one batch of rows were silently dropped.** With
`--format json`, `velociraptor query` does not print one JSON document. It streams rows in
batches of arrays joined as `][`, and a large result set crosses a batch boundary after roughly
11 KB. The Mesh parsed the output as one document, fell back to reading single-line objects, and
found none because rows are pretty-printed across many lines. It then returned **zero rows as a
success**. A fleet VQL query or compromise-assessment check with enough hits therefore reported
"nothing found". One captured pslist held 665 rows and came back as 0.

- All three components now ask for `--format jsonl` and parse the output with one shared function
  that also accepts concatenated arrays.
- Output that can't be read is now **an error, never an empty result**, because an empty result
  reads as "clean". This covers the Mesh's fleet queries and assessment, and the agents'
  Velociraptor response actions.

### Added

**Run Velociraptor queries from the agent's Hunt tab.** The Hunt tab has a new switch between
**History · SQL** and **Velociraptor · VQL**. VQL mode runs a query on this machine directly
through the local Velociraptor binary, with no server, and shows the results in the same table as
SQL hunts.

- **Canned queries:** processes, network sockets, users and system info on both platforms. macOS
  adds launch agents and daemons. Linux adds systemd units, cron jobs and SSH authorized keys.
- **Ask in plain English:** describe what you want and the AI writes the VQL into the editor.
  Unlike SQL hunts, generated VQL is **never run automatically**, because VQL can execute programs.
  You read it and press Run.
- **Guardrails:** VQL runs as root, so it is refused when response actions are locked
  (`--no-response`). Every query is written to the response audit log. The route is not reachable
  through the Mesh relay. Results are capped at 1,000 rows with a two-minute timeout.
- Launching the Velociraptor GUI from the Hunt tab still works as before.

### Changed

**The Mesh's Velociraptor "Ask in plain English" box now matches the SQL one.** It had a narrower,
differently styled input and a secondary button. It now uses the same full-width input and primary
**Generate VQL** button, and its header has a link to the AI settings.

## macOS agent 0.9.18 · Linux agent 0.9.17 · Mesh 0.6.23 — 2026-09-18

### Fixed

**Light mode's banners faded from white into near-black.** The agent header and the Mesh tab bar
each kept one hardcoded dark gradient stop, so in light mode they ran from white into near-black:
the agent's mode pills and hostname sat on the dark end, and on the Mesh every tab except Alerts
and Commands was effectively invisible. Both now read a theme token whose dark value is the
original gradient, unchanged.

### Changed

**Light mode now has structure instead of being a recoloured dark theme.**

- **A navy brand bar.** The header is a solid navy bar in light mode, and it carries the dark
  palette on itself, so its tabs, mode pills, Search, Restart and hostname render exactly as they
  do in dark mode rather than each being restyled.
- **Surfaces that separate.** A tinted canvas with white cards lifted off it by a soft shadow; the
  rail, the main pane and the cards no longer dissolve into one pale field.
- **Severity carries weight.** Severity tiles are tinted with their own colour, and the light
  severity and accent hues are more saturated while still clearing AA on white.
- Subtle white-alpha fills that vanished on white now darken slightly instead.

Contrast rose with it: inactive tabs 5.5 → 7.1:1, rail labels 5.1 → 6.6:1, the header title
12.2:1. Dark mode is unchanged: every new token's dark value is what dark mode already drew.

## macOS agent 0.9.17 · Linux agent 0.9.16 · Mesh 0.6.22 — 2026-09-17

### Added

**Light mode, in all three interfaces — and it follows your system by default.** Scouter has only
ever been dark. Plenty of people work in light, and on a bright screen a dark console is the
thing they have to work around all day.

- **Three states, not two.** *Match system* (the default) follows the OS through
  `prefers-color-scheme`, so a machine set to light opens light and one set to dark opens dark,
  with no setting to find. *Light* and *Dark* override that when you want one regardless.
- **Where:** the endpoint UI's left rail under **Appearance**, and the Mesh console's left rail
  under **Display**. The choice is remembered per browser and applied before the first paint, so
  there is no flash of the wrong theme on load.
- **The light palette is designed, not inverted.** Accent and severity hues are darkened to hold
  contrast on white, and the neutrals keep a slight cool bias so greys read as chosen rather than
  default. Every sampled text style clears WCAG AA: body 16:1, tabs 5.0–5.5:1, rail labels 5.1–5.9:1.
- Roughly 95 hardcoded colours across the three interfaces — scrims, the primary button, state
  tints, table hairlines, the header gradient, the graph canvas, toasts and badge text — were
  promoted to theme tokens first. Overriding the palette alone would have left light-on-dark text
  sitting on a light ground.

Dark is unchanged: the existing palette stays on `:root` and light overrides only the tokens.

<!-- mesh-only:start -->
## macOS agent 0.9.16 · Linux agent 0.9.15 · Mesh 0.6.20 — 2026-09-17

### Added

<!-- mesh-only:start -->

**The compromise assessment now hunts network/C2 and the persistence surfaces a launchd- or
systemd-only sweep walks past.** The first pack answered "what was installed"; it never asked "is
anything talking to infrastructure right now". Pack `2026.09` → `2026.10`, 14 → **34 checks**, each
tagged with a category so findings group the way a report reads.

- **Network & C2 (6 checks, both platforms):** listeners bound beyond loopback; established connections
  to public addresses with the owning process; ports C2 frameworks default to (Cobalt Strike 50050, the
  4444/1337/31337 family); tunnelling and remote-management agents — SMOKE#SCREEN pairs ScreenConnect
  with Cloudflare tunnels because both are signed and unremarkable; processes running from temporary or
  hidden directories; hosts file and DNS resolver configuration.
- **macOS persistence (8):** Background Task Management store (Login Items / SMAppService), cron tabs,
  periodic scripts and at jobs, shell startup files, `authorized_keys` (checked on Linux since the first
  pack and missing on macOS — an oversight), `LoginHook`/`LogoutHook`, system and kernel extensions,
  configuration profiles and managed preferences, and passwordless `sudo`.
- **Linux persistence (6):** udev rules, rc/init scripts and `update-motd.d`; systemd timers; kernel
  modules outside package management (VoidLink's C2 compiles a rootkit module per target kernel, which
  defeats hashing but still lands on disk); the `sshd` binary and the libraries it links
  (ELF/Sshdinjector); passwordless `sudo`; and the account database.

<!-- mesh-only:end -->

**8 new detections in both agents and the Mesh library** — macOS: remote-management agents, Background
Task Management writes. Linux: remote-management agents, udev `RUN+=` rules, rc/init scripts,
`update-motd.d`, kernel-module drops, and `sshd`/`libkeyutils` replacement. Factory libraries regenerated
(macOS 110, Linux 99).

<!-- mesh-only:start -->

### Changed

- **The network checks are filtered on the Mesh, not in VQL.** Velociraptor's reference documents no
  output columns for `netstat()` or `pslist()`, and a `WHERE` clause naming a column a build does not
  have returns zero rows — indistinguishable, in a report, from a clean estate. Those checks now ask for
  `SELECT *` and declare the field names their filter needs. If none appear, every row is shown with a
  note that the schema was not recognised; if they do, an empty result is reported as genuinely empty.
  The site scope is applied first and never fails open: one customer's rows cannot reach another's report.

### Still not exercised

The VQL has never run against a real Velociraptor server — only against stubs and fakes. Plugin behaviour
and field names vary by version, so the first engagement should still be a supervised dry run.

<!-- mesh-only:end -->

## macOS agent 0.9.15 · Linux agent 0.9.14 · Mesh 0.6.19 — 2026-09-16

### Added

<!-- mesh-only:start -->

**A one-click compromise assessment, per customer site.** The engagement that precedes monitoring: a
client signs, agents and Velociraptor clients deploy, and this answers what was already on the estate
before anyone was watching.

- **Hunt tab → Velociraptor card → “🔍 Launch VR and Run Compromise Assessment”.** Starts the VR server
  if stopped, maps the selected site's hosts to their VR clients, runs the pack, and groups findings by
  severity with the reasoning behind each check.
- **Per site by design.** It refuses “all sites”, a site with no hosts, and an unconfigured VR server —
  an assessment spanning two customers' estates would be a breach of both.
- **14 read-only checks** (pack `2026.09`) covering macOS LaunchAgent masquerading, relaunch-on-failure
  persistence, known 2026 staging paths, Full Disk Access grants and missing quarantine records; and
  Linux `ld.so.preload`, PAM module changes, hidden `/var/log` files, `authorized_keys`, systemd units
  from writable paths, XDG autostart, shell profiles and cron. Every check is a `SELECT`; nothing in the
  pack executes anything on an endpoint. New ops `assess` and `assess-pack` on `/api/vr-fleet`.

<!-- mesh-only:end -->

**21 new detections from current threat reporting**, in both agents and the Mesh library:

- **macOS (11):** LaunchAgents impersonating Apple or Google components (CrashStealer's
  `com.apple.crashreporter.helper`, SHub Reaper's fake Keystone agent), payloads in hidden Application
  Support directories, SHub Reaper's `/tmp/shub_` staging, ClickLock's `iCloudsync` backdoor, its
  password-prompt loop, browser Safe Storage key theft, TCC database reads, APFS local-snapshot mounting
  as a TCC bypass, wholesale keychain copies and bulk browser-profile collection.
- **Linux (10):** `/etc/ld.so.preload` writes and presence, PAM modules dropped outside packaging, QLNX's
  hidden `/var/log` credential log, rootkits compiled on the host from inline source, eBPF hiding
  components, XDG autostart and shell-profile persistence, SSH key harvesting and log wiping.

Each carries a description naming the family and mechanism, so an analyst reading an alert learns why it
matters. Sourced from published analysis by Jamf, SentinelOne, Trend Micro, Microsoft, Netskope, Group-IB,
Check Point, Elastic and Synacktiv.

### Changed

The Linux agent's `/etc/shadow` detection now also covers `strings`, `base64` and `xxd` (folded in rather
than added as a second, overlapping rule).

<!-- mesh-only:start -->

## macOS agent 0.9.14 · Linux agent 0.9.13 · Mesh 0.6.10 — 2026-09-15

### Added

**Decoys: bait credentials planted on every host.** Files no real user or service has a reason to use,
so that touching one is an intrusion signal rather than a judgement call. This is the first slice of the
deception work: credential decoys and bait-account detection. Detecting a decoy being *read* needs a
file-open sensor (fanotify on Linux, Endpoint Security on macOS) and comes next.

- **Five decoy types** per host: an extra AWS profile, a spare SSH private key, a kubeconfig, a Postgres
  password file and a saved SSH host entry. Each carries a **bait username** that exists nowhere else.
- **Generated per install.** Names, contents, bait username and timestamps differ on every host; Scouter
  is open source, so a fixed layout would be trivial to recognise.
- **Two detections.** A bait credential used anywhere is **critical** — matched against the login events
  the agents already record, including the failed attempts that never became alerts. A decoy deleted or
  edited is **medium** (T1078, T1110, T1021, T1070.004).
- **Fleet-wide attribution.** Each agent reports its bait username; the Mesh keeps the fleet's list and
  hands it back on every report, so any host recognises bait planted on any other. The alert then reads
  "planted on web-01, used here", and the Mesh shows a decoy pill per host plus a Decoys alert filter.
- **Safe by construction.** Only ever new files, never an edit to a real one; never inside a synced
  folder (iCloud, Dropbox, OneDrive, Google Drive); owned by the user whose home they sit in, mode 0600,
  timestamps backdated. Scouter hides its own decoys from the graph and its file monitor, and the
  registry mapping them is root-only. `--uninstall-service` removes them.
- **New API:** `GET /api/decoys` (status) and `POST /api/decoys` with `op=set` (enable/disable),
  `op=replant` (verify, then top up), or `op=fleet-bait` (the Mesh syncing bait names). Both are
  available to the Mesh relay.

### Changed

**On by default, opt out per scope.** Decoys plant themselves with no flag given, and a host connected
to a Mesh follows the Mesh's posture. Turn them off for one host with `--no-decoys` or the **Decoys**
panel in the left pane, or across a site from the Mesh's Config tab. Turning them off removes what was
already planted — an opt-out that left bait behind would keep firing alerts nobody owns.

## macOS agent 0.9.13 · Linux agent 0.9.12 — 2026-09-15

### Fixed

**The Mesh showed alerts the host had suppressed.** A host with no open alerts in its own Alerts view
appeared in the Mesh with 8 open, low-severity alerts from weeks earlier, every one of them silenced
by a suppression rule on that host.

The report to the Mesh left out suppressed alerts only while they were live in the graph, where
suppression lowers them to info. A stored alert whose process had already exited keeps its original
severity and was never checked against the suppression rules. Until 0.9.11 the report only looked at
the most recent alerts, which usually hid the problem. It now reads the whole open queue, which
brought older suppressed alerts back in.

Stored alerts are now matched against the host's suppression rules before they are reported, the same
way the host's own Alerts view does, so the Mesh alert list and severity counts match the host. Mesh
unchanged; update the agents.

## macOS agent 0.9.12 · Linux agent 0.9.11 · Mesh 0.6.9 — 2026-09-15

### Added

**Select several investigations and change them at once**, the way alerts already worked. Closing a
batch of investigations previously meant opening and closing each one in turn.

- **Agent (macOS and Linux), Investigations tab:** a checkbox on every investigation, *Select all
  shown*, and a bulk bar to set the selection to Open, Investigating, or Closed with any closure
  reason. Closing goes through the usual close dialog, so one note is recorded on every selected
  investigation. *Apply to their member alerts* carries the decision down to the alerts inside them,
  as the single-investigation control does.
- **Mesh:** the same selection on all three investigation lists: each host's investigations and
  Mesh investigations in the Investigations tab, and the Investigations tab of a host's detail panel.
  A selection can span hosts. Closing Mesh investigations also closes their member alerts, sent as one
  bulk request per host.
- **API:** `POST /api/incidents-bulk` on both agents, with a JSON body
  `{ids, status, substatus?, note?, cascade?}`. Every status is written under one lock with one save.
  Unknown ids are skipped and counted as `missing`. The endpoint is available to the Mesh relay.

### Changed

- **Agent close dialog** is titled for what it closes (alert, alerts, investigation, investigations)
  instead of always saying "Close alert". The bulk bar in both agents now wraps, since the
  Investigations list sits in a narrow column.

**Mixed fleets:** a Mesh on 0.6.9 uses the bulk endpoint when a host has it, and otherwise falls back
to one request per investigation, so hosts on older agents can still be managed in bulk.

## macOS agent 0.9.11 · Linux agent 0.9.10 · Mesh 0.6.8 — 2026-09-14

### Fixed

**The Mesh Alerts tab showed a fraction of each host's open queue.** A host with 233 open alerts
across 8 investigations appeared in the Alerts tab (with *Show Investigating* ticked) as 32 alerts
for the whole fleet. The sidebar counts and the Investigations tab were right, which made the gap
easy to miss. There were two causes, in the agent:

- **Only the top 25 were sent.** Each report carried a 25-alert preview, sorted by severity.
  Investigating alerts are mostly low severity, so nearly all of them fell off the end. The counts
  were computed before that cut, which is why they looked correct.
- **Older open alerts were never collected.** The feed read only the 2,000 most recent rows of the
  alert store, closed ones included, so a busy host silently lost older open and investigating
  alerts. It now reads the store exactly as the host's own Alerts view does: every non-closed alert.

### Changed

- **Agents send the whole open queue**, most severe first, up to 2,000 alerts per host, compressed.
  Before relying on that, an agent checks that the Mesh accepts compressed reports. Against an older
  Mesh it keeps sending the 25-alert preview, so upgrading agents first never breaks reporting.
- **Nothing is left out silently.** Reports carry `alerts_truncated`. The Alerts tab warns when a host
  sent less than its full queue (more than 2,000 open), when a host is running an older agent that only
  sends a preview, and when the fleet list exceeds 10,000 alerts.
- **Mesh:** accepts gzip-compressed reports, with a ceiling on decompressed size so a compressed
  body can't be used to exhaust memory; compresses large responses to the browser; keeps up to 2,000
  alerts per host. The Alerts tab renders 500 rows at a time with a *Show more* control.

**Upgrade order:** restart the Mesh first, then the agents. Until the Mesh is on 0.6.8, updated agents
fall back to the 25-alert preview.

## macOS agent 0.9.10 — 2026-09-14

**Full Disk Access now goes to "Scouter Agent", not to Python.** The background service previously
needed Full Disk Access granted to `Python.app`, which meant granting it to every Python script that
interpreter ever runs. The service now starts through a small signed launcher, and the grant names it.

- **Why it works.** macOS charges a process's privacy-protected access to the process *responsible*
  for it. A launchd daemon is responsible for itself, and its children inherit that. The launcher stays
  running as the agent's parent — it must not `exec` Python, or the process would be Python again — so
  it becomes the responsible process. Verified directly: run by launchd without the launcher, the agent
  is responsible for itself (Python.app); through the launcher, its responsible process is Scouter Agent.
- **Why it is deliberately inflexible.** A launcher holding Full Disk Access that ran whatever it was
  given would be a way around macOS's privacy controls — local malware could register its own launchd
  job pointing at it. So it runs only as root, only ever runs `agent.py` from its own install (arguments
  reach the agent as flags and are never executed), takes the interpreter from a root-owned file, and
  refuses to start if its executable, the install, the agent, that file, or any directory above them is
  writable by anyone but root.
- Exit codes pass through unchanged, so launchd's restart behaviour and the agent's own exit codes (78:
  port in use) work as before. Stop signals are forwarded. If the launcher dies, its agent goes with it
  rather than lingering on the port.
- The installer uses the launcher when the install carries one with a valid signature, and otherwise
  falls back to running Python directly with a warning — a tampered launcher is never used. The MDM
  profile now names Scouter Agent. `--service-status` shows which is in effect.
- About 250 lines of C in `launcher/`, built universal (Apple silicon + Intel) by `launcher/build.sh`.
  It ships **ad-hoc signed**, which ties its identity to that exact build, so rebuilding means granting
  Full Disk Access again. Sign it with a Developer ID (`SIGN_IDENTITY=… launcher/build.sh`) before
  deploying to other people's machines.

If you granted Full Disk Access to Python for 0.9.9, remove Python from that list after upgrading.

Not exercised: a real root install and an actual Full Disk Access grant — both need the machine owner.

## [0.9.9] — 2026-09-14

**Run Scouter as a background service: install once, root, starts at boot, restarts itself.**
Until now, full visibility meant a manual `sudo` every session and nothing survived a reboot.

```bash
sudo python3 agent.py --install-service   # macOS: LaunchDaemon · Linux: systemd
```

On macOS, `install.command` now offers this up front, and the launcher and `scouter` command simply
open the running service instead of starting a second agent.

A service that looked finished could have failed quietly in several ways, so the installer is
built around them:

- **It runs a root-owned copy** (`/Library/Application Support/Scouter/agent`, `/opt/scouter/agent`),
  never the checkout it was installed from. A root daemon executing code in a user-writable directory
  is a privilege escalation. It refuses an interpreter a non-root user could modify, and warns that
  python.org's framework is writable by the `admin` group.
- **Secrets survive reboots.** A daemon has no `SUDO_USER`, and a login keychain (or a Linux Secret
  Service keyring) isn't available at boot — so keychain-backed secrets, the Mesh token included,
  would have vanished after every restart. The service reads a root-only `0600` store instead, and the
  installer migrates every existing secret into it. A `--mesh-token` given to the installer goes there
  too, never into the plist or unit file, which any user can read.
- **State carries over** — baselines, rules, history (copied with SQLite's backup API), Mesh
  enrollment and quarantine — so nothing already known re-alerts as new. A reinstall upgrades the
  service's code, never rolls back a service that is already newer, and never overwrites its own state.
- **Full Disk Access is checked, not assumed.** macOS reserves that grant for the user or an MDM. When
  it's missing the installer opens the right Settings pane with the app revealed in Finder, waits,
  restarts the service and re-checks. For fleets it writes an MDM profile that grants access silently.
- **Uninstall is safe:** it always lifts host isolation (which would otherwise outlive the agent),
  refuses to strand other containment actions without `--force`, and never deletes quarantined files.
- **A taken port exits cleanly** with an explanation (exit 78) instead of failing mid-startup, and the
  service retries until the port frees — verified to recover on its own.
- **Desktop notifications still reach the user.** From launchd's system domain `osascript` reaches no
  one; they are now delivered into the logged-in user's session.
- **Logs are bounded.** On macOS the agent rotates its own log, because launchd holds the file open and
  an external rotator would rename it out from under the daemon. On Linux the journal handles it.

Not exercised here: installing as root into the real system domain (verified through a re-rooted
install and real launchd jobs in the user domain), and the systemd unit on a live systemd host
(verified by parsing it the way systemd does).

## [0.9.8] — 2026-09-10  ·  Mesh 0.6.7

**Fixed: the agent could make macOS credential prompts appear, repeatedly, with no explanation.**

The persistence collector runs `sfltool dumpbtm` every ten minutes to enumerate login and
background items. That command goes through macOS Authorization Services, so running the agent as a
**normal user** — rather than with `sudo` — puts a password dialog in front of whoever is logged in,
on the collector's own schedule, with nothing tying it to anything they did.

That is unacceptable in a security product, and not only because it is infuriating. It conditions
people to type their password into unexpected dialogs, which is exactly the reflex phishing depends
on. A tool that teaches users to trust surprise credential prompts has made them less safe, whatever
it detects in return.

- Commands that require root **and** can raise an authorization prompt (`sfltool`, `profiles`,
  `fdesetup`) now go through a guard that simply does not invoke them without root. No dialog can
  appear, because the command never runs.
- The resulting blind spot is **named, not hidden**. The persistence sensor reports which sources
  privilege denied it, and the Sensors card — on both the endpoint and in the Mesh drill-in — shows
  the sensor as *degraded* with the specific text "NOT COLLECTED without sudo: …". An operator who
  believes persistence is covered when it isn't has the worst kind of blind spot: an invisible one.
- Unprivileged sources (system extensions, kexts, launch agents) are unaffected and still collected,
  so a non-root agent degrades rather than failing.

Running with `sudo` is still the recommended deployment and collects everything, as before.

## [0.9.7] — 2026-09-09  ·  Mesh 0.6.6

Two controls that gate open-source publication, plus a logging fix found while testing them.

**Agent-silence alerting.** A userspace agent has no kernel-level tamper protection, so an agent
that stops reporting — killed, uninstalled, or network-blocked — is the strongest tamper signal
available. It previously only greyed out on the roster, which nobody is watching at 3am. The Mesh
now raises a **high-severity alert (T1562.001)** naming the host, how long it has been quiet, and
its last contact time, generated on the Mesh precisely because a killed agent cannot report its own
absence. It requires three consecutive missed windows so a closed laptop lid doesn't page anyone,
never duplicates while a host stays quiet, and retires itself when the host returns.

**AI prompt minimisation.** Bring-your-own-key transfers the commercial relationship with the model
provider, but not responsibility for what goes into the prompt — the customer picks the destination,
this software picks the payload. Two controls, both on by default:

- A **field allowlist**: only named fields may ever appear in a prompt, so a new detection field
  cannot leak by default. It is structural, and applies even with redaction disabled.
- **Identity redaction**: the local username, this hostname, and internal (RFC1918/link-local)
  addresses are replaced before anything leaves the host. Public addresses, ports, process names
  and command structure survive — they are the adversary's infrastructure and the model needs them
  to judge a threat. `--ai-no-redact` opts out. The Mesh applies the same treatment to its own
  cross-host prompts, identifying hosts by a stable pseudonym rather than by name.

**Fixed: logs were invisible in real time.** Python block-buffers stdout when it is redirected, so
under systemd, nohup, or a container — every way this actually runs — operator-visible events sat in
an 8KB buffer until the process exited. Found because the new silence alert didn't appear in a log
file during testing. All three components now line-buffer their output.

## [0.9.6] — 2026-09-05  ·  Mesh 0.6.5

**Fixed: fleet search silently hid whole categories of match.** Searching the Mesh for a term found
the network connections but not the downloaded file of the same name, while the endpoint's own
search found both.

The search runs one `UNION ALL` across processes, connections, downloads, files and hashes under a
single `LIMIT`. SQLite fills that limit from the branches in order, so a term matching hundreds of
connection rows consumed the entire budget and **every later category returned nothing at all** —
not a truncation the operator could see, just silence. Searching "github" on a real host returned 40
rows, all connections, hiding a downloaded file and eight file-integrity matches.

- Each source now carries its own limit, so no category can starve the others, and each branch is
  `DISTINCT` — the repeated rows that caused the flooding were mostly the same few addresses.
- The endpoint's search had the same query, and the same latent bug; it was masked because the
  endpoint also searches its live graph, which the Mesh has no equivalent of. Fixed in both.

## [0.9.5] — 2026-09-04  ·  Mesh 0.6.4

**Fixed: SQL detections fired without the evidence needed to judge them.** A brute-force alert
reached an analyst (and the AI reviewer) as nothing but *"matched 1 row(s)"* — no account, no source
address, no count, no timeframe. The AI's own verdict was the diagnosis: *"Alert lacks detail …
Cannot confirm true positive or dismiss as benign."*

The detection **library** was largely sound — nine of eleven chains already selected the right pivot
columns. The plumbing threw them away:

- **The matched row is now folded into the alert's reason text**, so every surface benefits at once —
  the endpoint UI, the Mesh alert list, exports, notifications and the AI reviewer. That brute-force
  alert now reads: *user=admin · failures=14 · sources=198.51.100.23 · first_failure=… ·
  last_failure=… · succeeded_after=0*. Custom SQL detections get this for free.
- **The AI reviewer now receives the matched rows, their columns, and the query.** Its payload
  hand-picked process/network fields (`cmdline`, `path`, `raddr`, …) that a correlated `detection`
  node simply does not have, so the model was handed a label and a row count and — correctly —
  declined to judge.
- **Two real content gaps closed:** the brute-force chain never selected `source`, so it could not
  say where the attempts came from; the mass-file chains counted files without naming one.

**Mesh: shipped fixes to built-in detections now actually reach an existing console.** The 0.9.4
top-up was strictly additive, so a *corrected* rule's stale copy would have kept overriding the fix
on every agent forever. Built-ins are now refreshed while they still match the definition they were
installed with (tracked per rule), and left untouched once edited — with the operator's tuning
(enabled, severity) carried across either way. Libraries predating this only refresh on a signature
the project is certain it shipped, so a local edit is never mistaken for an old release.

<!-- mesh-only:start -->

## [0.9.4] — 2026-08-28

**Fixed: newly shipped detections never reached an existing Mesh library.** The rule library is
seeded from the bundled factory files *once*, on first start, and is the operator's to edit
thereafter — so a console created earlier kept showing the counts it was built with (70 macOS /
36 Linux) no matter how many built-ins later releases added. The 0.9.0 fix added a top-up for the
multi-stage chains but not for node rules.

- Every start now tops the library up with any factory rule whose id it does not already have,
  for both node rules and chains, and bumps the library version so agents re-sync. Existing
  libraries move to **97 macOS / 83 Linux detections + 11 chains**.
- The top-up is strictly **additive**: a rule already in the library is left exactly as it is,
  because the operator may have retuned its severity, edited its conditions or disabled it, and a
  refresh that overwrote those would silently undo real work. Custom rules are untouched.

**Velociraptor deployment now installs the binary.** Deploying the fleet client to a host that
doesn't have Velociraptor previously just failed. Endpoints missing the binary now fetch it
themselves from the official GitHub release (the same host allow-list and checksum the endpoint
panel uses) before enrolling, so a rollout no longer requires visiting each host first. A second
button deploys only where the binary is already present.

## [0.9.3] — 2026-08-28

**Fleet Velociraptor.** The endpoint UI could already run Velociraptor standalone against one host;
the Mesh now runs it as a real deployment — the mesh hosts the VR server, endpoints run VR clients
that report to it, and a VQL query reaches the whole fleet at once. New panel in the Mesh **Hunt**
tab: generate the configuration, start/stop the server, deploy the client to a scope of hosts, and
run VQL (with canned queries for enrolled clients, hunts and artifacts).

- The mesh generates the server config, the client config, and an API client for itself, and grants
  that API user its role before the server boots.
- Client deployment rides the existing authenticated command channel as a new `vr-deploy` command;
  each endpoint writes the config `0600` and starts its client. The endpoint **localizes the
  writeback path** to sit beside the agent — Velociraptor otherwise writes it to `/etc`, which needs
  root and scatters state outside the agent's directory.
- Server-context queries (`clients()`, `hunts()`) go through the running server's API. A standalone
  datastore query reports zero clients even when endpoints are enrolled and connected, so the API
  path is used whenever the server is up, falling back to the datastore when it is stopped.
- Security: the server config holds private keys — `0600`, gitignored, never returned by any
  endpoint. Only the client config is distributed. VQL can execute programs, so every entry point is
  admin-token gated. The GUI and API bind to loopback.

## [0.9.2] — 2026-08-28

**Fixed: AI in-the-loop never saw the highest-value alerts.** The AI stage only queued an alert when
a reversible action was available for it, which conflated *"can I act?"* with *"should I look?"*.
Correlated findings from the multi-stage chains are `detection` nodes with no single process or
address to act on, so a critical "credential access followed by outbound transfer" was dropped
before the model was ever called.

- High and critical alerts with no available action are now queued **assess-only**: the model
  reviews and records its reasoning, and because no action is offered it cannot act — verified that
  a model answering "act" on such an alert executes nothing. The audit records it as
  *"act (assessment only — no reversible action available)"* rather than a bare "act", which would
  read as though something had been done.
- **An exited process no longer offers `suspend`.** Ephemeral real-time exec alerts still carry a
  pid, but suspending a dead process does nothing and would report a misleading success.
- **A malformed model reply is now distinguishable from a considered hold.** The model sometimes
  answers in prose instead of the required format (for instance when it notices instruction-shaped
  text inside an alert payload). Failing safe to "hold" is correct, but it was silent and looked
  identical to a deliberate hold; it is now recorded as *hold (unparsed)* and counted.

## [0.9.1] — 2026-08-28

**Fixed: an enrolled host could be asked to "join a Mesh" after a restart, and silently stop
reporting.** If `mesh-settings.json` existed but couldn't be parsed, the agent's loader swallowed
the error and fell back to its defaults — which are indistinguishable from a fresh install. The host
then had no mesh URL (so it stopped reporting, leaving the console's restart command stuck at
*running*) and re-offered the onboarding prompt, on a host that was already enrolled.

- A settings file that exists but can't be read is now treated as an error, never as a fresh
  install: the prompt is suppressed, the unreadable file is quarantined as `.corrupt` for
  diagnosis, and the operator is told plainly that mesh settings are unreadable and reporting is
  paused. A CLI-configured agent self-heals on the next start.
- The agent no longer advertises the join prompt at all for a host with any mesh identity — an
  enrollment token lives in the Keychain, independent of the settings file, so it still proves
  enrollment even if the settings are lost. Enforced server-side (`should_prompt()`), so it holds
  for any client, with the UI gate tightened to match.
- The console now says why a restart that never came back failed ("the host restarted but never
  reported back…") instead of leaving it reading as *running* until it expired.

## [0.9.0] — 2026-08-28

**Independent second paths** — hardening the brittle single-rule techniques the depth score flagged.

- **4 file-sensor rules** giving persistence and anti-forensics a second, independent route:
  a persistence file (launch agent/daemon, cron, systemd unit, init script) created or replaced;
  a shell startup file created or replaced; `authorized_keys` created or replaced; a log/audit/history
  file deleted. These watch the *outcome* via the real-time file sensor, so rewording the command,
  using another tool, or writing from a compiled binary doesn't evade them.
- **2 mass-file chains**: ransomware-pattern rewriting (60+ creates/renames by one process in five
  minutes) and wiper-pattern deletion. Impact looks like a storm of file operations, not a command line.
- **Depth classifier**: SQL detections that aggregate over a window (`GROUP BY` + `HAVING`) are now
  recognised as correlation, alongside `JOIN`/`WITH`. `depth_override` is used — with the reasoning
  recorded on each rule — where a matched value is *mandated by the technique* rather than chosen by
  the attacker (`/Library/LaunchAgents/` is unevadable for launchd persistence; `/tmp/` is a preference).
- **Fixed a real SQL-guard bug**: the read-only guard rejected the word `create` (and `delete`, `drop`,
  …) even inside a quoted string, so any hunt or detection filtering on the `'create'` file event failed
  with "disallowed keyword". String literals are now stripped before keyword scanning — verified still
  blocking real DDL/DML, multi-statement, and quote-escape attempts.

Result — macOS: brittle 68 → 64, behavioural 14 → 16, independent paths 6 → **10**, debt 85 → 80.
Linux: brittle 62 → 57, behavioural 10 → 11, independent paths 5 → **10**, debt 77 → 71.

## [0.8.0] — 2026-08-28

**Coverage-debt pass** — paying down the techniques the depth score exposed as telemetry-only.

- **19 new detections on non-process nodes.** Of 81 built-in rules, 76 looked at processes; nothing
  targeted the TCC, account, job, host-state or remote-access nodes the collectors already emit.
  Added rules for privacy grants held by non-bundled binaries (input monitoring, Accessibility /
  Full Disk Access, Endpoint Security entitlement, screen recording, microphone/camera), hidden
  accounts and non-root uid 0, scheduled jobs running from drop locations / downloading-and-executing
  / masquerading as system components, disabled security controls, and enabled remote access.
  macOS 81 → 93 rules, Linux 72 → 79.
- **Two count-based chains**: repeated authentication failures (brute force, with any success that
  followed), and a successful remote login from a never-before-seen source.
- **Depth classifier corrected.** It graded a match on system-attested state (`uid == 0`,
  `hidden`, a TCC service constant) as "brittle string rule", the same as a command-line regex.
  Depth measures *evadability*: attacker-controlled text can be reworded, system state cannot.
  Rules resting purely on such state are now depth 3. This promoted exactly the 9 new state-based
  rules and **no pre-existing rule** — the depth-2 count is unchanged at 68 / 62.

Result — macOS: telemetry-only 28 → 17, behavioural 6 → 14, independent paths 3 → 6, debt 96 → 85.
Linux: 20 → 15, 6 → 10, 3 → 5, debt 82 → 77.

## [0.7.0] — 2026-08-27

**Beaconing detection** — finds command-and-control by its rhythm rather than its content.

- New **edge-triggered connection log** (`conn_events`): an outbound connection is recorded when it
  *appears*, so a held-open socket costs one row while a beacon leaves one row per beat. Roughly
  2–8k rows/day instead of the 300k–1.1M that logging every active connection every write would
  cost. Capped and aged independently (14 days / 200k rows).
- New always-on detection **`s-beacon-cadence`** scores interval regularity (squared coefficient of
  variation) per destination, catching beacons jittered up to ~30%. Gated on destination novelty,
  single-executable use, and a minimum of 8 beats over 30 minutes.
- Because the beacon detector and the existing drop→beacon chain are independent paths to the same
  technique, **T1071 is now graded depth 4** — the first technique to reach it on that basis.

## [0.6.0] — 2026-08-27

**Detection depth score** — replaces "techniques covered" (a vanity metric ATT&CK itself warns
against) with a grade that answers whether coverage would survive a competent actor.

- Every detection source is graded **0–4**: 0 none · 1 telemetry only · 2 brittle string rule ·
  3 robust behavioural (lineage, rarity, or a multi-stage chain) · 4 multiple independent paths.
  Derived automatically from each rule's own conditions — nothing is hand-annotated — with a
  `depth_override` field for the cases the heuristic gets wrong.
- The ATT&CK matrix now shades cells across **four steps instead of covered / not-covered**, with a
  depth legend and a **coverage-debt** banner naming how many techniques sit at depth 1–2. That
  list is the work queue; the coverage count never was.
- Mirrored in the Mesh fleet ATT&CK view, graded from the Mesh rule library.
- The Mesh factory library now ships the **multi-stage chains** as well as node rules, so the fleet
  can see and manage them (with a migration for libraries seeded before chains existed).

Honest result on the current rule set: 105 techniques "covered" on macOS, but only **9 at depth
3–4**. That gap is the point of the metric.

## [0.5.0] — 2026-08-27

Detection-engineering release: the first detections that key on *behaviour* rather than strings.

- **Process lineage** — `ppid_name` (previously advertised to rule authors but never populated —
  lineage rules silently never matched) plus an `ancestry` chain on every process node, including
  ephemeral real-time exec events.
- **Rarity primitives** — `exe_novel` / `exe_times_seen` / `exe_age_days` and `raddr_novel` /
  `asn_novel`, seeded from the history DB so novelty survives restarts.
- **New built-in detections** (macOS 70 → 81, Linux 62 → 72): shell-under-browser/document,
  shell-under-web-server (webshell/RCE), interpreter-under-SSH (macOS), never-before-seen binary
  executing from a drop location, web-service C2 (webhooks / paste sites / raw GitHub), and
  DNS-over-HTTPS from a command line.
- **AI-surface pack** — AI agent performing high-risk actions, MCP/tool-config tampering, AI API
  key theft, file exfiltration to model APIs, and exposed local LLM runtimes.
- **Multi-stage chain detections** — six always-on SQL detections correlating events across time
  and tables: download→execute, drop→beacon, discovery→credentials, credentials→egress,
  execution→persistence, and remote-login→hands-on-keyboard.

<!-- mesh-only:start -->

## [0.4.1] — 2026-08-27 (Mesh only)

- **Clearer investigation status in the Mesh** — investigation cards now mirror the endpoint UI's
  status text (plain uppercase, colour-coded: *investigating* amber, *closed* green) instead of an
  undifferentiated grey pill, and an investigation that is still open (open or investigating) is
  ringed in green with a lit green dot, matching the online-host indicator. Applies to single-host,
  multi-host, and host drill-in cards.

<!-- mesh-only:end -->

## [0.4.0] — 2026-08-27

- **Low-signal auto-triage** — low/medium alerts with no detection rule behind them (the always-on
  scoring heuristics: unsigned binaries, listening ports, reputation scores) are now auto-closed as
  `Auto-closed` instead of cluttering the open queue. Rule-driven alerts (built-in *and* custom) and
  anything high/critical are never touched, and alerts you've already triaged are left alone. The
  closure is non-silencing, so a recurrence is judged fresh.
- **Investigation resurfacing** — an auto-closed low-signal alert is automatically pinned to an
  investigation opened on its host within ±1 hour of when it fired, and reopened to *Investigating*,
  so opening a case gathers the surrounding context. The Mesh runs the cross-host half for
  **multi-host investigations**, sweeping every member host and (where the host accepts management)
  reopening the alerts on the host itself.

## [0.3.0] — 2026-08-27

Pre-launch snapshot of the full feature set. New this release:

- **Linux Atomic Red Team gap-fill** — 26 new always-on built-in detections (36 → 62 rules),
  lifting Linux ART exact coverage from 31 to 57 of 119 techniques (rootkit/LKM loads, UPX,
  on-host compile, DNS/ssh exfil, container escape, PAM tampering, systemd timers, destructive
  wipes, timestomping, discovery, and more), each with an analyst-facing explanation.

Scouter is a lightweight, dependency-free (pure Python 3 standard library) EDR/XDR toolkit for
macOS and Linux — a native agent per OS, one graph UI, one mesh.

### Endpoint agent (macOS & Linux)

- **Live relationship graph** of processes, network connections, and persistence/autostart
  jobs, scored with heuristics tagged to MITRE ATT&CK techniques.
- **Real-time events** via Endpoint Security (macOS) / audit (Linux).
- **Collectors**: downloads (quarantine + provenance), authentication, file-integrity
  monitoring, persistence & extension surface, TCC privacy grants, remote-access surface,
  accounts & privilege, security posture, and shell history.
- **Enrichment**: VirusTotal + URLScan reputation, offline STIX/TAXII + IOC-list feeds, and
  offline geo/ASN annotation. Secrets live in the Keychain (0600 file fallback).
- **Detection engineering**: built-in always-on ATT&CK detections, custom per-node live
  rules, and scheduled SQL detections over the local history DB, with alert suppression.
- **Threat hunting**: a SQLite history database with a query console and AI-assisted
  natural-language → read-only SQL.
- **Triage & investigations**: a triage-able alert queue and automatic correlation of
  related alerts into investigations.
- **Active response**: reversible-first containment (isolate host, suspend process, block
  IP, quarantine file, disable job — with undos), an ATT&CK-tactic response playbook, and
  optional autonomous auto-response and AI-in-the-loop stages, all gated and audited with a
  circuit breaker. Read-only by default.
- Self-contained, dependency-free web UI with a ⌘K command palette, an ATT&CK coverage
  matrix, a threat-group overlap explorer, a timeline, and a sensor-health panel.

<!-- mesh-only:start -->
### Scouter Mesh (fleet console)

- **Fleet roster + combined alert feed** with bulk triage and per-alert drill-in; telemetry
  stays on the endpoints (no centralized SIEM) — the mesh is a control plane and query bus.
- **Federated hunt**: scatter-gather read-only SQL across every endpoint's local history,
  host-tagged, over a long-poll channel that works through NAT.
- **Host Full view**: a read-only, near-real-time mirror of a host's own UI (process tree,
  nodes, alerts, detections, ATT&CK, investigations, rules, suppressions, playbook).
- **Fleet broad search** (⌘K): hosts, alerts, ATT&CK techniques, threat groups, and an async
  fleet-wide history search.
- **Fleet Sensor Health**: cross-platform collector-coverage roll-up — spot blind spots
  (real-time events off, non-root, slow scans, disabled history) across the fleet.
- **Fleet Timeline**: one chronological, host-tagged feed across every host's history DB.
- **Mesh-authoritative management**: detection library, response playbooks, and response
  posture (mode + auto-response) pushed to a host, an asset group, or the whole fleet;
  mesh-side asset-group tagging (servers / workstations / critical / OT).
- **Mesh AI-in-the-loop**: the mesh's own AI reviews and (per asset-group posture) acts on
  agent alerts using only the mesh's AI config — reversible + deterministically-bounded,
  with a circuit breaker and full audit.
- **Remote management & containment** over the write relay (admin-token gated), with a
  command audit trail and a running/done status lifecycle.
- **Multi-tenant sites** with per-site enrollment tokens and a global site switcher; remote
  enrollment-token rotation pushed to the fleet with a grace window.
- **AI-assisted hunting**, an AI-drafted alert-closure flow, and fleet-wide configuration
  push (set each feature's settings and account once, distribute over the encrypted relay).

<!-- mesh-only:end -->

[Unreleased]: https://github.com/superdedooperboy/Scouter/compare/mesh-v0.9.4...HEAD
[0.9.4]: https://github.com/superdedooperboy/Scouter/releases/tag/mesh-v0.9.4
[0.9.3]: https://github.com/superdedooperboy/Scouter/releases/tag/mesh-v0.9.3
[0.9.2]: https://github.com/superdedooperboy/Scouter/releases/tag/mesh-v0.9.2
[0.9.1]: https://github.com/superdedooperboy/Scouter/releases/tag/mesh-v0.9.1
[0.9.0]: https://github.com/superdedooperboy/Scouter/releases/tag/mesh-v0.9.0
[0.8.0]: https://github.com/superdedooperboy/Scouter/releases/tag/mesh-v0.8.0
[0.7.0]: https://github.com/superdedooperboy/Scouter/releases/tag/mesh-v0.7.0
[0.6.0]: https://github.com/superdedooperboy/Scouter/releases/tag/mesh-v0.6.0
[0.5.0]: https://github.com/superdedooperboy/Scouter/releases/tag/mesh-v0.5.0
[0.4.1]: https://github.com/superdedooperboy/Scouter/releases/tag/mesh-v0.4.1
[0.4.0]: https://github.com/superdedooperboy/Scouter/releases/tag/mesh-v0.4.0
[0.3.0]: https://github.com/superdedooperboy/Scouter/releases/tag/mesh-v0.3.0
