# Agent Access Audit — design spec (target: Scouter 1.16.0)

**Status:** proposal / unbuilt · **Author:** design pass 2026-11-18 · **Prereqs:** 1.14 AI-abuse subsystem,
1.15 offensive-AI layer (both shipped)

## 1. Problem

Scouter can today *inventory* a host's AI surface (agent CLIs, local models, MCP servers, instruction
files — `AISurfaceCollector`, [agent.py:9072](../../agent.py)) and *catch* a dangerous action taken under
AI lineage (`correlate_ai_agent_lineage`, F-series findings). What it **cannot** do is audit **agent
authentication and authorization** as its own stream:

- **No non-human-identity (NHI) inventory** — we never answer "which identities/tokens do agent *X*'s
  tools hold?" (`_mcp_record` keeps the env-var *names* at [agent.py:9347](../../agent.py) but goes no
  further).
- **No scope reading** — grep across both agents for scope-excess / least-privilege logic returns zero.
  We never say "this token carries `admin:org`."
- **No approved-target baseline** — the egress classifier scores the LAMEHUG *shape*
  ([agent.py:9420](../../agent.py)) but has no per-agent allowlist of hosts/APIs it is *sanctioned* to
  reach, so "agent reached an API it never used before" is invisible.
- **No file-reach audit** — an agent reading `~/.aws/credentials` or the login keychain is silent unless
  the *command* independently trips a dangerous-command rule.

**Goal:** monitor for unapproved / overly-scoped access by AI agents to applications, APIs and files,
using only read-only, on-host telemetry — no proxy, no MITM, no secret values ever read.

### 1.1 The wall (explicit non-goal)

True wire-level scope **enforcement** — observing every API call and the scope it was granted — requires
an egress proxy or an identity-provider connector. That is XDR-connector territory, already parked for
**v2.0** (see the `network-wire-detection-v2` note). This spec stays inside the host agent: it reads what
the box already records about identities, scopes and destinations, and it watches what AI-lineage
processes do. Everything here is best-effort against on-disk and process/network telemetry, and the spec
marks each limit where it bites.

## 2. Design principles (inherited from 1.14)

1. **Inventory, don't alarm.** Everything is catalogued; severity appears only where access is genuinely
   risky (world-readable credential, admin scope, unbaselined destination, sensitive-file reach).
2. **Never read secret values.** Names, paths, providers, and scopes-*as-already-recorded-on-disk* only.
   Reuse `_AI_AUDIT_SECRET_RE` scrubbing ([agent.py:829](../../agent.py)) on anything that could carry a
   value. A credential file's **presence and mode** are facts; its contents are not read.
3. **Privacy walls to Mesh.** On-host console gets detail; Mesh gets derived findings + counts over the
   existing `/api/ai-surface` relay. Nothing new is force-pushed; deep/opt-in data stays on-host.
4. **Learn-first.** Every baseline (identities, destinations, access pairs) has a learn-only first pass —
   a change flags only against a previously-seen state, never on first scan. Reuse the AISurface baseline
   file mechanism ([agent.py:9095](../../agent.py)).
5. **Posture-gated.** Anything that shells out (e.g. `gh auth status`) or does deep file-access auditing is
   opt-in behind a `SCOUTER_*` env gate and defaults off, mirroring `AIAuditCollector`
   ([agent.py:9940](../../agent.py)).
6. **Cross-platform with honest gaps.** macOS and Linux credential layouts differ; the macOS
   ESF-open-event limitation is called out in Phase 4 rather than papered over.

## 3. New finding family: `ai-access`

A distinct category from the F-series exposures (which are derived from static inventory); these are
identity/authorization findings, some stateful. All ATT&CK-mapped.

| ID | Finding | Default severity | ATT&CK | Phase |
|----|---------|------------------|--------|-------|
| `ai-identity-exposed` | A credential file an agent's tools reference is world-readable or writable by others | high | T1552.001 | P1 |
| `ai-identity-new` | A new identity/credential wired into an agent since baseline | low→medium | T1078.004 | P1 |
| `ai-scope-excessive` | A locally-recorded token/credential grants broad or admin scope | high | T1528 / T1098 | P2 |
| `ai-dest-unapproved` | An AI-lineage process reached a destination outside its learned/approved set | medium | T1071 / T1567 | P3 |
| `ai-access-sensitive` | An AI-lineage process accessed a credential store, key, or browser secret DB | high | T1552 / T1555 | P4 |

The full NHI inventory (scored or not) lives in `meta.ai_surface.nhi` and a new `/api/agent-access`
endpoint (local, **not** relay-whitelisted for raw detail; a summary relay carries counts).

## 4. Phases

### Phase 1 — Non-Human Identity (NHI) inventory

**What:** resolve, per agent and per MCP server, the concrete identities its tools are wired to —
presence, provider, kind, source path, and file posture. Never the value.

**Sources (all read-only):**
- **MCP `env` keys** (already captured) → classify each key credential-bearing via the existing
  `KEY|TOKEN|SECRET|PASSWORD|CRED` pattern, then map to a provider
  (`GITHUB_TOKEN`→GitHub, `AWS_*`→AWS, `OPENAI_API_KEY`→OpenAI, `ANTHROPIC_API_KEY`→Anthropic,
  `GOOGLE_APPLICATION_CREDENTIALS`→GCP, `SLACK_*`→Slack, …) via a `PROVIDER_ENV_MAP`.
- **MCP command/args** that reference a credential file or profile (`--credentials <path>`,
  `AWS_PROFILE=`, a `*.json` service-account path).
- **Well-known on-disk credential stores** reachable by the agent's user — *presence, path, mode,
  provider only*:
  - `~/.aws/credentials`, `~/.aws/config` (profile names, not keys)
  - `~/.config/gh/hosts.yml` (GitHub hosts/users)
  - `~/.config/gcloud/` (ADC + legacy creds), service-account JSON
  - `~/.kube/config` (context + cluster names)
  - `~/.npmrc`, `~/.pypirc` (presence of `_authToken` / `password` lines — line *presence*, scrubbed)
  - `~/.docker/config.json` (`auths` registry hosts)
  - `~/.ssh/` (key file inventory: names + `authorized_keys` presence, never key material)
  - `~/.netrc`, and `.env` files in discovered agent project roots (key *names* only, via scrub)
- macOS adds: login keychain presence (already partly under `TCCCollector`/security posture); Linux adds
  Secret Service / `pass` store presence.

**Output:** `meta.ai_surface.nhi = [ {provider, kind, source, mode, world_readable, writable,
used_by:[agent/mcp], present:true} … ]`. Baseline + change-watch via the AISurface baseline file (add an
`"nhi"` key alongside `"context"`/`"mcp"`).

**Scored findings:**
- `ai-identity-exposed` (high) — a referenced credential file is world-readable (`mode & 0o044`) or
  writable by group/other. This is the genuine exposure and fires even on first scan.
- `ai-identity-new` (low, →medium if the identity is admin-ish by name, e.g. `*_ADMIN_*`, `root`,
  `owner`) — a new identity appears after the learn-only pass.

**Privacy:** values never read. `.npmrc`/`.env`/`.netrc` lines pass through `_ai_audit_sanitise`
before any field is kept; only the credential *name* survives.

**Tests:** `test_nhi_inventory.py` — provider mapping; world-readable → `ai-identity-exposed`; learn-only
first pass raises nothing; a second-pass new identity → `ai-identity-new`; secret values never present in
any emitted node (assert the scrubber ran).

### Phase 2 — Scope reading (best-effort "overly scoped")

**What:** the honest path to "overly scoped." Read scopes **where they are recorded locally**, classify
broad/admin grants, flag them. Be explicit about what is and isn't readable.

**Readable on-disk (no external call):**
- **GCP** — `application_default_credentials.json` and service-account/authorized-user files carry a
  `scopes` array; service-account JSON carries the account email + project. Flag `cloud-platform`
  (full-access) and owner/editor-implying scopes.
- **OAuth client configs** that store `scope` (various agent integrations, `*.oauth.json`).
- **Kubeconfig** — context → cluster/user mapping; flag `cluster-admin`-bound users where the binding is
  locally visible.
- **Docker/registry** — `auths` presence per registry (reach, not scope).

**Readable only via a bounded, opt-in status call** (`SCOUTER_AGENT_SCOPE_PROBE=1`, default off):
- **GitHub** — token scopes aren't in `hosts.yml`; `gh auth status` prints `Token scopes: …`. Optional,
  rate-limited, read-only; output scrubbed of the token. Flag `repo` (full), `admin:org`, `workflow`,
  `delete_repo`, `admin:*`.
- Opaque tokens (npm/pypi/Slack bot tokens) have **no locally-recorded scope** → reported as
  `scope: unknown`, never guessed.

**Scored finding:** `ai-scope-excessive` (high) when a readable scope set intersects a
`BROAD_SCOPE_TABLE` (per-provider list of admin/full grants). Severity drops to medium if the identity is
not currently wired to any *reachable* (remote) MCP or running agent — i.e. dormant.

**Honesty caveat (document in-code and in the console tooltip):** scope coverage is partial by
construction — present for GCP/OAuth/kube/gh-opt-in, absent for opaque bearer tokens. The console must
show `scope: unknown` distinctly from `scope: none`, so an operator never reads silence as safety.

**Tests:** `test_scope_read.py` — GCP ADC with `cloud-platform` → excessive; kube cluster-admin → flagged;
opaque npm token → `unknown`, no finding; the gh probe is exercised behind a fake-binary shim and is a
no-op when the env gate is off.

### Phase 3a — DNS collection (default-on, best-effort)

**What:** a first-class DNS-query collector, so hunts and the P3 destination baseline can work at
**domain** granularity, not just IP. DNS is table-stakes security telemetry — on par with the
connections, auth and shell-history Scouter already collects, and less sensitive than shell history — so
it is **default-on (opt-out)**, consistent with the agent's standing posture, **not** gated behind an env
flag. Storage is a non-issue: records are deduplicated exactly like `connections` (one row per distinct
domain with `first_seen`/`last_seen`/`times_seen`), so the firehose of queries collapses to the host's
distinct-domain cardinality — typically hundreds to a few thousand rows (~1 MB), in line with IP storage.

**The real constraint is collection availability, not privacy or cost.** There is no universal read-only,
unprivileged, stdlib way to see every DNS query, so the collector is **best-effort by source** and reads
whatever the host actually exposes:

- **Linux** — a local caching resolver's query log when one is present and logging:
  `systemd-resolved` (journal, when query logging is enabled), `dnsmasq` / `unbound` / Pi-hole query
  logs. A stock glibc stub going straight to upstream leaves **no local log**; that host reports *no DNS
  source* rather than silently empty.
- **macOS** — the unified log (`log stream`/`log show` with an `mDNSResponder` predicate), bounded and
  parsed. Caveat: the query name is frequently redacted to `<private>` unless private-data logging is
  enabled — the same `<private>` redaction that already affects `AuthCollector`. Redacted queries are
  counted but recorded as `name: <private>`, never guessed.

**Schema:** a new `dns_events` table — `(id, ts, qname, qtype, proc_name, exe, pid, source, resolved_ip,
first_seen, last_seen, times_seen)` — mirroring `conn_events`’ dedup shape. `proc_name`/`pid` are filled
only where the source attributes a query to a process (resolver logs usually don't; the unified log
sometimes does); otherwise the row is host-level. `source` records which reader produced it
(`systemd-resolved` / `dnsmasq` / `unified-log` / …), so coverage is always legible.

**Honesty invariant (the thing to get right):** the collector's status always reports whether a DNS
source was found and which one. "No DNS events" must be distinguishable from "no readable DNS source on
this host," on the agent (`/api/dns` status) and in the Mesh, so an operator never reads an empty table
as a clean host. Bounded collection cost: dedup + a per-tick cap + drop-oldest, so a query storm can
never grow the table or the tick unboundedly.

**Hunts:** DNS is immediately huntable once collected — newly-seen domains, high-entropy / DGA-shaped
`qname`, excessive `qtype=TXT`/`NULL` (tunneling), a burst of distinct subdomains under one parent
(tunneling/beaconing), and `qname` ∩ domain threat-intel IOCs (today those IOCs only match domains pulled
from cmdlines/URLs — with `dns_events` they match actual lookups). Advisory-hunt + VQL twins where they
fit.

**Tests:** `test_dns_collect.py` — a synthetic `dnsmasq`/`unbound` log line and a synthetic unified-log
line each parse into a `dns_events` row; dedup collapses repeats into `times_seen`; a `<private>` macOS
line is counted but carries no guessed name; a host with no source reports `source: none` (status), not an
empty success.

### Phase 3 — Approved-destination baseline (egress authorization)

**What:** extend the existing lineage-tagged egress classifier so each agent has a learned set of
destinations it normally reaches; flag a *new* one. With P3a present, the baseline and the finding key on
**domain** where a `dns_events` lookup can be correlated to the connection (by `resolved_ip` or a
close-in-time lookup from the same process), falling back to IP/host otherwise.

**Mechanism:** `_classify_egress` / `_gather_egress` ([agent.py:9420](../../agent.py)) already tag a
connection with its AI lineage and provider. Add a per-agent (keyed by agent base name, not ephemeral pid)
destination baseline `{agent → set(provider|domain|host)}` persisted in the AISurface baseline file. After
the learn-only pass, a connection/lookup to a destination not in that agent's set **and** not a known
first-party AI provider raises:

- `ai-dest-unapproved` (medium, T1071/T1567) — "agent *X* reached `api.example.com`, a destination it had
  never used." Deduped per (agent, destination). Escalates to high if it correlates with an
  `ai-identity-new` from P1 in the same window (new identity + new destination = the strongest
  unapproved-access signal).

**Scope control:** domain/host granularity only (we already avoid querystring/token capture). Known AI
providers (the LLM egress allow-list) are excluded so this doesn't fire on ordinary model calls.

**Tests:** `test_dest_baseline.py` — learn-only records, no alert; a post-baseline new destination under
AI lineage → `ai-dest-unapproved`; a known-provider call never fires; correlation with `ai-identity-new`
escalates to high; a connection correlated to a `dns_events` lookup keys on the domain, not the IP.

### Phase 4 — Agent file-reach / credential-access audit

**What:** the "unapproved/overly-scoped access to files" the request named. When an AI-lineage process
touches a sensitive credential/secret path, raise an access-audit event — *even when the command is
otherwise benign* (today it's silent unless the command matches a dangerous-command rule).

**Sensitive set (`SENSITIVE_ACCESS_PATHS`):** cloud cred files (`~/.aws/credentials`, gcloud, service
accounts), `~/.ssh/id_*` + `authorized_keys`, kubeconfig, `~/.docker/config.json`, browser cookie/login
DBs (`Cookies`, `Login Data`, Firefox `logins.json`), password-store dirs, `.env` in non-agent project
roots, and the macOS login keychain files.

**Signal by platform (the honest part):**
- **Linux** — map AI-lineage pids → open file descriptors via `/proc/<pid>/fd` on the collector tick
  (read-only, pure stdlib). An AI-lineage process holding an fd onto a sensitive path → event. Also catch
  cmdline references to the paths (covers short-lived reads a tick can miss).
- **macOS** — ESF does **not** cheaply deliver file-open events (noted in the deception-layer design), so
  there is no live open-event stream. Fallbacks: (a) cmdline/argv reference to a sensitive path under AI
  lineage; (b) a periodic `lsof -p <ai-pid>` for *running* agents behind the opt-in deep gate. macOS
  coverage is therefore weaker than Linux for silent reads; the console states this per-OS.

**Scored finding:** `ai-access-sensitive` (high, T1552/T1555) — scored by whether the (agent, path) pair
is baselined. A first observation during learn-only is recorded, not alarmed; a *new* (agent, path) pair
after baseline, or any access to a credential store the agent has no declared identity for in P1, fires.

**Privacy:** record `{agent, path, action, ts}` only — never file contents, never the secret.

**Tests:** `test_access_audit.py` — Linux `/proc/<pid>/fd` symlink to a sensitive path under a faked AI
lineage → event; benign non-AI process reading the same path → nothing; learn-only suppresses the first
pair; a new post-baseline pair fires; emitted node carries no content field.

### Phase 5 — Mesh fleet rollup + console

**What:** surface the whole picture fleet-wide and on the local console.

- **Local console:** a new **Agent Access** view (or an "Access" sub-tab under AI Surface) showing, per
  agent: the NHI inventory (P1), scope flags (P2), its approved vs. recently-new destinations (P3, at
  domain granularity where P3a resolved it), and sensitive-access events (P4). A fleet **DNS** view / hunt
  surface rides on the P3a `dns_events` table. Reuse the existing AI Surface tab scaffolding; respect the
  `showTab`/pane-visibility gotcha (`mesh-console-tab-gotcha`) when adding a fleet tab. Each host's DNS
  panel states its `source` (and `none` where no DNS source exists), honoring the P3a honesty invariant.
- **Mesh:** derive the fleet view client-side from the read-only `/api/ai-surface` relay plus a new
  `/api/agent-access-summary` (counts + scored findings only; raw NHI detail is **not** relay-whitelisted,
  same wall as `/api/ai-audit`). New fleet tiles: *Exposed agent identities*, *Excessive scopes*,
  *Unapproved destinations*. Each scored finding lists in the fleet Exposures feed with host + severity +
  ATT&CK. No new agent-push channel — version-robust, derived.
- **Advisory/VQL twins** where a hunt form makes sense (e.g. "agents holding admin-scoped tokens across
  the fleet", "world-readable cloud credentials across the fleet"), following the shipped advisory-hunt
  pattern + the `TestAdvisoryFleetVql` guard.
- **Mesh version bump** (next on the console track) + factory export regen
  (`python3 ~/mac-scouter/tools/gen-mesh-builtins.py`) so `builtins-*.json`/`collectors-*.json` stay
  fresh and `test_factory_export` passes.

### Phase 6 (optional) — Policy & response

Turns "new vs baseline" into a first-class **approved/unapproved** concept and wires reversible response.

- **Policy file** (operator-defined, per agent): approved identities, approved destinations, max scope.
  Then `ai-dest-unapproved` / `ai-identity-new` evaluate against *policy*, not just the learned baseline,
  and the console shows a true allow/deny.
- **Response, reusing the shipped reversible ladder:** quarantine a world-writable agent config/instruction
  file (already supported); where the MCP-quarantine channel exists (1.14 P6), offer to remove an MCP
  server wired to an over-scoped or exposed identity. Kill/host-isolation remain **never** fleet-pushable,
  per the existing containment rule.

## 5. Privacy & data-flow summary

| Data | Read? | Stored on-host | Sent to Mesh |
|------|-------|----------------|--------------|
| Credential **values** | **never** | no | no |
| Credential names / paths / provider / file mode | yes | `/api/agent-access` (local) | no (counts only) |
| Scopes as recorded on disk | yes | local detail | derived finding + count |
| Egress destinations (host/domain granularity) | yes (already) | local | scored finding only |
| DNS queries (qname, qtype, proc where available) | yes, **default-on** (P3a) | `dns_events`, deduped | counts + hunt surface |
| Sensitive-file access events (agent, path, ts) | yes | local | count + scored finding |

## 6. Versioning & scope

- **Target: 1.16.0, both agents** (the AI surface is cross-platform; P1–P3 are OS-portable, P3a and P4
  have documented per-OS source gaps). Follows `per-agent-version-drift` only if a phase ends up touching
  one OS — but the intent is a joint 1.16.0.
- **Mesh:** one console bump at P5 (next number on the Mesh track).
- **Posture gates:** `SCOUTER_AGENT_SCOPE_PROBE` (P2 gh probe) and the deep file-access opt-in (P4 macOS
  `lsof`) are default-off and surfaced in `/api/ai-surface` config like the existing opt-ins. **P3a DNS
  collection is default-on (opt-out)**, consistent with the agent's standing posture — DNS is baseline
  security telemetry, not a deep probe; its only "gate" is whether a readable DNS source exists on the
  host, which the collector reports.
- **Storage:** P3a adds a `dns_events` table; deduped like `connections`, so it is bounded by distinct
  domains (~1 MB), not query volume.
- **Factory export** regenerated at P5; new tests per phase; suites must stay green
  (mac/linux/mesh) as in every prior release.

## 7. Suggested build order

P1 (NHI inventory) is the spine — it gives P2 (scopes hang off identities), P3 (new identity ↔ new
destination correlation) and P4 (does the agent even have a declared identity for the store it read?) their
join key. Recommended sequence: **P1 → P2 → P4 → P3a → P3 → P5**, with P6 gated on review. P3a lands
immediately before P3 so the destination baseline can key on domains from the start; it is also useful on
its own (a DNS hunt surface) independent of the rest of the Access Audit. P1 alone is a shippable
increment (an NHI inventory + the world-readable-credential finding) and the cheapest way to see this
against real data on one box before committing to the rest.
