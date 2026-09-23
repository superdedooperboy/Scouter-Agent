<!-- Thanks for contributing! Please read CONTRIBUTING.md if you haven't. -->

## What & why

<!-- What does this change, and what problem does it solve? Link any related issue. -->

## Component(s)

- [ ] macOS agent (`agent.py` / `index.html`)
- [ ] Linux agent (`linux/agent.py` / `linux/index.html`)
- [ ] Docs / tooling

<!-- Reminder: shared agent behaviour usually needs to land in BOTH agents to keep parity. -->

## Verification

<!-- Paste the results. CI runs the first two automatically, but please confirm locally. -->

- [ ] `python3 -m py_compile agent.py linux/agent.py` passes
- [ ] `cd linux && python3 -m unittest discover -s tests` passes
- [ ] If the web UI changed, I verified it renders/works in the browser (screenshot welcome)
- [ ] Added/updated tests where the change is unit-testable

## Constraints

- [ ] I have signed the [CLA](../CLA.md) (a bot will prompt you on your first PR)
- [ ] No new third-party runtime dependencies (Scouter is stdlib-only)
- [ ] Secrets/tokens do not reach the browser, the mesh payload, argv, or logs

## Security-sensitive areas

<!-- Check any this PR touches, and describe how you kept the guarantees intact. -->

- [ ] Write path / CSRF+Host guards / mesh relay
- [ ] Enrollment-token or admin-token gates / read-only hunt boundary
- [ ] Response / containment / auto-response / AI-in-the-loop guardrails
- [ ] Parsing of attacker-controlled telemetry
- [ ] None of the above
