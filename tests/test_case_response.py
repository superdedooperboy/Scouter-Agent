#!/usr/bin/env python3
"""Investigation escalation, and the response bound to a case rather than to one alert.

Two things that only make sense together. A case gets worse when a member worse than anything
already in it correlates in — which used to happen in complete silence, so the response chosen
while the case looked milder simply stayed chosen. And nothing could express "this case is now
critical, contain all six of its members", because every binding available was to a single
artifact: a tactic, a detection, a confidence rating.

The risky direction here is over-reach, not under-reach: a case is a correlation and correlation
can be wrong, so most of these tests are about what a case must NOT be able to talk the machine
into — acting on a closed case, stacking weak signals into certainty, or reaching an irreversible
action because a lot of alerts arrived at once.

Pure stdlib, like the agent. Run from the repo root:

    python3 -m unittest discover -s tests -v
    python3 tests/test_case_response.py           # same thing, single file
"""
import json
import os
import shutil
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
import agent  # noqa: E402

REGISTRY = {a["id"]: a for a in json.load(open(os.path.join(ROOT, "playbook-macos.json")))["actions"]}


# --------------------------------------------------------------------------------------------
# fixtures
# --------------------------------------------------------------------------------------------
def rule(rid):
    return next(r for r in agent.BUILTIN_RULES if r["id"] == rid)


def node(nid, rid, **extra):
    """An alert carrying one detection, shaped the way build_graph() emits it."""
    r = rule(rid)
    n = {"id": nid, "type": "process", "label": nid, "severity": r["severity"], "score": 70,
         "detail": {"pid": int(nid.split(":")[1]),
                    "rule_hits": [{"id": rid, "name": r["name"], "mitre": r["mitre"],
                                   "severity": r["severity"],
                                   "confidence": agent.rule_confidence(r)}]},
         "reasons": []}
    n.update(extra)
    return n


def in_case(n, severity="critical", size=4, status="open"):
    return dict(n, incident="c1", incident_severity=severity,
                incident_size=size, incident_status=status)


def playbook(test):
    d = tempfile.mkdtemp()
    test.addCleanup(shutil.rmtree, d, True)
    return agent.ResponsePlaybook(path=os.path.join(d, "response-playbook.json"),
                                  valid_actions=list(REGISTRY))


def store(test):
    d = tempfile.mkdtemp()
    test.addCleanup(shutil.rmtree, d, True)
    return agent.IncidentStore(path=os.path.join(d, "incidents.json"))


def cluster(meta, severity):
    members = list(meta)
    return {"members": members, "size": len(members), "severity": severity, "member_meta": meta,
            "member_labels": {m: meta[m]["label"] for m in members},
            "types": {"process": len(members)}, "techniques": [], "indicators": []}


# --------------------------------------------------------------------------------------------
class TestEscalationIsVisible(unittest.TestCase):
    """The upgrade already worked; what was missing was any trace that it happened."""

    def setUp(self):
        self.store = store(self)
        self.meta = {"proc:1": {"label": "curl", "severity": "medium", "type": "process"},
                     "proc:2": {"label": "osascript", "severity": "medium", "type": "process"}}
        self.store.reconcile([cluster(self.meta, "medium")])
        self.store.take_upgrades()

    def escalate(self, nid, label, severity):
        self.meta[nid] = {"label": label, "severity": severity, "type": "process"}
        inc, _ = self.store.reconcile([cluster(self.meta, severity)])
        return inc[0], self.store.take_upgrades()

    def test_an_upgrade_is_recorded_on_the_case(self):
        inc, ups = self.escalate("proc:3", "security dump-keychain", "high")
        self.assertEqual(len(ups), 1)
        self.assertEqual((ups[0]["from"], ups[0]["to"]), ("medium", "high"))
        events = [e for e in inc["events"] if e["kind"] == "severity"]
        self.assertEqual(len(events), 1)

    def test_the_record_names_what_caused_it(self):
        """"Raised medium to high" is a fact. "Raised by keychain dump" is actionable, and it is
        the difference between a log line and a lead."""
        inc, _ = self.escalate("proc:3", "security dump-keychain", "high")
        detail = [e for e in inc["events"] if e["kind"] == "severity"][0]["detail"]
        self.assertIn("security dump-keychain", detail)
        self.assertIn("medium", detail)
        self.assertIn("high", detail)

    def test_each_step_up_is_recorded_separately(self):
        self.escalate("proc:3", "security dump-keychain", "high")
        inc, ups = self.escalate("proc:4", "/tmp/shub_stage", "critical")
        self.assertEqual((ups[0]["from"], ups[0]["to"]), ("high", "critical"))
        self.assertEqual(len([e for e in inc["events"] if e["kind"] == "severity"]), 2)

    def test_a_case_settling_back_down_stays_quiet(self):
        """Members get triaged closed and the case drifts back down. That is housekeeping, and a
        banner for it would teach the operator to ignore the banners that matter."""
        self.escalate("proc:3", "security dump-keychain", "high")
        self.meta.pop("proc:3")
        inc, ups = self.store.reconcile([cluster(self.meta, "medium")])[0][0], self.store.take_upgrades()
        self.assertEqual(ups, [])
        self.assertEqual(len([e for e in inc["events"] if e["kind"] == "severity"]), 1)

    def test_upgrades_are_drained_not_replayed(self):
        """The caller notifies and re-opens response off this queue. Handing the same upgrade back
        twice would mean a duplicate banner every three seconds, forever."""
        self.escalate("proc:3", "security dump-keychain", "high")
        self.assertEqual(self.store.take_upgrades(), [])

    def test_a_brand_new_case_is_not_an_escalation(self):
        s2 = store(self)
        s2.reconcile([cluster({"proc:9": {"label": "x", "severity": "critical", "type": "process"},
                               "proc:8": {"label": "y", "severity": "critical", "type": "process"}},
                              "critical")])
        self.assertEqual(s2.take_upgrades(), [], "a case opening at critical never 'rose' to it")


# --------------------------------------------------------------------------------------------
class TestEscalationReopensTheDecision(unittest.TestCase):
    """The point of noticing is to reconsider. A member handled while the case looked mild must be
    eligible to be handled again at the level the case reached."""

    def setUp(self):
        self.r = agent.Responder.__new__(agent.Responder)
        import threading
        self.r.lock = threading.Lock()
        self.r.mode = "defensive"
        self.r.audit_file = os.path.join(tempfile.mkdtemp(), "audit.log")
        self.r._auto_seen = {"proc:1|vr_forensics", "proc:2|vr_forensics", "proc:9|suspend"}
        self.r._ai_seen = {"proc:1", "proc:9"}

    def test_members_of_an_upgraded_case_are_reconsidered(self):
        n = self.r.reopen_for_upgrade([{"id": "c1", "case_no": 1, "members": ["proc:1", "proc:2"]}])
        self.assertEqual(n, 2)
        self.assertEqual(self.r._auto_seen, {"proc:9|suspend"}, "only this case's members")
        self.assertEqual(self.r._ai_seen, {"proc:9"})

    def test_nothing_happens_without_an_upgrade(self):
        before = set(self.r._auto_seen)
        self.assertEqual(self.r.reopen_for_upgrade([]), 0)
        self.assertEqual(self.r._auto_seen, before)


# --------------------------------------------------------------------------------------------
class TestCaseMembershipAsEvidence(unittest.TestCase):
    """Correlation is evidence: an alert tied to others is likelier to be real than the same alert
    standing alone. That is the whole reason low-signal activity is kept and correlated."""

    def test_a_worse_case_lends_a_member_one_tier(self):
        alone = node("proc:1", "b-cloud-creds")
        self.assertEqual(agent._plan_confidence(alone), 1)
        self.assertEqual(agent._plan_confidence(in_case(alone)), 2)

    def test_it_lends_at_most_one_tier(self):
        """A pile of weak signals must not be able to manufacture certainty."""
        for sev in ("medium", "high", "critical"):
            n = in_case(node("proc:1", "b-cloud-creds"), severity=sev, size=50)
            self.assertLessEqual(agent._plan_confidence(n), 2)

    def test_a_case_no_worse_than_the_alert_lends_nothing(self):
        n = node("proc:1", "b-keychain-dump")           # high / strong on its own
        self.assertEqual(agent._plan_confidence(in_case(n, severity="high")),
                         agent._plan_confidence(n))

    def test_a_closed_case_lends_nothing(self):
        """Someone judged this case. The machine does not get to re-open the question by citing it."""
        n = node("proc:1", "b-cloud-creds")
        self.assertEqual(agent._plan_confidence(in_case(n, status="closed")), 1)

    def test_a_lone_alert_is_not_a_case(self):
        n = in_case(node("proc:1", "b-cloud-creds"), size=1)
        self.assertEqual(agent._plan_confidence(n), 1)

    def test_the_lend_is_excluded_when_rating_the_case_itself(self):
        """Otherwise a case lends weight to its members and then cites its members as its own
        weight — which is just a case promoting itself."""
        n = in_case(node("proc:1", "b-cloud-creds"))
        self.assertEqual(agent._plan_confidence(n, with_case=False), 1)
        inc = {"id": "c1", "status": "open", "severity": "critical", "members": ["proc:1"]}
        self.assertEqual(agent.case_confidence(inc, {"proc:1": n}), 1)


# --------------------------------------------------------------------------------------------
class TestCasePlan(unittest.TestCase):
    def setUp(self):
        self.pb = playbook(self)
        self.members = [node("proc:21", "b-revshell"), node("proc:22", "b-cloud-creds")]
        self.by_id = {n["id"]: n for n in self.members}
        self.inc = {"id": "c1", "case_no": 7, "status": "open", "severity": "critical",
                    "members": list(self.by_id)}

    def plan(self, **over):
        return agent.resolve_case_plan(dict(self.inc, **over), self.by_id, self.pb, REGISTRY)

    def test_a_case_plan_covers_every_member(self):
        p = self.plan()
        self.assertEqual({s["member"] for s in p["steps"]}, set(self.by_id))

    def test_a_closed_case_resolves_to_nothing(self):
        self.assertIsNone(self.plan(status="closed"))

    def test_a_low_case_resolves_to_nothing(self):
        """A low case is correlation, not an incident — there is nothing to contain yet."""
        self.assertIsNone(self.plan(severity="low"))

    def test_a_member_acted_on_the_cases_evidence_is_flagged_as_such(self):
        """A weak member IS contained by a critical case — the case is the unit of judgment — but
        the operator has to be able to see that it was not convicted on its own evidence."""
        p = self.plan()
        weak = [s for s in p["steps"] if s["member"] == "proc:22"]
        self.assertTrue(weak)
        self.assertTrue(all(s["on_case_evidence"] for s in weak))
        self.assertEqual(weak[0]["member_confidence"], "weak")
        strong = [s for s in p["steps"] if s["member"] == "proc:21"]
        self.assertFalse(any(s["on_case_evidence"] for s in strong))

    def test_the_blast_radius_of_one_click_is_bounded(self):
        many = {("proc:%d" % i): node("proc:%d" % i, "b-revshell") for i in range(100, 200)}
        inc = {"id": "c2", "case_no": 8, "status": "open", "severity": "critical",
               "members": list(many)}
        p = agent.resolve_case_plan(inc, many, self.pb, REGISTRY)
        self.assertEqual(len({s["member"] for s in p["steps"]}), agent.CASE_WORKFLOW_MAX_MEMBERS)
        self.assertEqual(p["truncated"], 100 - agent.CASE_WORKFLOW_MAX_MEMBERS)

    def test_members_that_are_gone_are_simply_not_acted_on(self):
        inc = dict(self.inc, members=list(self.by_id) + ["proc:999"])
        p = agent.resolve_case_plan(inc, self.by_id, self.pb, REGISTRY)
        self.assertEqual({s["member"] for s in p["steps"]}, set(self.by_id))

    def test_no_default_case_workflow_seeds_a_destructive_action(self):
        for sev, ids in agent.DEFAULT_CASE_WORKFLOWS.items():
            for aid in ids:
                self.assertFalse(REGISTRY[aid].get("destructive"), "%s seeds %s" % (sev, aid))

    def test_a_case_workflow_still_obeys_the_confidence_floors(self):
        """The case gates on the case's rating, but the floors themselves are not suspended."""
        mild = [node("proc:31", "b-cloud-creds"), node("proc:32", "b-ssh-keys")]
        by_id = {n["id"]: n for n in mild}
        inc = {"id": "c3", "case_no": 9, "status": "open", "severity": "medium",
               "members": list(by_id)}
        p = agent.resolve_case_plan(inc, by_id, self.pb, REGISTRY)
        for s in (p or {}).get("steps", []):
            floor = agent.ACTION_MIN_CONFIDENCE.get(s["action"], agent.DEFAULT_ACTION_MIN_CONFIDENCE)
            self.assertGreaterEqual(s["confidence_rank"], floor)

    def test_the_mesh_playbook_outranks_the_local_one(self):
        self.pb.set_case_workflow("critical", ["vr_forensics"])
        self.assertEqual(self.pb.case_workflow_for("critical"), ["vr_forensics"])
        self.pb.set_mesh_playbook(3, {}, {}, {"critical": ["suspend"]})
        self.assertEqual(self.pb.case_workflow_for("critical"), ["suspend"])
        self.pb.clear_mesh_playbook()
        self.assertEqual(self.pb.case_workflow_for("critical"), ["vr_forensics"])


# --------------------------------------------------------------------------------------------
class TestWhatTravelsToTheMesh(unittest.TestCase):
    """The periodic report carries no `detail` at all — deliberately, it is a roster, not a graph.
    That left the mesh unable to see two hosts hitting the same thing, so a bounded identity block
    rides along instead. What it must NOT carry matters more than what it does: this is the only
    place a host's indicators become a fleet-wide correlation key."""

    def ind(self, **detail):
        return agent.MeshReporter._report_indicators({"detail": detail})

    def test_a_dropped_binarys_hash_travels(self):
        self.assertEqual(self.ind(exe="/tmp/stage", hashes={"sha256": "a" * 64})["hash"], "a" * 64)

    def test_an_os_binarys_hash_does_not(self):
        """Every host has /bin/zsh. Correlating on it would join the fleet, not an intrusion —
        the agent's own correlation tests caught exactly this merge once already."""
        self.assertIsNone(self.ind(exe="/bin/zsh", hashes={"sha256": "b" * 64},
                                   signature={"trusted": True, "category": "apple"}))

    def test_but_a_tampered_one_does(self):
        got = self.ind(exe="/bin/zsh", hashes={"sha256": "c" * 64},
                       signature={"trusted": False, "category": "invalid"})
        self.assertEqual(got["hash"], "c" * 64)

    def test_an_unknown_signature_at_a_system_path_stays_generic(self):
        """Absence of a signature check is not evidence of tampering, and the cost of a wrong
        'specific' here is a case joining hosts that share nothing but macOS."""
        self.assertIsNone(self.ind(exe="/usr/bin/curl", hashes={"sha256": "d" * 64}))

    def test_a_private_peer_does_not_travel(self):
        self.assertIsNone(self.ind(raddr="10.0.0.5", public=True))

    def test_a_public_peer_does(self):
        self.assertEqual(self.ind(raddr="93.184.216.34", public=True)["ip"], "93.184.216.34")

    def test_paths_and_pids_never_travel(self):
        """A path is a location and a pid is nothing off-host; neither identifies a thing."""
        got = self.ind(path="/tmp/update", pid=4242, cmdline="/tmp/update --now")
        self.assertIsNone(got)

    def test_urls_travel_but_are_capped(self):
        got = self.ind(cmdline="curl https://a.example/1 https://b.example/2 https://c.example/3")
        self.assertEqual(len(got["urls"]), 2)

    def test_an_alert_with_no_identity_sends_nothing(self):
        self.assertIsNone(self.ind(pid=1, label="bash"))



class TestBreakGlassCommand(unittest.TestCase):
    """The copyable break-glass line must survive an install path with a space
    (macOS installs under /Library/Application Support/Scouter/)."""

    def test_spaced_path_is_shell_safe(self):
        import shlex
        script = "/Library/Application Support/Scouter/agent/agent.py"
        python = "/Library/Application Support/Scouter/agent/.venv/bin/python3"
        cmd = agent.breakglass_command(python=python, script=script)
        argv = shlex.split(cmd)                       # how a shell parses the copied line
        self.assertEqual(argv[0], "sudo")
        self.assertIn(python, argv)                   # the interpreter path is ONE argument
        self.assertIn(script, argv)                   # the script path is ONE argument, not split
        self.assertIn("--break-glass", argv)

    def test_plain_path_not_needlessly_quoted(self):
        cmd = agent.breakglass_command(python="python3", script="/opt/scouter/agent.py")
        self.assertIn("python3 /opt/scouter/agent.py --break-glass", cmd)


class TestUpdateChecker(unittest.TestCase):
    """The "check for updates" signal. We ship by pushing a commit that bumps __version__ on main,
    not by cutting a GitHub release for every version -- so the authoritative "latest" is the source
    __version__ on the release branch, and the release lookup is only for notes/link enrichment. The
    regression guarded here: an old release (mac-v1.0.0) must NOT make a running 1.9.0 look current."""

    def _checker(self, current, source_version, release=None):
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        uc = agent.UpdateChecker(current=current,
                                 cache_file=os.path.join(tmp, "update-check.json"))
        uc._fetch_source_version = lambda: source_version
        uc._fetch_release = lambda latest: release
        return uc

    def test_source_version_newer_than_running_reports_update(self):
        # The exact bug report: on 1.9.0, main at 1.9.1, only release is mac-v1.0.0.
        uc = self._checker("1.9.0", "1.9.1")
        uc._check()
        st = uc.status()
        self.assertEqual(st["latest"], "1.9.1")
        self.assertTrue(st["update_available"])
        self.assertTrue(st["url"])                    # UI link still works without a tagged release

    def test_same_version_reports_up_to_date(self):
        uc = self._checker("1.9.1", "1.9.1")
        uc._check()
        self.assertFalse(uc.status()["update_available"])

    def test_old_release_cannot_mask_newer_source(self):
        # A stale release (1.0.0) must never win over the source version on main.
        rel = {"tag_name": "mac-v1.0.0", "html_url": "https://example/r", "body": "old"}
        uc = self._checker("1.9.0", "1.9.1", release=None)
        uc._fetch_release = lambda latest: None       # no release matches 1.9.1 yet
        uc._check()
        self.assertTrue(uc.status()["update_available"])
        self.assertEqual(uc.status()["latest"], "1.9.1")
        del rel

    def test_matching_release_enriches_notes(self):
        rel = {"tag_name": "mac-v1.9.1", "name": "Scouter 1.9.1",
               "html_url": "https://example/rel", "body": "release notes here"}
        uc = self._checker("1.9.0", "1.9.1", release=rel)
        uc._check()
        st = uc.status()
        self.assertEqual(st["url"], "https://example/rel")
        self.assertEqual(st["notes"], "release notes here")

    def test_offline_probe_keeps_last_good_state(self):
        uc = self._checker("1.9.0", "1.9.1")
        uc._check()                                   # learns 1.9.1
        uc._fetch_source_version = lambda: None       # next probe is offline
        uc._fetch_release = lambda latest: None
        uc._check()
        self.assertEqual(uc.status()["latest"], "1.9.1")   # not wiped back to "up to date"

    def test_parse_source_version(self):
        self.assertEqual(
            agent.UpdateChecker._parse_source_version('x\n__version__ = "2.10.3"\ny'), "2.10.3")
        self.assertIsNone(agent.UpdateChecker._parse_source_version("no version here"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
