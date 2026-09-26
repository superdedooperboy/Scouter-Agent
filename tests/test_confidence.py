#!/usr/bin/env python3
"""Detection confidence, and the response it is allowed to buy.

Severity says how bad an alert would be if it were real. Confidence says how likely it is to be
real at all, and the two come apart constantly: `curl … | sh` is how rustup and Homebrew install
themselves, and a scheduled job masquerading as an Apple component is nothing else. Before this
existed, both resolved to the same ATT&CK tactic and therefore got the same workflow, and the only
way to tell them apart was to hand-write a per-detection override for one of them.

These tests pin the two properties that makes that unnecessary: the ratings are real data (they
name rules that exist, and they disagree with severity often enough to carry information), and the
response ladder they drive is monotonic — more confidence never buys less, and the machine's floor
for acting unasked is always at least as high as its floor for making a suggestion.

Pure stdlib, like the agent. Run from the repo root:

    python3 -m unittest discover -s tests -v
    python3 tests/test_confidence.py             # same thing, single file
"""
import json
import os
import shutil
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
import agent  # noqa: E402

REGISTRY = {a["id"]: a
            for a in json.load(open(os.path.join(os.path.dirname(HERE), "playbook-macos.json")))["actions"]}


# --------------------------------------------------------------------------------------------
# fixtures
# --------------------------------------------------------------------------------------------
def rule(rid):
    for r in agent.BUILTIN_RULES:
        if r["id"] == rid:
            return r
    raise AssertionError("no such built-in rule: %s" % rid)


def hit(rid):
    """A rule_hit shaped the way apply_node_rules() stamps it."""
    r = rule(rid)
    return {"id": rid, "name": r["name"], "mitre": r.get("mitre"),
            "severity": r.get("severity"), "confidence": agent.rule_confidence(r), "builtin": True}


def alert(rid, ntype="process", **detail):
    """One alert carrying exactly one detection, at that detection's own severity."""
    r = rule(rid)
    detail.setdefault("rule_hits", [hit(rid)])
    if ntype == "process":
        detail.setdefault("pid", 4242)
    return {"id": "%s:1" % ntype, "type": ntype, "label": "t", "severity": r["severity"],
            "score": 80, "detail": detail, "reasons": []}


def playbook(test):
    """A real ResponsePlaybook on a throwaway path. It writes its file on construction, so it must
    never be pointed at the repo, and it validates action ids against the registry it is handed —
    hand it an empty one and every override silently becomes []."""
    d = tempfile.mkdtemp()
    test.addCleanup(shutil.rmtree, d, True)
    return agent.ResponsePlaybook(path=os.path.join(d, "response-playbook.json"),
                                  valid_actions=list(REGISTRY))


def plan_for(node, pb=None):
    return agent.resolve_response_plan(node, pb, REGISTRY)


def actions(node, pb=None):
    p = plan_for(node, pb)
    return [s["action"] for s in (p or {}).get("actions", [])]


# --------------------------------------------------------------------------------------------
class TestRatingsAreRealData(unittest.TestCase):
    """The curated table is the substance of this feature. If it drifts out of step with the rule
    library, it fails silently — a renamed rule simply stops being rated and quietly falls back to
    its severity, which is the exact conflation the ratings exist to undo."""

    def test_every_rating_names_a_rule_that_exists(self):
        ids = {r["id"] for r in agent.BUILTIN_RULES}
        orphans = sorted(set(agent.RULE_CONFIDENCE) - ids)
        self.assertEqual(orphans, [], "confidence ratings for rules that no longer exist: %s" % orphans)

    def test_every_rating_is_in_range(self):
        bad = {k: v for k, v in agent.RULE_CONFIDENCE.items() if v not in (1, 2, 3, 4)}
        self.assertEqual(bad, {})

    def test_the_table_only_holds_divergences(self):
        """An entry that merely restates the severity seed is noise: it makes the curation look
        bigger than it is and hides the entries that are actually a judgment."""
        redundant = {k: v for k, v in agent.RULE_CONFIDENCE.items()
                     if agent._SEV_CONFIDENCE.get(rule(k)["severity"]) == v}
        self.assertEqual(redundant, {})

    def test_every_rule_is_rated_even_when_unlisted(self):
        """A rule added tomorrow must arrive rated, not unrated — otherwise the gate opens by
        accident on whatever nobody remembered to put in the table."""
        for r in agent.BUILTIN_RULES:
            self.assertIn(agent.rule_confidence(r), (1, 2, 3, 4), r["id"])

    def test_a_custom_rule_with_no_id_at_all_is_still_rated(self):
        self.assertEqual(agent.rule_confidence({"severity": "high"}), 3)
        self.assertEqual(agent.rule_confidence({}), 2)

    def test_an_inline_override_beats_the_table(self):
        r = dict(rule("b-curlpipe"), confidence_override=4)
        self.assertEqual(agent.rule_confidence(rule("b-curlpipe")), 2)
        self.assertEqual(agent.rule_confidence(r), 4)

    def test_the_axis_actually_carries_information(self):
        """If confidence always agreed with severity it would be a second name for it. It has to
        disagree in BOTH directions or the rating is decoration."""
        demoted = [r["id"] for r in agent.BUILTIN_RULES
                   if agent.rule_confidence(r) < agent._SEV_CONFIDENCE[r["severity"]]]
        promoted = [r["id"] for r in agent.BUILTIN_RULES
                    if agent.rule_confidence(r) > agent._SEV_CONFIDENCE[r["severity"]]]
        self.assertTrue(demoted, "no rule rates below its severity")
        self.assertTrue(promoted, "no rule rates above its severity")


# --------------------------------------------------------------------------------------------
class TestTheLinuxLibraryToo(unittest.TestCase):
    """The two agents keep separate rule libraries and therefore separate ratings, and only the
    macOS one is exercised above. The behaviour code is shared verbatim; the DATA is not, so the
    drift that matters here is a Linux rule renamed out from under its rating."""

    @classmethod
    def setUpClass(cls):
        import importlib.util
        path = os.path.join(os.path.dirname(HERE), "linux", "agent.py")
        spec = importlib.util.spec_from_file_location("linux_agent", path)
        cls.lin = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.lin)

    def test_every_rating_names_a_rule_that_exists(self):
        ids = {r["id"] for r in self.lin.BUILTIN_RULES}
        self.assertEqual(sorted(set(self.lin.RULE_CONFIDENCE) - ids), [])

    def test_the_table_only_holds_divergences(self):
        sev = {r["id"]: r["severity"] for r in self.lin.BUILTIN_RULES}
        redundant = {k: v for k, v in self.lin.RULE_CONFIDENCE.items()
                     if self.lin._SEV_CONFIDENCE.get(sev[k]) == v}
        self.assertEqual(redundant, {})

    def test_every_rule_is_rated(self):
        for r in self.lin.BUILTIN_RULES:
            self.assertIn(self.lin.rule_confidence(r), (1, 2, 3, 4), r["id"])

    def test_the_floors_match_the_other_agent(self):
        """A host being Linux is not a reason for the machine to act on thinner evidence."""
        self.assertEqual(self.lin.ACTION_MIN_CONFIDENCE, agent.ACTION_MIN_CONFIDENCE)
        self.assertEqual(self.lin.AUTO_CONFIDENCE_FLOOR, agent.AUTO_CONFIDENCE_FLOOR)

    def test_no_rule_is_curated_differently_in_the_two_tables(self):
        """b-curlpipe is curl | sh on both platforms. Where both tables name the same rule, a
        rating that disagrees is a mistake in one of them, not a platform difference."""
        shared = set(agent.RULE_CONFIDENCE) & set(self.lin.RULE_CONFIDENCE)
        disagree = {k: (agent.RULE_CONFIDENCE[k], self.lin.RULE_CONFIDENCE[k])
                    for k in shared if agent.RULE_CONFIDENCE[k] != self.lin.RULE_CONFIDENCE[k]}
        self.assertEqual(disagree, {}, "same rule id, different rating: %s" % disagree)

    def test_a_shared_rule_only_rates_differently_when_its_severity_does(self):
        """The remaining differences must be inherited from the severity seed rather than chosen,
        because a rating that differs for no stated reason is one of the two libraries being wrong.
        b-upx, b-timestomp and b-screencap are each filed at different severities on the two
        platforms — a real divergence, but one that predates confidence and belongs to severity."""
        mac = {r["id"]: r for r in agent.BUILTIN_RULES}
        for r in self.lin.BUILTIN_RULES:
            m = mac.get(r["id"])
            if not m or agent.rule_confidence(m) == self.lin.rule_confidence(r):
                continue
            self.assertNotEqual(m["severity"], r["severity"],
                                "%s rates differently at the same severity" % r["id"])


# --------------------------------------------------------------------------------------------
class TestSameTacticDifferentResponse(unittest.TestCase):
    """The complaint this feature answers: a tactic is a handful of buckets over a curated library,
    so every rule in a bucket got the same response and telling two of them apart meant writing an
    override by hand."""

    def setUp(self):
        self.pb = playbook(self)

    def test_two_rules_on_one_technique_get_different_responses_with_no_override(self):
        rev, curl = rule("b-revshell"), rule("b-curlpipe")
        self.assertEqual(rev["mitre"], curl["mitre"])          # same technique, so same tactic
        self.assertEqual(rev["severity"], curl["severity"])    # and the same severity
        self.assertEqual(agent.technique_tactic(rev["mitre"]),
                         agent.technique_tactic(curl["mitre"]))
        self.assertEqual(self.pb.snapshot()[1], {}, "this must hold with NO override configured")

        contained = actions(alert("b-revshell"), self.pb)
        observed = actions(alert("b-curlpipe"), self.pb)
        self.assertIn("suspend", contained)
        self.assertNotIn("suspend", observed)
        self.assertIn("vr_forensics", observed, "a probable hit is still worth collecting on")

    def test_a_weak_detection_proposes_nothing_at_all(self):
        """Reading ~/.aws/credentials is what the aws CLI does on every invocation. The alert still
        exists and still correlates; putting a containment button in front of it is the bug."""
        self.assertEqual(agent.rule_confidence(rule("b-cloud-creds")), 1)
        self.assertEqual(actions(alert("b-cloud-creds"), self.pb), [])

    def test_more_confidence_never_buys_less(self):
        """Monotonicity over the whole library: sort every process rule by rating and the action
        sets must nest. A rating that bought FEWER actions would be incomprehensible."""
        by_rank = {}
        for r in agent.BUILTIN_RULES:
            if r.get("node_type", "process") != "process":
                continue
            got = set(actions(alert(r["id"]), self.pb))
            by_rank.setdefault(agent.rule_confidence(r), set()).update(got)
        ranks = sorted(by_rank)
        for lo, hi in zip(ranks, ranks[1:]):
            self.assertTrue(by_rank[lo] <= by_rank[hi],
                            "rank %d offers %s, which rank %d does not" %
                            (lo, by_rank[lo] - by_rank[hi], hi))


# --------------------------------------------------------------------------------------------
class TestFloors(unittest.TestCase):
    def setUp(self):
        self.pb = playbook(self)

    def test_no_action_is_ever_offered_below_its_floor(self):
        for r in agent.BUILTIN_RULES:
            conf = agent.rule_confidence(r)
            for aid in actions(alert(r["id"], ntype=r.get("node_type", "process"),
                                     **({"path": "/tmp/x.plist"} if r.get("node_type") == "job" else
                                        {"path": "/tmp/x"} if r.get("node_type") == "file" else {})),
                               self.pb):
                floor = agent.ACTION_MIN_CONFIDENCE.get(aid, agent.DEFAULT_ACTION_MIN_CONFIDENCE)
                self.assertGreaterEqual(conf, floor, "%s offered %s below its floor" % (r["id"], aid))

    def test_blocking_an_address_needs_more_than_a_probable_hit(self):
        """A blackhole route is host-wide rather than scoped to the offending process, so it costs
        more than suspending one pid and should be rated accordingly."""
        self.assertGreater(agent.ACTION_MIN_CONFIDENCE["block_ip"],
                           agent.ACTION_MIN_CONFIDENCE["suspend"] - 1)
        n = alert("b-c2-webservice", ntype="remote", raddr="198.51.100.7", public=True)
        self.assertEqual(agent.rule_confidence(rule("b-c2-webservice")), 2)
        self.assertEqual(actions(n, self.pb), [])

    def test_corroboration_promotes_one_tier_and_no_more(self):
        n = alert("b-c2-webservice", ntype="remote", raddr="198.51.100.7", public=True,
                  ioc={"source": "feed"})
        self.assertEqual(agent._plan_confidence(n), 3)
        self.assertIn("block_ip", actions(n, self.pb))

    def test_corroboration_cannot_exceed_certain(self):
        n = alert("b-revshell", ioc={"source": "feed"},
                  vt={"status": "done", "malicious": 9})
        self.assertEqual(agent._plan_confidence(n), 4)

    def test_an_alert_with_no_detection_falls_back_to_its_severity(self):
        n = {"id": "process:9", "type": "process", "severity": "high", "score": 80,
             "detail": {"pid": 7}, "reasons": []}
        self.assertEqual(agent._plan_confidence(n), 3)

    def test_an_operator_override_is_not_floor_gated(self):
        """An operator who configures a response for a detection has made a judgment that outranks
        our rating of it. Dropping what they configured would look like the feature is broken."""
        pb = playbook(self)
        pb.set_override("b-cloud-creds", ["suspend"])
        got = actions(alert("b-cloud-creds"), pb)
        self.assertEqual(got, ["suspend"], "an explicit override must survive a weak rating")


# --------------------------------------------------------------------------------------------
class TestWhatTheMachineDoesUnasked(unittest.TestCase):
    """Offering an action and performing it are different bars. Every posture's floor for acting
    alone must sit at or above the floor for merely suggesting."""

    def setUp(self):
        self.pb = playbook(self)

    def auto_steps(self, node, posture):
        floor = agent.AUTO_CONFIDENCE_FLOOR[posture]
        p = plan_for(node, self.pb) or {}
        return [s["action"] for s in p.get("actions", [])
                if s.get("reversible") and int(s.get("confidence_rank") or 0) >= floor]

    def test_scouting_never_acts(self):
        for rid in ("b-revshell", "b-acct-uid0", "b-lazagne"):
            self.assertEqual(self.auto_steps(alert(rid), "scouting"), [], rid)

    def test_scouting_floor_is_unreachable_by_construction(self):
        self.assertGreater(agent.AUTO_CONFIDENCE_FLOOR["scouting"], max(agent.CONFIDENCE_NAME))

    def test_defensive_spends_only_on_a_certain_detection(self):
        self.assertIn("suspend", self.auto_steps(alert("b-revshell"), "defensive"))
        self.assertEqual(self.auto_steps(alert("b-keychain-dump"), "defensive"), [],
                         "a strong hit is not certain, and Defensive is the cautious posture")

    def test_counter_offensive_also_accepts_a_strong_detection(self):
        self.assertIn("suspend", self.auto_steps(alert("b-keychain-dump"), "counter"))

    def test_arming_harder_never_acts_on_less(self):
        for r in agent.BUILTIN_RULES:
            if r.get("node_type", "process") != "process":
                continue
            n = alert(r["id"])
            self.assertTrue(set(self.auto_steps(n, "defensive")) <= set(self.auto_steps(n, "counter")),
                            r["id"])

    def test_irreversible_and_destructive_steps_never_auto_fire(self):
        """Forensics is one-shot and kill/delete cannot be undone, so no rating and no posture may
        reach them — they are confirmed by a human or they do not happen."""
        for posture in agent.AUTO_CONFIDENCE_FLOOR:
            for r in agent.BUILTIN_RULES:
                for aid in self.auto_steps(alert(r["id"]), posture):
                    spec = REGISTRY[aid]
                    self.assertTrue(spec.get("reversible"), "%s auto-fired %s" % (r["id"], aid))
                    self.assertFalse(spec.get("destructive"), "%s auto-fired %s" % (r["id"], aid))


if __name__ == "__main__":
    unittest.main(verbosity=2)
