#!/usr/bin/env python3
"""The Metrics-page detection flow (the severity → confidence → disposition Sankey).

A Sankey is only honest if its bands conserve mass: every alert that leaves a severity must arrive
at a confidence, and every alert that leaves a confidence must arrive at a disposition. These tests
pin that conservation, plus the two bits of derivation the flow adds on top of the raw lifecycle
record — how a closed alert's substatus becomes a disposition bucket, and how records written before
either field existed still land somewhere sensible instead of vanishing.

Pure stdlib, like the agent. Run from the repo root:

    python3 -m unittest discover -s tests -v
    python3 tests/test_metrics_flow.py           # same thing, single file
"""
import os
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
import agent  # noqa: E402


def _rec(sev, conf_rank=None, status="open", substatus=None, tech=None, source=None,
         events=None, gen=1_700_000_000_000):
    r = {"type": "process", "label": "n", "severity": sev, "landing_ms": gen - 1000,
         "generated_ms": gen,
         "first_status_ms": (gen + 5000) if status != "open" else None, "first_action_ms": None,
         "closed_ms": (gen + 9000) if status == "closed" else None,
         "status": status, "pre_existing": False, "events": events or []}
    if conf_rank is not None:
        r["confidence_rank"] = conf_rank
    if substatus is not None:
        r["substatus"] = substatus
    if tech is not None:
        r["technique"] = tech
    if source is not None:
        r["source"] = source
    return r


def _flows_of(records, case_index=None):
    lc = agent.AlertLifecycle(path=tempfile.mktemp())
    for i, r in enumerate(records):
        lc.data[r.get("_nid", "n%d" % i)] = r
    return {f["id"]: f for f in lc.aggregate(case_index=case_index)["flows"]}


def _assert_conserves(tc, fl):
    """Every non-empty column, and each of the two link stages, must sum to the flow total."""
    for col in fl["columns"]:
        s = sum(c[1] for c in col)
        if s:
            tc.assertEqual(s, fl["total"], "column sum != total in %s" % fl["id"])
    if fl["total"]:
        col0 = {c[0] for c in fl["columns"][0]}
        col1 = {c[0] for c in fl["columns"][1]}
        tc.assertEqual(sum(l[2] for l in fl["links"] if l[0] in col0), fl["total"])
        tc.assertEqual(sum(l[2] for l in fl["links"] if l[0] in col1), fl["total"])
    declared = {c[0] for col in fl["columns"] for c in col}
    for a, b, _ in fl["links"]:
        tc.assertIn(a, declared)
        tc.assertIn(b, declared)


class FlowConservation(unittest.TestCase):
    def test_signal_conserves_mass(self):
        recs = [_rec("critical", 4, "closed", "Malicious"),
                _rec("high", 3, "closed", "False Positive"),
                _rec("high", 4, "closed", "Security Testing"),
                _rec("medium", 2, "closed", "Benign"),
                _rec("low", 1, "closed", "Auto-closed"),
                _rec("low", 1, "open"),
                _rec("medium", 2, "investigating")]
        fls = _flows_of(recs)
        self.assertEqual(fls["signal"]["total"], len(recs))
        _assert_conserves(self, fls["signal"])

    def test_all_five_flows_present_and_conserve(self):
        recs = [_rec("critical", 4, "closed", "Malicious", "T1059.004", "live-rule"),
                _rec("high", 3, "closed", "False Positive", "T1071", "threat-intel"),
                _rec("medium", 2, "closed", "Auto-closed", "T1053", "sql"),
                _rec("low", 1, "open", None, None, "heuristic"),
                _rec("high", 4, "closed", "Security Testing", "T1021", "custom")]
        fls = _flows_of(recs)
        self.assertEqual(set(fls), {"signal", "attack", "response", "lifecycle", "correlation"})
        for fl in fls.values():
            _assert_conserves(self, fl)
        # the heuristic alert has no technique, so the ATT&CK flow drops it
        self.assertEqual(fls["attack"]["total"], 4)
        self.assertEqual(fls["signal"]["total"], 5)

    def test_attack_technique_tail_folds_into_other(self):
        # 15 distinct techniques, 1 alert each -> capped at 10, the rest in a single '__other__' node
        recs = [_rec("medium", 2, "open", None, "T10%02d" % i, "live-rule") for i in range(15)]
        fls = _flows_of(recs)
        tech_col = fls["attack"]["columns"][1]
        self.assertLessEqual(len(tech_col), 10)
        self.assertIn("__other__", {c[0] for c in tech_col})
        _assert_conserves(self, fls["attack"])

    def test_correlation_uses_case_index(self):
        recs = [_rec("high", 3, "closed", "Malicious", "T1059", "live-rule"),
                _rec("high", 3, "closed", "Malicious", "T1059", "live-rule"),
                _rec("low", 1, "open", None, "T1046", "heuristic")]
        recs[0]["_nid"] = "m1"
        recs[1]["_nid"] = "m2"
        fls = _flows_of(recs, case_index={"m1": "critical", "m2": "critical"})
        corr = fls["correlation"]["columns"][1]
        self.assertEqual(dict(corr).get("correlated"), 2)
        self.assertEqual(dict(corr).get("standalone"), 1)
        self.assertEqual(dict(fls["correlation"]["columns"][2]).get("critical"), 2)


class DispositionMapping(unittest.TestCase):
    def test_substatus_maps_to_bucket(self):
        cases = {"Malicious": "malicious", "Security Testing": "security-testing",
                 "Benign": "benign", "False Positive": "false-positive",
                 "Auto-closed": "auto-closed", "Unknown": "closed-unknown"}
        for sub, want in cases.items():
            self.assertEqual(agent.AlertLifecycle._disposition(_rec("high", 3, "closed", sub)), want)

    def test_open_and_investigating_collapse_to_open(self):
        self.assertEqual(agent.AlertLifecycle._disposition(_rec("high", 3, "open")), "open")
        self.assertEqual(agent.AlertLifecycle._disposition(_rec("high", 3, "investigating")), "open")

    def test_closed_without_substatus_parses_last_status_event(self):
        # a record from before substatus was tracked still carries the verdict in its event detail
        ev = [{"kind": "status", "detail": "Status → closed (Benign)"}]
        self.assertEqual(agent.AlertLifecycle._disposition(
            _rec("medium", 2, "closed", substatus=None, events=ev)), "benign")

    def test_closed_with_no_evidence_is_closed_unknown(self):
        self.assertEqual(agent.AlertLifecycle._disposition(
            _rec("medium", 2, "closed", substatus=None)), "closed-unknown")


class ConfidenceFallback(unittest.TestCase):
    def test_rank_maps_to_name(self):
        self.assertEqual(agent.AlertLifecycle._confidence_key(_rec("low", 4)), "certain")
        self.assertEqual(agent.AlertLifecycle._confidence_key(_rec("low", 1)), "weak")

    def test_missing_rank_seeds_from_severity(self):
        # pre-confidence record: no confidence_rank, so it should fall back to a severity seed
        self.assertEqual(agent.AlertLifecycle._confidence_key(_rec("critical")), "certain")
        self.assertEqual(agent.AlertLifecycle._confidence_key(_rec("low")), "weak")


if __name__ == "__main__":
    unittest.main()
