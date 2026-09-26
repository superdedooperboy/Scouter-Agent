#!/usr/bin/env python3
"""The factory libraries the Mesh is seeded from must match the agents that produced them.

The Mesh is the authority for an enrolled host: it seeds its editable rule library and response
playbooks from builtins-<plat>.json and playbook-<plat>.json, then pushes ITS copy to every agent.
So a change in an agent's BUILTIN_RULES, action registry or confidence ratings is invisible to the
fleet until those files are regenerated — and a stale one is worse than invisible, because the Mesh
keeps pushing the old definition back over the new one.

This failed silently once already. The generator (tools/gen-mesh-builtins.py, in the Mesh repo)
read the agents from the directory it used to share with them; the agents moved to their own
repository and the tool was never repointed, so it had been erroring out on a missing path. Nobody
noticed, because nothing checked. This is the thing that checks.

Regenerate with:  python3 ../mac-scouter/tools/gen-mesh-builtins.py

Pure stdlib, like the agent. Run from the repo root:

    python3 -m unittest discover -s tests -v
    python3 tests/test_factory_export.py          # same thing, single file
"""
import importlib.util
import json
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
import agent  # noqa: E402

REGENERATE = "regenerate with: python3 ../mac-scouter/tools/gen-mesh-builtins.py"


def load_linux():
    spec = importlib.util.spec_from_file_location("linux_agent", os.path.join(ROOT, "linux", "agent.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def read(name):
    with open(os.path.join(ROOT, name), encoding="utf-8") as fh:
        return json.load(fh)


class _ExportCase:
    """Shared assertions. Deliberately NOT a TestCase: as one it would be collected and run on its
    own, reporting a screenful of skips that read like something is wrong. The per-platform
    subclasses mix it with TestCase and supply the module and its two files."""

    mod = None
    builtins_file = None
    playbook_file = None

    def setUp(self):
        self.rules = read(self.builtins_file)["rules"]
        self.playbook = read(self.playbook_file)

    def test_the_rule_set_matches_the_code(self):
        self.assertEqual(sorted(r["id"] for r in self.rules),
                         sorted(r["id"] for r in self.mod.BUILTIN_RULES), REGENERATE)

    def test_every_exported_rule_matches_its_definition(self):
        """Not just the ids: a rule whose CONDITIONS drifted is the dangerous case, because the Mesh
        would keep pushing the old logic — a fixed false positive would come straight back."""
        code = {r["id"]: r for r in self.mod.BUILTIN_RULES}
        for exported in self.rules:
            src = code[exported["id"]]
            for field in ("severity", "mitre", "match", "node_type", "conditions"):
                if field in src:
                    self.assertEqual(exported.get(field), src[field],
                                     "%s.%s drifted — %s" % (exported["id"], field, REGENERATE))

    def test_every_exported_rule_carries_its_rating(self):
        """Confidence is what bounds the response, so the Mesh cannot show, retune or push a rating
        that never left the agent."""
        for exported in self.rules:
            src = next(r for r in self.mod.BUILTIN_RULES if r["id"] == exported["id"])
            self.assertEqual(exported.get("confidence"), self.mod.rule_confidence(src),
                             "%s — %s" % (exported["id"], REGENERATE))
            self.assertEqual(exported.get("confidence_label"),
                             self.mod.CONFIDENCE_NAME[self.mod.rule_confidence(src)])

    def test_the_action_catalog_carries_its_floors(self):
        floors = self.mod.ACTION_MIN_CONFIDENCE
        default = self.mod.DEFAULT_ACTION_MIN_CONFIDENCE
        for a in self.playbook["actions"]:
            self.assertEqual(a.get("min_confidence"), floors.get(a["id"], default),
                             "%s — %s" % (a["id"], REGENERATE))
            self.assertEqual(a.get("min_confidence_label"),
                             self.mod.CONFIDENCE_NAME[a["min_confidence"]])

    def test_the_catalog_covers_every_visible_action(self):
        try:
            registry = self.mod.Responder().registry
        except Exception:  # noqa: BLE001
            self.skipTest("responder unavailable in this environment")
        visible = {aid for aid, spec in registry.items() if not spec.get("hidden")}
        self.assertEqual({a["id"] for a in self.playbook["actions"]}, visible, REGENERATE)

    def test_the_tactic_workflows_match(self):
        self.assertEqual(self.playbook["workflows"],
                         {k: list(v) for k, v in self.mod.DEFAULT_TACTIC_WORKFLOWS.items()}, REGENERATE)


class TestMacOSExport(_ExportCase, unittest.TestCase):
    builtins_file = "builtins-macos.json"
    playbook_file = "playbook-macos.json"

    @classmethod
    def setUpClass(cls):
        cls.mod = agent


class TestLinuxExport(_ExportCase, unittest.TestCase):
    builtins_file = "builtins-linux.json"
    playbook_file = "playbook-linux.json"

    @classmethod
    def setUpClass(cls):
        cls.mod = load_linux()


if __name__ == "__main__":
    unittest.main(verbosity=2)
