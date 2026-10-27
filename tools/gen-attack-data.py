#!/usr/bin/env python3
"""Regenerate attack-data.json from the MITRE ATT&CK Enterprise STIX bundle.

attack-data.json is the static, bundled dataset behind the ATT&CK coverage matrix and the Threat
Groups explorer (techniques, groups, software). It ships with the agent and updates only when this
script is re-run for a release — run it each release so the matrix and groups stay current.

The on-disk format is deliberately compact: a group's `tech` / `soft` are POSITIONAL INDICES into the
`techniques` / `software` arrays (the agent expands them at serve time). This script rebuilds those
arrays and recomputes the indices, so the output is internally consistent regardless of ordering.

Usage:
  python3 tools/gen-attack-data.py                 # download the latest Enterprise STIX, write ../attack-data.json
  python3 tools/gen-attack-data.py --stix PATH     # use a local enterprise-attack.json instead of downloading
  python3 tools/gen-attack-data.py --out PATH      # write somewhere other than the repo's attack-data.json

Pure stdlib. Source: MITRE's attack-stix-data repo (CC-BY-4.0 with attribution to MITRE).
"""
import argparse
import datetime
import json
import os
import re
import sys
import urllib.request

STIX_URL = ("https://raw.githubusercontent.com/mitre-attack/attack-stix-data/"
            "master/enterprise-attack/enterprise-attack.json")

# Enterprise tactics in kill-chain order (the matrix column order). Stable; MITRE rarely changes it.
TACTIC_ORDER = ["reconnaissance", "resource-development", "initial-access", "execution", "persistence",
                "privilege-escalation", "defense-evasion", "credential-access", "discovery",
                "lateral-movement", "collection", "command-and-control", "exfiltration", "impact"]

_CITATION_RE = re.compile(r"\(Citation:[^)]*\)")


def _attack_id(obj):
    """The ATT&CK id (Txxxx, Gxxxx, Sxxxx) from an object's mitre-attack external reference."""
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack" and ref.get("external_id"):
            return ref["external_id"]
    return None


def _live(obj):
    """Exclude revoked / deprecated objects — they should not appear in the matrix or group lists."""
    return not (obj.get("revoked") or obj.get("x_mitre_deprecated"))


def _clean_desc(text):
    return re.sub(r"\s+", " ", _CITATION_RE.sub("", text or "")).strip()


def _tech_sort_key(tid):
    # "T1059.001" -> (1059, 1); "T1003" -> (1003, 0) — natural order, parents before their sub-techniques.
    m = re.match(r"T(\d+)(?:\.(\d+))?$", tid)
    return (int(m.group(1)), int(m.group(2) or 0)) if m else (10 ** 9, tid)


def _num_sort_key(aid):
    m = re.match(r"[A-Z](\d+)$", aid or "")
    return int(m.group(1)) if m else 10 ** 9


def build(bundle):
    objs = bundle.get("objects", [])
    stix2attack = {}            # stix id -> ATT&CK id (attack-patterns + software)
    techniques, software, groups = {}, {}, {}   # ATT&CK id -> record

    attack_version = None
    for o in objs:
        t = o.get("type")
        if t == "x-mitre-collection":
            attack_version = o.get("x_mitre_version") or attack_version
            continue
        if not _live(o):
            continue
        aid = _attack_id(o)
        if t == "attack-pattern" and aid:
            stix2attack[o["id"]] = aid
            tactics = [p["phase_name"] for p in o.get("kill_chain_phases", [])
                       if p.get("kill_chain_name") == "mitre-attack"]
            is_sub = bool(o.get("x_mitre_is_subtechnique"))
            techniques[aid] = {"id": aid, "name": o.get("name", aid),
                               "sub": 1 if is_sub else 0,
                               "parent": aid.split(".", 1)[0] if (is_sub and "." in aid) else None,
                               "tactics": tactics, "platforms": o.get("x_mitre_platforms", []) or []}
        elif t in ("malware", "tool") and aid:
            stix2attack[o["id"]] = aid
            software[aid] = {"id": aid, "name": o.get("name", aid),
                             "type": "tool" if t == "tool" else "malware"}
        elif t == "intrusion-set" and aid:
            name = o.get("name", aid)
            groups[aid] = {"id": aid, "name": name,
                           "aliases": [a for a in o.get("aliases", []) if a and a != name],
                           "desc": _clean_desc(o.get("description")),
                           "_tech": set(), "_soft": set()}   # ATT&CK ids, resolved to indices below

    # Wire group -> technique / software via "uses" relationships from intrusion-sets.
    gby_stix = {o["id"]: _attack_id(o) for o in objs if o.get("type") == "intrusion-set" and _live(o)}
    for o in objs:
        if o.get("type") != "relationship" or o.get("relationship_type") != "uses":
            continue
        src, tgt = o.get("source_ref", ""), o.get("target_ref", "")
        gid = gby_stix.get(src)
        if not gid or gid not in groups:
            continue
        taid = stix2attack.get(tgt)
        if not taid:
            continue
        if tgt.startswith("attack-pattern--") and taid in techniques:
            groups[gid]["_tech"].add(taid)
        elif (tgt.startswith("malware--") or tgt.startswith("tool--")) and taid in software:
            groups[gid]["_soft"].add(taid)

    # Freeze ordering, then map each group's sets to positional indices.
    tech_list = sorted(techniques.values(), key=lambda r: _tech_sort_key(r["id"]))
    soft_list = sorted(software.values(), key=lambda r: _num_sort_key(r["id"]))
    tech_idx = {r["id"]: i for i, r in enumerate(tech_list)}
    soft_idx = {r["id"]: i for i, r in enumerate(soft_list)}

    group_list = []
    for g in sorted(groups.values(), key=lambda r: _num_sort_key(r["id"])):
        tech = sorted(tech_idx[a] for a in g["_tech"] if a in tech_idx)
        soft = sorted(soft_idx[a] for a in g["_soft"] if a in soft_idx)
        if not tech:
            continue                      # a group with no (live) techniques adds nothing to the explorer
        group_list.append({"id": g["id"], "name": g["name"], "aliases": g["aliases"],
                           "desc": g["desc"], "tech": tech, "soft": soft})

    meta = {"source": "MITRE ATT&CK Enterprise (STIX)",
            "generated": datetime.date.today().isoformat(),
            "tactic_order": TACTIC_ORDER, "platforms_added": True}
    if attack_version:
        meta["attack_version"] = attack_version
    return {"meta": meta, "groups": group_list, "techniques": tech_list, "software": soft_list}


def main():
    ap = argparse.ArgumentParser(description="Regenerate attack-data.json from MITRE ATT&CK STIX.")
    ap.add_argument("--stix", help="local enterprise-attack.json (default: download the latest)")
    here = os.path.dirname(os.path.abspath(__file__))
    ap.add_argument("--out", default=os.path.join(os.path.dirname(here), "attack-data.json"),
                    help="output path (default: ../attack-data.json)")
    args = ap.parse_args()

    if args.stix:
        with open(args.stix, "rb") as f:
            bundle = json.load(f)
    else:
        sys.stderr.write("Downloading %s …\n" % STIX_URL)
        req = urllib.request.Request(STIX_URL, headers={"User-Agent": "scouter-gen-attack-data"})
        with urllib.request.urlopen(req, timeout=120) as r:   # noqa: S310 — fixed MITRE https URL
            bundle = json.load(r)

    data = build(bundle)
    with open(args.out, "w") as f:
        json.dump(data, f, separators=(",", ":"))
    m = data["meta"]
    sys.stderr.write("Wrote %s — %d techniques, %d groups, %d software (ATT&CK %s, generated %s)\n"
                     % (args.out, len(data["techniques"]), len(data["groups"]),
                        len(data["software"]), m.get("attack_version", "?"), m["generated"]))


if __name__ == "__main__":
    main()
