#!/usr/bin/env python3
"""
Sysmon Detection Engine - run Sigma-style rules over Sysmon logs, rebuild the
process tree, and group alerts into incidents ordered along the ATT&CK kill chain.

Usage:
  python hunt.py samples/attack_chain.jsonl
  python hunt.py events.jsonl --rules rules --json alerts.json --navigator layer.json
  python hunt.py samples/attack_chain.jsonl --html report.html
  python hunt.py --list-rules
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import Counter

from engine.correlate import ProcessTree, build_incidents, detect
from engine.enrich import enrich
from engine.events import load_events
from engine.rules import LEVELS, load_rules

COLOR = {"critical": "\033[95m", "high": "\033[91m", "medium": "\033[93m", "low": "\033[94m"}
RESET = "\033[0m"


def paint(level: str, text: str, on: bool) -> str:
    return f"{COLOR.get(level, '')}{text}{RESET}" if on else text


def navigator_layer(alerts, rules) -> dict:
    """MITRE ATT&CK Navigator layer: detected techniques scored by alert count."""
    hits = Counter(t for a in alerts for t in a.rule.techniques)
    covered = {t for r in rules for t in r.techniques}
    techniques = []
    for t in sorted(covered):
        titles = sorted({a.rule.title for a in alerts if t in a.rule.techniques})
        techniques.append({
            "techniqueID": t, "score": hits.get(t, 0),
            "comment": "; ".join(titles) if titles else "Rule coverage only (not triggered)",
            "color": "" if hits.get(t) else "#d9e7f5",
        })
    return {
        "name": "Sysmon Detection Engine - findings", "domain": "enterprise-attack",
        "versions": {"layer": "4.5", "navigator": "4.9.1"},
        "description": "Red = detected in this dataset; light blue = covered by a rule but not triggered.",
        "techniques": techniques,
        "gradient": {"colors": ["#ffffff", "#ff6666"], "minValue": 0, "maxValue": max(hits.values() or [1])},
    }


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Sigma-style detection + correlation for Sysmon logs")
    ap.add_argument("events", nargs="?", help="Sysmon events (JSON array or JSONL)")
    ap.add_argument("--rules", default="rules")
    ap.add_argument("--json", help="write alerts as JSON")
    ap.add_argument("--navigator", help="write a MITRE ATT&CK Navigator layer")
    ap.add_argument("--html", help="write a self-contained HTML dashboard report")
    ap.add_argument("--list-rules", action="store_true")
    ap.add_argument("--no-color", action="store_true")
    args = ap.parse_args(argv)
    color = not args.no_color and sys.stdout.isatty()

    rules = load_rules(args.rules)
    if args.list_rules:
        for r in sorted(rules, key=lambda r: -LEVELS[r.level]):
            print(f"{r.level:<9} {', '.join(r.techniques):<28} {r.title}")
        return 0
    if not args.events:
        ap.error("events file required")

    events = enrich(load_events(args.events))
    tree = ProcessTree(events)
    alerts = detect(events, rules)
    incidents = build_incidents(alerts, tree)

    hosts = {e.get("Computer") for e in events}
    print("=" * 96)
    print(" SYSMON DETECTION ENGINE")
    print("=" * 96)
    print(f" Events: {len(events)}   Hosts: {len(hosts)}   Rules loaded: {len(rules)}   "
          f"Alerts: {len(alerts)}   Incidents: {len(incidents)}")
    print("-" * 96)
    print(" ALERT TIMELINE")
    for a in sorted(alerts, key=lambda a: a.time):
        e = a.event
        what = e.get("CommandLine") or e.get("TargetObject") or e.get("TargetFilename") \
            or (f"{e.get('SourceImage', '').split(chr(92))[-1]} -> {e.get('TargetImage', '').split(chr(92))[-1]} "
                f"({e.get('GrantedAccess')})" if e.get("EventID") == 10 else e.get("DestinationIp"))
        what = str(what)
        print(f" {a.time[11:19]}  {paint(a.rule.level, f'{a.rule.level.upper():<8}', color)} "
              f"{a.rule.title[:44]:<44}  {', '.join(a.rule.techniques)}")
        print(f"           {e.get('Computer', '?')}: {what[:78]}")
        if e.get("CommandLineDecoded"):
            print(f"           decoded -enc payload: {e['CommandLineDecoded'][:70]}")

    for n, inc in enumerate(incidents, 1):
        print("-" * 96)
        print(f" INCIDENT {n}: {inc.host}   severity={paint(inc.severity, inc.severity.upper(), color)}   "
              f"risk score={inc.score}   alerts={len(inc.alerts)}")
        print(f" Attack progression: {' -> '.join(inc.tactics)}")
        print(f" Techniques: {', '.join(inc.techniques)}")
        flagged = {}
        for a in inc.alerts:
            if a.guid:
                flagged.setdefault(a.guid, [])
                if a.rule.title not in flagged[a.guid]:
                    flagged[a.guid].append(a.rule.title)
        if not inc.root_guid.startswith("orphan:"):
            parent = tree.procs.get(tree.procs.get(inc.root_guid, {}).get("ParentProcessGuid"), {})
            print(f" Process tree (launched by {(parent.get('Image') or '?').split(chr(92))[-1]}):")
            for line in tree.render(inc.root_guid, flagged):
                print("   " + line)

    print("=" * 96)
    if args.json:
        with open(args.json, "w") as fh:
            json.dump([{"time": a.time, "host": a.event.get("Computer"), "rule_id": a.rule.id,
                        "rule": a.rule.title, "level": a.rule.level, "techniques": a.rule.techniques,
                        "tactics": a.rule.tactics, "event": a.event} for a in alerts], fh, indent=2)
        print(f"Alerts written to {args.json}")
    if args.navigator:
        with open(args.navigator, "w") as fh:
            json.dump(navigator_layer(alerts, rules), fh, indent=2)
        print(f"ATT&CK Navigator layer written to {args.navigator} (open at https://mitre-attack.github.io/attack-navigator/)")
    if args.html:
        from engine.dashboard import write_dashboard

        write_dashboard(args.html, events, rules, alerts, incidents, tree, args.events)
        print(f"HTML report written to {args.html}")
    return 2 if any(a.rule.level == "critical" for a in alerts) else 0


if __name__ == "__main__":
    sys.exit(main())
