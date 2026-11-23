"""Run rules, rebuild process trees, and group alerts into incidents."""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from .rules import LEVELS, Rule

# MITRE ATT&CK Enterprise tactic order (kill-chain order)
TACTIC_ORDER = ["reconnaissance", "resource-development", "initial-access", "execution",
                "persistence", "privilege-escalation", "defense-evasion", "credential-access",
                "discovery", "lateral-movement", "collection", "command-and-control",
                "exfiltration", "impact"]


@dataclass
class Alert:
    rule: Rule
    event: Dict[str, Any]

    @property
    def guid(self) -> Optional[str]:
        e = self.event
        return e.get("ProcessGuid") or e.get("SourceProcessGuid")

    @property
    def time(self) -> str:
        return self.event.get("UtcTime", "")


@dataclass
class Incident:
    host: str
    root_guid: str
    alerts: List[Alert] = field(default_factory=list)

    @property
    def severity(self) -> str:
        return max((a.rule.level for a in self.alerts), key=lambda l: LEVELS[l])

    @property
    def tactics(self) -> List[str]:
        """Tactics in the order the attacker first reached them (ties: ATT&CK matrix order)."""
        first: Dict[str, str] = {}
        for a in sorted(self.alerts, key=lambda a: a.time):
            for t in sorted(a.rule.tactics, key=TACTIC_ORDER.index):
                first.setdefault(t, a.time)
        return sorted(first, key=lambda t: (first[t], TACTIC_ORDER.index(t)))

    @property
    def techniques(self) -> List[str]:
        return sorted({t for a in self.alerts for t in a.rule.techniques})

    @property
    def score(self) -> int:
        """Simple risk score: severity of each distinct rule + bonus per tactic stage."""
        rules = {a.rule.id: a.rule for a in self.alerts}
        return sum(LEVELS[r.level] * 10 for r in rules.values()) + 15 * len(self.tactics)


class ProcessTree:
    def __init__(self, events: List[Dict[str, Any]]):
        self.procs: Dict[str, Dict[str, Any]] = {}
        self.children: Dict[str, List[str]] = defaultdict(list)
        for e in events:
            if e.get("EventID") == 1 and e.get("ProcessGuid"):
                self.procs[e["ProcessGuid"]] = e
        for guid, p in list(self.procs.items()):
            parent = p.get("ParentProcessGuid")
            if parent:
                self.children[parent].append(guid)
                if parent not in self.procs:  # parent started before logging began
                    self.procs[parent] = {"ProcessGuid": parent, "Image": p.get("ParentImage"),
                                          "CommandLine": p.get("ParentCommandLine"),
                                          "Computer": p.get("Computer"), "_synthetic": True}

    def ancestors(self, guid: str) -> List[str]:
        chain, seen = [], set()
        while guid and guid in self.procs and guid not in seen:
            seen.add(guid)
            chain.append(guid)
            guid = self.procs[guid].get("ParentProcessGuid")
        return chain  # [self, parent, grandparent, ...]

    def incident_root(self, guid: str) -> str:
        """Top-most ancestor that is not a shell/session host (explorer, services, ...)."""
        chain = self.ancestors(guid)
        root = guid
        for g in chain:
            image = (self.procs[g].get("Image") or "").lower()
            if image.endswith(("\\explorer.exe", "\\services.exe", "\\svchost.exe",
                               "\\wininit.exe", "\\userinit.exe")):
                break
            root = g
        return root

    def render(self, guid: str, flagged: Dict[str, List[str]], prefix: str = "",
               last: bool = True, top: bool = True) -> List[str]:
        p = self.procs.get(guid, {})
        image = (p.get("Image") or "?").split("\\")[-1]
        cmd = p.get("CommandLine") or ""
        cmd = cmd if len(cmd) <= 80 else cmd[:77] + "..."
        tag = ""
        if guid in flagged:
            names = flagged[guid]
            tag = f"   <== {names[0]}" + (f" (+{len(names) - 1} more)" if len(names) > 1 else "")
        branch = "" if top else ("`-- " if last else "|-- ")
        lines = [f"{prefix}{branch}{image}  [{cmd}]{tag}"]
        child_prefix = "" if top else prefix + ("    " if last else "|   ")
        kids = sorted(self.children.get(guid, []), key=lambda g: self.procs[g].get("UtcTime", ""))
        for i, kid in enumerate(kids):
            lines += self.render(kid, flagged, child_prefix, i == len(kids) - 1, top=False)
        return lines


def detect(events: List[Dict[str, Any]], rules: List[Rule]) -> List[Alert]:
    return [Alert(r, e) for e in events for r in rules if r.matches(e)]


def build_incidents(alerts: List[Alert], tree: ProcessTree) -> List[Incident]:
    incidents: Dict[tuple, Incident] = {}
    for a in alerts:
        host = a.event.get("Computer", "?")
        root = tree.incident_root(a.guid) if a.guid else f"orphan:{a.rule.id}"
        inc = incidents.setdefault((host, root), Incident(host, root))
        inc.alerts.append(a)
    return sorted(incidents.values(), key=lambda i: -i.score)
