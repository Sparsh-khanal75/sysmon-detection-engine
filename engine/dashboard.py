"""HTML dashboard: alert timeline, ATT&CK coverage and incident process trees."""

from __future__ import annotations

from collections import Counter
from typing import Any, Dict, List

from .correlate import Alert, Incident, ProcessTree
from .html_report import Report, render


def describe(e: Dict[str, Any]) -> str:
    """One-line summary of what an event did."""
    if e.get("EventID") == 10:
        src = str(e.get("SourceImage", "")).split("\\")[-1]
        dst = str(e.get("TargetImage", "")).split("\\")[-1]
        return f"{src} -> {dst} ({e.get('GrantedAccess')})"
    what = e.get("CommandLine") or e.get("TargetObject") or e.get("TargetFilename") or e.get("DestinationIp") or ""
    return str(what)


def _flagged(inc: Incident) -> Dict[str, List[str]]:
    flagged: Dict[str, List[str]] = {}
    for a in inc.alerts:
        if a.guid:
            names = flagged.setdefault(a.guid, [])
            if a.rule.title not in names:
                names.append(a.rule.title)
    return flagged


def build(events: List[Dict[str, Any]], rules: list, alerts: List[Alert], incidents: List[Incident], tree: ProcessTree, source: str) -> Report:
    hosts = {e.get("Computer") for e in events}
    techniques = {t for a in alerts for t in a.rule.techniques}
    extras = []
    for n, inc in enumerate(incidents, 1):
        lines = [
            f"Host: {inc.host}    severity: {inc.severity.upper()}    risk score: {inc.score}    alerts: {len(inc.alerts)}",
            f"Attack progression: {' -> '.join(inc.tactics)}",
            f"Techniques: {', '.join(inc.techniques)}",
            "",
        ]
        if not inc.root_guid.startswith("orphan:"):
            lines += tree.render(inc.root_guid, _flagged(inc))
        extras.append((f"Incident {n} · process tree", "\n".join(lines)))
    return Report(
        tool="sysmon-detection-engine",
        title="Sysmon detection report",
        subtitle="Sigma-style rules over Sysmon telemetry, correlated into incidents along the ATT&CK kill chain",
        meta={"source": source, "hosts": len(hosts), "rules loaded": len(rules)},
        kpis=[
            ("events", len(events), "acc"),
            ("alerts", len(alerts), "warn" if alerts else "good"),
            ("incidents", len(incidents), "bad" if incidents else "good"),
            ("ATT&CK techniques", len(techniques), "warn"),
            ("hosts", len(hosts), "acc"),
        ],
        charts=[
            ("Alerts by ATT&CK tactic", Counter(t for a in alerts for t in a.rule.tactics).most_common(10)),
            ("Alerts by technique", Counter(t for a in alerts for t in a.rule.techniques).most_common(10)),
        ],
        extras=extras,
        columns=["time", "host", "rule", "techniques", "activity"],
        rows=[
            {
                "severity": a.rule.level,
                "time": a.time[11:19],
                "host": a.event.get("Computer", "?"),
                "rule": a.rule.title,
                "techniques": ", ".join(a.rule.techniques),
                "activity": describe(a.event)[:100],
            }
            for a in sorted(alerts, key=lambda a: a.time)
        ],
        empty_message="No rule matched.",
    )


def write_dashboard(path: str, *args: Any) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(render(build(*args)))
