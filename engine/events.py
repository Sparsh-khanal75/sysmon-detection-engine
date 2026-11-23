"""Load Sysmon events from JSON / JSONL in several common export formats."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Iterator, List


def _flatten_eventdata(data: Any) -> Dict[str, Any]:
    if isinstance(data, dict):
        # python-evtx / xmltodict style: {"Data": [{"@Name": "Image", "#text": "..."}]}
        if "Data" in data and isinstance(data["Data"], list):
            return {d.get("@Name") or d.get("Name"): d.get("#text") for d in data["Data"]}
        return dict(data)
    return {}


def normalise(raw: Dict[str, Any]) -> Dict[str, Any]:
    """Return a flat dict with EventID (int), Computer, UtcTime and all EventData fields."""
    if "Event" in raw:  # evtx_dump --format jsonl / python-evtx -> xmltodict
        system = raw["Event"].get("System", {})
        ev = _flatten_eventdata(raw["Event"].get("EventData", {}))
        eid = system.get("EventID")
        ev["EventID"] = eid.get("#text") if isinstance(eid, dict) else eid
        ev.setdefault("Computer", system.get("Computer"))
    elif "winlog" in raw:  # Winlogbeat / Elastic ECS
        w = raw["winlog"]
        ev = dict(w.get("event_data", {}))
        ev["EventID"] = w.get("event_id")
        ev.setdefault("Computer", w.get("computer_name"))
        ev.setdefault("UtcTime", raw.get("@timestamp"))
    else:  # already flat (e.g. Get-WinEvent | ConvertTo-Json after flattening)
        ev = dict(raw)
    ev["EventID"] = int(ev["EventID"]) if ev.get("EventID") is not None else None
    return ev


def load_events(path: str | Path) -> List[Dict[str, Any]]:
    text = Path(path).read_text(encoding="utf-8-sig").strip()
    if text.startswith("["):
        raws = json.loads(text)
    else:
        raws = [json.loads(line) for line in text.splitlines() if line.strip()]
    events = [normalise(r) for r in raws]
    for i, e in enumerate(events):
        e["_index"] = i
    return sorted(events, key=lambda e: (e.get("UtcTime") or "", e["_index"]))


def iter_jsonl(path: str | Path) -> Iterator[Dict[str, Any]]:
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            if line.strip():
                yield normalise(json.loads(line))
