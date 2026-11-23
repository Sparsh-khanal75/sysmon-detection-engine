"""Enrichment applied to events before rules run."""
from __future__ import annotations

import base64
import binascii
import re
from typing import Any, Dict, List

ENC_RE = re.compile(r"\s[-/](?:e|ec|en|enc|enco|encod|encodedcommand)\s+([A-Za-z0-9+/=]{20,})", re.I)


def decode_powershell(cmdline: str) -> str | None:
    """Decode the Base64 (UTF-16LE) payload of `powershell -EncodedCommand`."""
    m = ENC_RE.search(cmdline or "")
    if not m:
        return None
    try:
        return base64.b64decode(m.group(1)).decode("utf-16-le", errors="replace")
    except (binascii.Error, ValueError):
        return None


def enrich(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    for e in events:
        decoded = decode_powershell(e.get("CommandLine", ""))
        if decoded:
            e["CommandLineDecoded"] = decoded
    return events
