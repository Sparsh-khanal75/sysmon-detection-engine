"""
A Sigma-compatible rule matcher (supported subset).

Supported
  detection:
    <name>:                     a selection: map of field -> value(s)
      Field: value              exact match (case-insensitive)
      Field: [a, b]             OR of values
      Field|contains: x         modifiers: contains, startswith, endswith, re, all
      Field|contains|all: [..]  every value must match
    <name>: [ {map}, {map} ]    list of maps = OR of selections
    condition: "sel and not filter" | "1 of sel_*" | "all of them" | (...) or/and/not
"""
from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List

import yaml

LEVELS = {"informational": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


# --------------------------------------------------------------------------- #
# Field matching
# --------------------------------------------------------------------------- #

def _value_matcher(modifiers: List[str], expected: Any) -> Callable[[Any], bool]:
    exp = str(expected)
    if "re" in modifiers:
        rx = re.compile(exp, re.I)
        return lambda v: v is not None and bool(rx.search(str(v)))
    exp_l = exp.lower()
    if "contains" in modifiers:
        return lambda v: v is not None and exp_l in str(v).lower()
    if "startswith" in modifiers:
        return lambda v: v is not None and str(v).lower().startswith(exp_l)
    if "endswith" in modifiers:
        return lambda v: v is not None and str(v).lower().endswith(exp_l)
    if "*" in exp or "?" in exp:  # Sigma wildcard in a plain value
        return lambda v: v is not None and fnmatch.fnmatchcase(str(v).lower(), exp_l)
    return lambda v: v is not None and str(v).lower() == exp_l


def _compile_selection(sel: Dict[str, Any]) -> Callable[[Dict[str, Any]], bool]:
    checks = []
    for key, expected in sel.items():
        fname, *mods = key.split("|")
        values = expected if isinstance(expected, list) else [expected]
        matchers = [_value_matcher(mods, v) for v in values]
        combine = all if "all" in mods else any
        checks.append((fname, matchers, combine))

    def match(event: Dict[str, Any]) -> bool:
        return all(combine(m(event.get(fname)) for m in matchers) for fname, matchers, combine in checks)
    return match


def compile_detection_item(item: Any) -> Callable[[Dict[str, Any]], bool]:
    if isinstance(item, dict):
        return _compile_selection(item)
    if isinstance(item, list):  # list of maps = OR
        subs = [_compile_selection(i) for i in item]
        return lambda e: any(s(e) for s in subs)
    raise ValueError(f"Unsupported detection item: {item!r}")


# --------------------------------------------------------------------------- #
# Condition parser (recursive descent):  expr := term (or term)*
#   term := factor (and factor)*   factor := not factor | ( expr ) | N of pat | name
# --------------------------------------------------------------------------- #

TOKEN_RE = re.compile(r"\(|\)|[A-Za-z0-9_*]+")


class ConditionParser:
    def __init__(self, text: str, names: Dict[str, Callable]):
        self.tokens = TOKEN_RE.findall(text)
        self.pos = 0
        self.names = names

    def parse(self) -> Callable[[Dict[str, Any]], bool]:
        fn = self._expr()
        if self.pos != len(self.tokens):
            raise ValueError(f"Unexpected token {self.tokens[self.pos]!r}")
        return fn

    def _peek(self):
        return self.tokens[self.pos].lower() if self.pos < len(self.tokens) else None

    def _take(self):
        tok = self.tokens[self.pos]
        self.pos += 1
        return tok

    def _expr(self):
        left = self._term()
        while self._peek() == "or":
            self._take()
            right, prev = self._term(), left
            left = lambda e, a=prev, b=right: a(e) or b(e)
        return left

    def _term(self):
        left = self._factor()
        while self._peek() == "and":
            self._take()
            right, prev = self._factor(), left
            left = lambda e, a=prev, b=right: a(e) and b(e)
        return left

    def _factor(self):
        tok = self._peek()
        if tok == "not":
            self._take()
            inner = self._factor()
            return lambda e: not inner(e)
        if tok == "(":
            self._take()
            inner = self._expr()
            if self._take() != ")":
                raise ValueError("Missing ')'")
            return inner
        if self.pos + 1 < len(self.tokens) and self.tokens[self.pos + 1].lower() == "of":
            quant = self._take().lower()
            self._take()  # 'of'
            pattern = self._take()
            pattern = "*" if pattern.lower() == "them" else pattern
            fns = [f for n, f in self.names.items() if fnmatch.fnmatchcase(n, pattern)]
            if not fns:
                raise ValueError(f"No selection matches {pattern!r}")
            if quant == "all":
                return lambda e: all(f(e) for f in fns)
            n = int(quant)
            return lambda e: sum(1 for f in fns if f(e)) >= n
        name = self._take()
        if name not in self.names:
            raise ValueError(f"Unknown selection {name!r}")
        return self.names[name]


# --------------------------------------------------------------------------- #
# Rule object
# --------------------------------------------------------------------------- #

@dataclass
class Rule:
    id: str
    title: str
    level: str
    description: str
    tags: List[str]
    event_ids: List[int]
    matcher: Callable[[Dict[str, Any]], bool] = field(repr=False)
    path: str = ""
    falsepositives: List[str] = field(default_factory=list)

    @property
    def techniques(self) -> List[str]:
        return [t.split(".", 1)[1].upper() for t in self.tags if re.match(r"attack\.t\d{4}", t)]

    @property
    def tactics(self) -> List[str]:
        return [t.split(".", 1)[1].replace("_", "-") for t in self.tags
                if t.startswith("attack.") and not re.match(r"attack\.t\d{4}", t)]

    def matches(self, event: Dict[str, Any]) -> bool:
        if self.event_ids and event.get("EventID") not in self.event_ids:
            return False
        return self.matcher(event)


def load_rule(path: Path) -> Rule:
    doc = yaml.safe_load(path.read_text(encoding="utf-8"))
    det = dict(doc["detection"])
    condition = det.pop("condition")
    names = {name: compile_detection_item(item) for name, item in det.items()}
    eids = doc.get("logsource", {}).get("event_ids", [])
    return Rule(
        id=doc["id"], title=doc["title"], level=doc.get("level", "medium"),
        description=doc.get("description", "").strip(), tags=doc.get("tags", []),
        event_ids=eids, matcher=ConditionParser(condition, names).parse(),
        path=str(path), falsepositives=doc.get("falsepositives", []),
    )


def load_rules(directory: str | Path) -> List[Rule]:
    rules = [load_rule(p) for p in sorted(Path(directory).rglob("*.yml"))]
    ids = [r.id for r in rules]
    dupes = {i for i in ids if ids.count(i) > 1}
    if dupes:
        raise ValueError(f"Duplicate rule ids: {dupes}")
    return rules
