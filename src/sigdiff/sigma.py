"""A working subset of the Sigma format: parse, validate, compile to matchers.

Supported (and documented as such in the README):
  * logsource: product linux + service/category routing via mapping.py
  * detections: named selections with field:value pairs (AND), list values
    (OR by default, `|all` for AND), modifiers: contains, startswith,
    endswith, re; wildcards * and ? in plain values; keywords lists
  * conditions: `a`, `a and b`, `a and not b`, `not a`, `1 of keyword*`,
    `all of selection*`, `all of them`, parentheses
Anything else is a *hard compile error*, not a silent skip — a rule that
cannot be understood is a rule that cannot be trusted.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

import yaml

from .events import Event
from .mapping import KEYWORD_FIELDS, canonical_field, canonical_source

MATCHERS = ("contains", "startswith", "endswith", "re", "base64offset", "i")


@dataclass
class RuleError(Exception):
    msg: str


@dataclass
class Rule:
    path: str
    id: str
    title: str
    level: str
    status: str
    tags: list[str]
    source: str | None
    matcher: Callable[[Event], bool] | None = None
    error: str | None = None
    selections: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return self.error is None and self.matcher is not None and self.source is not None


# ---------------------------------------------------------------------------
# value matching
# ---------------------------------------------------------------------------

def _glob_re(pattern: str) -> re.Pattern[str]:
    out = []
    for ch in pattern:
        if ch == "*":
            out.append(".*")
        elif ch == "?":
            out.append(".")
        else:
            out.append(re.escape(ch))
    return re.compile("".join(out), re.I | re.S)


def make_value_matcher(mods: list[str], value: Any) -> Callable[[str], bool]:
    return _ValueMatcher(mods, str(value).lower())


class _ValueMatcher:
    def __init__(self, mods: list[str], value: str) -> None:
        self.mods = [m for m in mods if m in MATCHERS]
        self.value = value

    def __call__(self, actual: str) -> bool:
        a = actual.lower()
        v = self.value
        if "re" in self.mods:
            try:
                return re.search(v, a) is not None
            except re.error:
                return False
        if "contains" in self.mods:
            return v in a
        if "startswith" in self.mods:
            return a.startswith(v)
        if "endswith" in self.mods:
            return a.endswith(v)
        # plain value: wildcards honored, else case-insensitive equality
        if "*" in v or "?" in v:
            return _glob_re(v).fullmatch(a) is not None
        return a == v


# ---------------------------------------------------------------------------
# conditions
# ---------------------------------------------------------------------------

COND_TOKEN = re.compile(r"\s*([\w*|-]+|\(|\))")


def _tokenize(cond: str) -> list[str]:
    toks, i = [], 0
    cond = cond.replace("&&", " and ").replace("||", " or ")
    while i < len(cond):
        m = COND_TOKEN.match(cond, i)
        if not m:
            if cond[i].isspace():
                i += 1
                continue
            raise RuleError(f"bad condition near {cond[i:i+12]!r}")
        toks.append(m.group(1))
        i = m.end()
    return toks


class _CondParser:
    """Recursive descent over the supported condition grammar."""

    def __init__(self, toks: list[str], names: set[str]) -> None:
        self.toks, self.i, self.names = toks, 0, names
        self.sel: dict[str, Callable[[Event], bool]] = {}

    def peek(self) -> str | None:
        return self.toks[self.i] if self.i < len(self.toks) else None

    def next(self) -> str:
        t = self.toks[self.i]
        self.i += 1
        return t

    def parse(self):
        fn = self.or_expr()
        if self.i != len(self.toks):
            raise RuleError(f"trailing tokens in condition: {self.toks[self.i:]}")
        return fn

    def or_expr(self):
        fn = self.and_expr()
        while self.peek() in ("or", "||"):
            self.next()
            rhs = self.and_expr()
            fn = (lambda a=fn, b=rhs: (lambda ev: a(ev) or b(ev)))()
        return fn

    def and_expr(self):
        fn = self.unary()
        while self.peek() in ("and", "&&"):
            self.next()
            rhs = self.unary()
            fn = (lambda a=fn, b=rhs: (lambda ev: a(ev) and b(ev)))()
        return fn

    def unary(self):
        t = self.peek()
        if t == "not":
            self.next()
            inner = self.unary()
            return lambda ev: not inner(ev)
        return self.atom()

    def atom(self):
        t = self.peek()
        if t == "(":
            self.next()
            fn = self.or_expr()
            if self.peek() != ")":
                raise RuleError("unbalanced parens in condition")
            self.next()
            return fn
        if t is not None and re.fullmatch(r"\d+", t):
            # "1 of selection*", "all of them"
            self.next()
            if self.peek() != "of":
                raise RuleError("expected 'of' after count in condition")
            self.next()
            parts = []
            while True:
                p = self.peek()
                if p is None or p in ("and", "or", "not", "(", ")"):
                    break
                parts.append(self.next())
            wanted = "all" if t.lower() == "all" else int(t)
            if parts == ["them"]:
                names = sorted(self.names)
            else:
                names = [n for n in sorted(self.names) if any(_name_match(pat, n) for pat in parts)]
            if not names:
                raise RuleError(f"'{t} of {parts}' matched no selectors")
            fns = [self.sel[n] for n in names]
            if wanted == "all":
                return lambda ev, fns=fns: all(f(ev) for f in fns)
            return lambda ev, fns=fns, w=wanted: sum(1 for f in fns if f(ev)) >= w
        if t in self.names:
            self.next()
            return self.sel[t]
        raise RuleError(f"condition references unknown selector {t!r}")


def _name_match(pattern: str, name: str) -> bool:
    return _glob_re(pattern).fullmatch(name) is not None


# ---------------------------------------------------------------------------
# parsing + compiling
# ---------------------------------------------------------------------------

def compile_selection(selname: str, sel: Any, source: str) -> Callable[[Event], bool]:
    """Compile one named selection to an event predicate."""
    if isinstance(sel, list):  # keyword selection
        fields = KEYWORD_FIELDS[source]
        subs = [str(v).lower() for v in sel]
        return lambda ev, fs=fields, vs=subs: any(
            any(v in (ev.fields.get(f, "").lower()) for f in fs) for v in vs
        )
    if not isinstance(sel, dict):
        raise RuleError(f"selection {selname!r} must be a mapping or list, got {type(sel).__name__}")
    clauses = []
    for raw_field, value in sel.items():
        base, _, modstr = str(raw_field).partition("|")
        mods = modstr.split("|") if modstr else []
        all_mode = "all" in mods
        canon = canonical_field(source, base)
        if canon is None:
            raise RuleError(f"field {base!r} has no mapping for source {source!r} (in {selname!r})")
        values = value if isinstance(value, list) else [value]
        mtrs = [make_value_matcher(mods, v) for v in values]
        if all_mode:
            clauses.append((canon, mtrs, True))
        else:
            clauses.append((canon, mtrs, False))
    return lambda ev, cl=clauses: all(
        (all(m(ev.fields.get(c, "")) for m in ms) if is_all else any(m(ev.fields.get(c, "")) for m in ms))
        for c, ms, is_all in cl
    )


def compile_detection(source: str, detection: dict) -> Callable[[Event], bool]:
    """Compile a detection mapping (selections + condition) for a canonical
    source directly — the path load_rule takes after resolving a logsource."""
    sels_uncompiled = {k: v for k, v in detection.items() if k != "condition"}
    if not sels_uncompiled:
        raise RuleError("no selections")
    sels = {k: compile_selection(k, v, source) for k, v in sels_uncompiled.items()}
    cond_src = detection.get("condition")
    if cond_src is None:
        cond_src = "1 of them" if len(sels) > 1 else next(iter(sels))
    p = _CondParser(_tokenize(str(cond_src)), set(sels))
    p.sel = sels
    return p.parse()


def load_rule(path: Path) -> Rule:
    try:
        doc = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        return Rule(str(path), "", path.stem, "", "", [], None, error=f"yaml: {exc}")
    if not isinstance(doc, dict):
        return Rule(str(path), "", path.stem, "", "", [], None, error="not a mapping")

    det = doc.get("detection")
    ls = doc.get("logsource") or {}
    if not isinstance(det, dict) or not isinstance(ls, dict):
        return Rule(str(path), str(doc.get("id", "")), str(doc.get("title", path.stem)),
                    "", "", [], None, error="missing detection/logsource mapping")
    source = canonical_source(str(ls.get("category", "")), str(ls.get("service", "")),
                              str(ls.get("product", "")))
    if source is None:
        return Rule(str(path), str(doc.get("id", "")), str(doc.get("title", path.stem)),
                    str(doc.get("level", "")), str(doc.get("status", "experimental")),
                    [str(t) for t in doc.get("tags", [])], None,
                    error=f"no telemetry source on this host for logsource {ls}")
    sels_uncompiled = {k: v for k, v in det.items() if k != "condition"}
    if not sels_uncompiled:
        return Rule(str(path), str(doc.get("id", "")), str(doc.get("title", path.stem)),
                    "", "", [], source, error="no selections")
    try:
        sels = {k: compile_selection(k, v, source) for k, v in sels_uncompiled.items()}
        cond_src = det.get("condition")
        if cond_src is None:
            cond_src = "1 of them" if len(sels) > 1 else next(iter(sels), "")
        p = _CondParser(_tokenize(str(cond_src)), set(sels))
        p.sel = sels
        matcher = p.parse()
    except RuleError as exc:
        return Rule(str(path), str(doc.get("id", "")), str(doc.get("title", path.stem)),
                    str(doc.get("level", "")), str(doc.get("status", "experimental")),
                    [str(t) for t in doc.get("tags", [])], source, error=str(exc))
    if not sels:
        return Rule(str(path), "", path.stem, "", "", [], source, error="no selections")
    return Rule(
        path=str(path),
        id=str(doc.get("id", "")),
        title=str(doc.get("title", path.stem)),
        level=str(doc.get("level", "informational")),
        status=str(doc.get("status", "experimental")),
        tags=[str(t) for t in doc.get("tags", [])],
        source=source,
        matcher=matcher,
        selections=sorted(sels),
    )


def load_rules(directory: Path) -> list[Rule]:
    out = []
    for p in sorted(directory.rglob("*.yml")):
        out.append(load_rule(p))
    return out
