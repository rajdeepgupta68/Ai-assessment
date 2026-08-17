"""
Injection / prompt-manipulation detector.

Why this module exists:
  Anything fetched from an untrusted source is treated as raw bytes, not as
  instructions. Before any record is admitted into the clean pipeline it is
  scanned by three independent layers, each catches a different class of
  attack. A record fails if ANY layer raises; we never partially trust.

Layer 1 - Schema validation:
  Every field is checked against its declared type / pattern. A column that
  should be an integer cannot be a long imperative sentence; a notes column
  has a length cap. Catches attackers who try to hide a payload inside an
  obviously-mistyped field.

Layer 2 - Pattern / keyword detection:
  Regexes and key-phrase lists for known injection styles: prompt-override
  attempts ("ignore previous instructions"), SQL DDL/DML, shell command
  shapes, control characters, homoglyph unicode, javascript: URLs, base64
  blobs inside text fields. Catches the well-known attack patterns.

Layer 3 - Structural / semantic heuristics:
  Counts ratio of imperative verbs to content words, looks for instruction-
  shaped strings (commands, "you must", "<system>", "### Instruction:",
  "IMPORTANT: ignore", etc.), checks for invisible unicode. Catches novel
  attacks that the keyword list misses but that *look like* instructions.

Crucially, this module returns Verdict objects with a `reason` string. The
orchestrator logs the reason and NEVER executes any part of the rejected
content. The agent's own behaviour is driven by its system prompt and the
tool registry, never by data flowing through this module.
"""

from __future__ import annotations

import base64
import re
import unicodedata
from dataclasses import dataclass, field
from typing import Any, Iterable


# -- Verdict -----------------------------------------------------------------

@dataclass
class Verdict:
    safe: bool
    reasons: list[str] = field(default_factory=list)
    layer: str = ""
    payload_snippet: str = ""

    def add(self, layer: str, reason: str, snippet: str = "") -> None:
        self.safe = False
        self.layer = layer or self.layer
        self.reasons.append(reason)
        if snippet and not self.payload_snippet:
            self.payload_snippet = snippet[:200]

    def merge(self, other: "Verdict") -> None:
        if not other.safe:
            self.safe = False
            if other.layer:
                self.layer = other.layer
            self.reasons.extend(other.reasons)
            if other.payload_snippet and not self.payload_snippet:
                self.payload_snippet = other.payload_snippet


# -- Schema declaration ------------------------------------------------------

@dataclass
class FieldSpec:
    name: str
    kind: str  # "int", "float", "str", "id", "date", "email"
    required: bool = True
    max_length: int | None = None
    pattern: str | None = None  # optional regex the value must match


@dataclass
class Schema:
    name: str
    key_field: str  # the field used to join / reconcile across sources
    fields: list[FieldSpec]
    notes_field: str | None = None  # free-text field (gets extra scanning)

    def field_map(self) -> dict[str, FieldSpec]:
        return {f.name: f for f in self.fields}


# -- Helpers -----------------------------------------------------------------

_INVISIBLE_CODEPOINTS = {
    0x200B, 0x200C, 0x200D, 0x2060, 0xFEFF,  # zero-width
    0x202A, 0x202B, 0x202C, 0x202D, 0x202E,  # bidi
    0x00AD,  # soft hyphen
}

def _has_invisible(s: str) -> bool:
    return any(ord(c) in _INVISIBLE_CODEPOINTS for c in s)

def _normalize(s: str) -> str:
    # Strip zero-width / bidi so we can still match on the visible text.
    return "".join(c for c in unicodedata.normalize("NFKC", s)
                   if ord(c) not in _INVISIBLE_CODEPOINTS)


# -- Layer 1: schema ---------------------------------------------------------

class SchemaValidator:
    """Type / shape checks. A value that doesn't fit its declared type is
    treated as a probable injection, not as a benign typo."""

    def __init__(self, schema: Schema):
        self.schema = schema

    def check_record(self, record: dict[str, Any]) -> Verdict:
        v = Verdict(safe=True)
        fmap = self.schema.field_map()

        # Required fields present.
        for f in self.schema.fields:
            if f.required and (f.name not in record or record[f.name] in (None, "")):
                v.add("schema", f"required field '{f.name}' missing")
                return v

        for name, value in record.items():
            spec = fmap.get(name)
            if spec is None:
                # Unknown field - drop with a reason. We treat unknown fields
                # as suspicious because attackers append extra fields.
                v.add("schema", f"unknown field '{name}' rejected")
                continue

            if not self._check_value(spec, value):
                snippet = repr(value)[:80]
                v.add("schema",
                      f"field '{name}' fails type={spec.kind} "
                      f"(value={snippet})")
        return v

    def _check_value(self, spec: FieldSpec, value: Any) -> bool:
        if value is None:
            return not spec.required
        if not isinstance(value, (str, int, float)):
            return False

        s = str(value)
        if spec.max_length and len(s) > spec.max_length:
            return False
        if spec.pattern and not re.fullmatch(spec.pattern, s):
            return False

        if spec.kind == "int":
            try:
                int(str(value).strip())
            except (ValueError, TypeError):
                return False
        elif spec.kind == "float":
            try:
                float(str(value).strip())
            except (ValueError, TypeError):
                return False
        elif spec.kind == "id":
            return bool(re.fullmatch(r"[A-Za-z0-9_\-]{1,32}", s))
        elif spec.kind == "date":
            return bool(re.fullmatch(r"\d{4}-\d{2}-\d{2}", s))
        elif spec.kind == "email":
            return bool(re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", s))
        elif spec.kind == "str":
            # A string field shouldn't look like a long imperative sentence
            # - real data is short. > 1k chars of free text in a typed field
            # is a red flag.
            if len(s) > 1000:
                return False
        return True


# -- Layer 2: pattern / keyword ---------------------------------------------

# Phrases we treat as instruction-shaped.
_PROMPT_OVERRIDE_PATTERNS = [
    r"ignore\s+(all\s+)?previous\s+(instructions?|rules?|prompts?)",
    r"disregard\s+(all\s+)?(prior|above|previous)\s+(instructions?|rules?|context)",
    r"forget\s+(everything|all)\s+(you\s+)?(were|are)\s+told",
    r"you\s+are\s+now\s+(a|an)\s+",
    r"act\s+as\s+(a|an)\s+",
    r"system\s*:\s*",
    r"<\|im_start\|>",
    r"<\|im_end\|>",
    r"###\s*instruction",
    r"###\s*system",
    r"new\s+instructions?\s*:",
    r"override\s+(system|developer|previous)\s+prompt",
    r"reveal\s+(the\s+)?(system|developer)\s+prompt",
    r"execute\s+(the\s+following|this)\s+command",
]

_SQL_PATTERNS = [
    r"\bdrop\s+table\b",
    r"\bdelete\s+from\b",
    r"\btruncate\s+table\b",
    r";\s*drop\s+",
    r"\bunion\s+select\b",
    r"\binsert\s+into\b.*values\s*\(",
    r"--\s*$",   # SQL line comment at end of field
    r"\bor\s+1\s*=\s*1\b",
    r"xp_cmdshell",
]

_SHELL_PATTERNS = [
    r"\$\([^)]*\)",       # $(...)
    r"`[^`]+`",           # backticks
    r"\brm\s+-rf\b",
    r"\bcurl\s+[^\s]+\s+\|\s*sh",
    r"\bwget\s+[^\s]+\s+-O\s*-",
    r"\bnc\s+-e\b",
    r"\bpowershell\b\s+-e",
]

_JS_URL_PATTERNS = [
    r"javascript\s*:",
    r"data\s*:\s*text/html",
    r"vbscript\s*:",
]

_BASE64_BLOB = re.compile(r"\b[A-Za-z0-9+/]{120,}={0,2}\b")


class PatternScanner:
    """Regex / phrase scanning against well-known attack patterns."""

    def __init__(self, schema: Schema):
        self.schema = schema
        # Compile prompt-override, SQL, shell, JS patterns once.
        self._prompt = [re.compile(p, re.IGNORECASE) for p in _PROMPT_OVERRIDE_PATTERNS]
        self._sql     = [re.compile(p, re.IGNORECASE) for p in _SQL_PATTERNS]
        self._shell   = [re.compile(p, re.IGNORECASE) for p in _SHELL_PATTERNS]
        self._jsurl   = [re.compile(p, re.IGNORECASE) for p in _JS_URL_PATTERNS]

    def scan(self, record: dict[str, Any]) -> Verdict:
        v = Verdict(safe=True)
        for name, value in record.items():
            if value is None:
                continue
            text = str(value)
            norm = _normalize(text)
            if not text:
                continue

            # All free-text fields and the notes field get full pattern scan.
            scan_full = (name == self.schema.notes_field) or \
                        self._field_is_text(name)

            if _has_invisible(text):
                v.add("pattern", f"field '{name}' contains invisible unicode", text)
                continue

            for label, patterns in (("prompt-override", self._prompt),
                                    ("sql", self._sql),
                                    ("shell", self._shell)):
                if not scan_full:
                    break
                for p in patterns:
                    m = p.search(norm)
                    if m:
                        v.add("pattern",
                              f"field '{name}' matches {label} pattern '{m.group(0)}'",
                              text)
                        break

            if scan_full:
                for p in self._jsurl:
                    m = p.search(norm)
                    if m:
                        v.add("pattern",
                              f"field '{name}' contains {m.group(0)!r} URL scheme",
                              text)
                        break
                m = _BASE64_BLOB.search(norm)
                if m:
                    snippet = m.group(0)[:60] + "..."
                    # Only flag if base64 actually decodes to something that
                    # looks like instructions - we don't want to reject
                    # legitimately long tokens.
                    decoded = _try_decode_b64(m.group(0))
                    if decoded and _looks_like_instruction(decoded):
                        v.add("pattern",
                              f"field '{name}' contains base64 that decodes "
                              f"to instruction-shaped text",
                              snippet)
        return v

    def _field_is_text(self, name: str) -> bool:
        spec = self.schema.field_map().get(name)
        return spec is not None and spec.kind in ("str", "email")


def _try_decode_b64(blob: str) -> str | None:
    try:
        return base64.b64decode(blob).decode("utf-8", errors="replace")
    except Exception:
        return None


def _looks_like_instruction(s: str) -> bool:
    s = s.lower()
    cues = ("ignore", "delete", "drop table", "system:", "you are now",
            "override", "execute", "forget previous")
    return any(c in s for c in cues)


# -- Layer 3: structural / semantic -----------------------------------------

_IMPERATIVE_CUES = (
    "ignore", "delete", "drop", "truncate", "execute", "run", "send",
    "post", "email", "transfer", "wire", "override", "reveal", "print",
    "dump", "exfiltrate", "fetch", "download", "upload", "wipe",
    "kill", "shutdown", "restart", "reset", "format",
)

_PLEASE_PHRASES = (
    "please", "you must", "as per", "kindly", "make sure to",
    "before continuing", "important: ", "warning: ", "note: ", "hint: ",
)

class SemanticScanner:
    """Catches novel instruction-shaped payloads the keyword list misses."""

    def __init__(self, schema: Schema):
        self.schema = schema

    def scan(self, record: dict[str, Any]) -> Verdict:
        v = Verdict(safe=True)
        for name, value in record.items():
            if value is None:
                continue
            text = str(value)
            # Only inspect text-shaped fields.
            if not self._is_text_field(name):
                continue

            norm = _normalize(text).lower()
            if not norm:
                continue

            imperative_hits = sum(1 for w in _IMPERATIVE_CUES if w in norm)
            please_hits = sum(1 for p in _PLEASE_PHRASES if p in norm)

            # If the field looks like a sentence with multiple imperative verbs
            # AND includes politeness cues, treat it as an attempted prompt
            # injection - real customer data doesn't sound like this.
            if imperative_hits >= 2 and please_hits >= 1:
                v.add("semantic",
                      f"field '{name}' is instruction-shaped "
                      f"({imperative_hits} imperative verbs, "
                      f"{please_hits} politeness cues)",
                      text)
                continue

            # System-prompt-style markers anywhere.
            if any(tok in text for tok in ("<system>", "</system>",
                                            "<assistant>", "<<SYS>>",
                                            "[INST]", "[/INST]")):
                v.add("semantic",
                      f"field '{name}' contains chat-template markers",
                      text)
                continue

            # Long free-text fields with a very high imperative ratio.
            words = norm.split()
            if len(words) >= 12:
                imp_ratio = imperative_hits / max(len(words), 1)
                if imp_ratio > 0.15:
                    v.add("semantic",
                          f"field '{name}' has high imperative density "
                          f"({imp_ratio:.0%})",
                          text)
        return v

    def _is_text_field(self, name: str) -> bool:
        spec = self.schema.field_map().get(name)
        return spec is not None and spec.kind in ("str", "email")


# -- Public entry point ------------------------------------------------------

class InjectionDetector:
    """Composes the three layers; ANY layer rejecting = record rejected."""

    def __init__(self, schema: Schema):
        self.schema = schema
        self.schema_v = SchemaValidator(schema)
        self.pattern  = PatternScanner(schema)
        self.semantic = SemanticScanner(schema)

    def check(self, record: dict[str, Any]) -> Verdict:
        v = self.schema_v.check_record(record)
        if not v.safe:
            return v
        v.merge(self.pattern.scan(record))
        if not v.safe:
            return v
        v.merge(self.semantic.scan(record))
        return v

    def check_batch(self, records: Iterable[dict[str, Any]]):
        for r in records:
            yield r, self.check(r)
