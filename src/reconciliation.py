"""Reconciliation engine.

Strategy: weighted trust with recency tiebreak.

  Each source carries a trust weight (0.0-1.0). On conflict the value
  from the higher-trust source wins. Ties within 1% of trust are broken
  by most recent observed_at. This is chosen over majority voting (a
  single attacker-controlled source can never be outvoted by two clean
  ones) and over pure recency (a trusted upstream is often older than a
  stale downstream snapshot).

Strategies are registered by name; swapping is a one-liner.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any


@dataclass
class SourceMeta:
    source_id: str
    trust: float             # 0.0 - 1.0; higher wins on conflict
    observed_at: str         # ISO date; more recent wins on tie
    kind: str = "unknown"


@dataclass
class ConflictLog:
    key: str
    field: str
    candidates: list[tuple[str, Any]]
    winner_source: str
    rule: str

    def render(self) -> str:
        opts = ", ".join(f"{sid}={val!r}" for sid, val in self.candidates)
        return (f"conflict on key={self.key} field={self.field}: [{opts}] "
                f"-> winner={self.winner_source} (rule={self.rule})")


@dataclass
class ReconciledRecord:
    key: str
    values: dict[str, Any]
    sources: list[str]
    conflicts: list[ConflictLog] = field(default_factory=list)


def weighted_trust_with_recency(
    key: str,
    field: str,
    candidates: list[tuple[SourceMeta, Any]],
) -> tuple[str, str]:
    if not candidates:
        return ("", "no-candidates")

    max_trust = max(c[0].trust for c in candidates)
    top = [c for c in candidates if c[0].trust >= max_trust - 0.01]
    if len(top) == 1:
        return (top[0][0].source_id, f"highest-trust={max_trust:.2f}")

    def parse(d: str) -> datetime:
        try:
            return datetime.fromisoformat(d)
        except ValueError:
            return datetime.min

    top.sort(key=lambda c: parse(c[0].observed_at), reverse=True)
    return (top[0][0].source_id,
            f"trust-tied-at={max_trust:.2f}; recency={top[0][0].observed_at}")


def majority_voting(
    key: str,
    field: str,
    candidates: list[tuple[SourceMeta, Any]],
) -> tuple[str, str]:
    counts: dict[Any, list[SourceMeta]] = {}
    for meta, val in candidates:
        counts.setdefault(val, []).append(meta)
    best_val = max(counts.keys(), key=lambda v: len(counts[v]))
    bucket = counts[best_val]
    if len(bucket) > len(candidates) / 2:
        return (bucket[0].source_id,
                f"majority value={best_val!r} ({len(bucket)}/{len(candidates)})")
    bucket.sort(key=lambda m: m.trust, reverse=True)
    return (bucket[0].source_id,
            f"majority-tie-broken-by-trust value={best_val!r}")


STRATEGIES = {
    "weighted_trust_recency": weighted_trust_with_recency,
    "majority": majority_voting,
}


class ReconciliationEngine:
    """Joins records across sources by `key_field` and resolves per-field
    conflicts using the chosen strategy."""

    def __init__(
        self,
        key_field: str,
        strategy: str = "weighted_trust_recency",
    ):
        if strategy not in STRATEGIES:
            raise ValueError(f"unknown strategy '{strategy}'")
        self.key_field = key_field
        self.strategy = strategy

    def reconcile(
        self,
        accepted: list[tuple["SourceRecord", SourceMeta]],
    ) -> tuple[list[ReconciledRecord], list[ConflictLog]]:
        groups: dict[str, list[tuple]] = {}
        for sr, meta in accepted:
            key = str(sr.data.get(self.key_field, "")).strip()
            if not key:
                continue
            groups.setdefault(key, []).append((sr, meta))

        out_records: list[ReconciledRecord] = []
        all_conflicts: list[ConflictLog] = []

        for key, group in groups.items():
            field_names: list[str] = []
            seen: set[str] = set()
            for sr, _ in group:
                for f in sr.data:
                    if f not in seen and f != self.key_field:
                        seen.add(f)
                        field_names.append(f)

            merged: dict[str, Any] = {}
            conflicts_for_key: list[ConflictLog] = []
            sources_for_key: list[str] = []
            for f in field_names:
                cands: list[tuple[SourceMeta, Any]] = []
                for sr, meta in group:
                    if f in sr.data:
                        cands.append((meta, sr.data[f]))
                if not cands:
                    continue
                if len(cands) == 1:
                    merged[f] = cands[0][1]
                    continue

                distinct_values = {str(c[1]) for c in cands}
                if len(distinct_values) == 1:
                    merged[f] = cands[0][1]
                    continue

                winner_id, rule = STRATEGIES[self.strategy](key, f, cands)
                winner_value = next(
                    v for m, v in cands if m.source_id == winner_id
                )
                merged[f] = winner_value

                log = ConflictLog(
                    key=key,
                    field=f,
                    candidates=[(m.source_id, v) for m, v in cands],
                    winner_source=winner_id,
                    rule=rule,
                )
                conflicts_for_key.append(log)
                all_conflicts.append(log)

            for sr, meta in group:
                if meta.source_id not in sources_for_key:
                    sources_for_key.append(meta.source_id)

            merged[self.key_field] = key
            out_records.append(ReconciledRecord(
                key=key,
                values=merged,
                sources=sources_for_key,
                conflicts=conflicts_for_key,
            ))

        return out_records, all_conflicts


def fingerprint(values: dict[str, Any]) -> str:
    """Stable hash of a record's values for the audit log."""
    h = hashlib.sha256()
    for k in sorted(values):
        h.update(k.encode("utf-8"))
        h.update(b"\x00")
        h.update(str(values[k]).encode("utf-8", errors="replace"))
        h.update(b"\x00")
    return h.hexdigest()[:16]
