"""Agent orchestrator.

Composes the readers, the injection detector, and the reconciliation
engine. Every step is logged to an append-only audit log.

The agent's own behaviour is driven by this file - never by any data
value. No fetched string is ever passed to eval/exec/shell. The detector
returns reasons that get logged verbatim; nothing in those reasons is
treated as an instruction.
"""

from __future__ import annotations

import csv
import json
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from .injection_detector import (
    InjectionDetector,
    Schema,
    FieldSpec,
    Verdict,
)
from .reconciliation import (
    ReconciliationEngine,
    ReconciledRecord,
    SourceMeta,
    fingerprint,
)
from .source_readers import (
    CsvReader,
    HtmlTableReader,
    JsonReader,
    SourceRecord,
)


class AuditLog:
    """Append-only JSONL event log."""

    def __init__(self, path: Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text("", encoding="utf-8")

    def write(self, event_type: str, **fields: Any) -> None:
        ts = datetime.now(timezone.utc).isoformat()
        record = {"ts": ts, "event": event_type, **fields}
        with self.path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(record, ensure_ascii=False, default=str) + "\n")

    def dump(self) -> list[dict[str, Any]]:
        if not self.path.exists():
            return []
        return [json.loads(line) for line in self.path.read_text(
            encoding="utf-8").splitlines() if line]


READERS: dict[str, Callable[[str], Any]] = {
    "csv": lambda sid: CsvReader(sid),
    "json": lambda sid: JsonReader(sid),
    "html": lambda sid: HtmlTableReader(sid),
}


class SanitisationAgent:
    def __init__(
        self,
        schema: Schema,
        sources: list[tuple[str, str, float, str]],
        strategy: str = "weighted_trust_recency",
        log_path: Path | str = "logs/audit.jsonl",
    ):
        """
        sources: list of (source_id, kind, trust, observed_at).
            kind is one of "csv" | "json" | "html".
        """
        self.schema = schema
        self.strategy = strategy
        self.sources_cfg = sources
        self.log = AuditLog(Path(log_path))
        self.detector = InjectionDetector(schema)
        self.engine = ReconciliationEngine(
            key_field=schema.key_field,
            strategy=strategy,
        )

    def run(self, source_paths: dict[str, Path]) -> dict[str, Any]:
        self._step_plan()
        records, metas = self._step_fetch(source_paths)
        accepted = self._step_validate(records, metas)
        reconciled, conflicts = self._step_reconcile(accepted)
        out_files = self._step_store(reconciled)

        summary = {
            "sources_read": len(source_paths),
            "records_fetched": sum(len(v) for v in records.values()),
            "records_accepted": sum(len(v) for v in accepted.values()),
            "records_rejected": sum(len(v) for v in records.values())
                                - sum(len(v) for v in accepted.values()),
            "records_emitted": len(reconciled),
            "conflicts_resolved": len(conflicts),
            "outputs": {k: str(v) for k, v in out_files.items()},
            "strategy": self.strategy,
        }
        self.log.write("summary", **summary)
        return summary

    def _step_plan(self) -> None:
        self.log.write(
            "plan",
            schema=self.schema.name,
            key_field=self.schema.key_field,
            fields=[f.name for f in self.schema.fields],
            strategy=self.strategy,
            strategy_justification=(
                "weighted_trust_recency: trusted authoritative source wins "
                "on conflict; recency is the tiebreak. Avoids the failure "
                "mode of majority voting where a single attacker-controlled "
                "feed cannot be outvoted by two clean sources."
            ),
            sources=[
                {"id": sid, "kind": kind, "trust": trust, "observed_at": obs}
                for sid, kind, trust, obs in self.sources_cfg
            ],
        )

    def _step_fetch(self, paths: dict[str, Path]) -> tuple[
            dict[str, list[SourceRecord]], dict[str, SourceMeta]]:
        records: dict[str, list[SourceRecord]] = {}
        metas: dict[str, SourceMeta] = {}
        for source_id, kind, trust, observed_at in self.sources_cfg:
            path = Path(paths[source_id])
            reader = READERS[kind](source_id)
            recs = reader.read(path)
            records[source_id] = recs
            metas[source_id] = SourceMeta(
                source_id=source_id,
                trust=trust,
                observed_at=observed_at,
                kind=kind,
            )
            self.log.write(
                "fetch",
                source=source_id,
                kind=kind,
                path=str(path),
                rows=len(recs),
            )
        return records, metas

    def _step_validate(
        self,
        records: dict[str, list[SourceRecord]],
        metas: dict[str, SourceMeta],
    ) -> dict[str, list[tuple[SourceRecord, SourceMeta]]]:
        accepted: dict[str, list[tuple[SourceRecord, SourceMeta]]] = {}
        for source_id, recs in records.items():
            bucket: list[tuple[SourceRecord, SourceMeta]] = []
            for rec in recs:
                verdict = self.detector.check(rec.data)
                if verdict.safe:
                    bucket.append((rec, metas[source_id]))
                else:
                    self.log.write(
                        "reject",
                        source=source_id,
                        row=rec.row_index,
                        layer=verdict.layer,
                        reasons=verdict.reasons,
                        snippet=verdict.payload_snippet,
                        record_id=rec.data.get(self.schema.key_field, ""),
                    )
            accepted[source_id] = bucket
            self.log.write(
                "validate_summary",
                source=source_id,
                accepted=len(bucket),
                rejected=len(recs) - len(bucket),
            )
        return accepted

    def _step_reconcile(
        self,
        accepted: dict[str, list[tuple[SourceRecord, SourceMeta]]],
    ) -> tuple[list[ReconciledRecord], list]:
        flat = [pair for bucket in accepted.values() for pair in bucket]
        reconciled, conflicts = self.engine.reconcile(flat)
        for c in conflicts:
            self.log.write(
                "conflict_resolved",
                key=c.key,
                field=c.field,
                candidates=c.candidates,
                winner=c.winner_source,
                rule=c.rule,
            )
        for r in reconciled:
            self.log.write(
                "emit_record",
                key=r.key,
                sources=r.sources,
                fingerprint=fingerprint(r.values),
                fields=r.values,
            )
        return reconciled, conflicts

    def _step_store(
        self,
        reconciled: list[ReconciledRecord],
    ) -> dict[str, Path]:
        out_dir = Path("data/clean")
        out_dir.mkdir(parents=True, exist_ok=True)

        json_path = out_dir / "clean.json"
        csv_path = out_dir / "clean.csv"

        with json_path.open("w", encoding="utf-8") as f:
            json.dump(
                [
                    {
                        "key": r.key,
                        "values": r.values,
                        "sources": r.sources,
                        "conflicts": [asdict(c) for c in r.conflicts],
                        "fingerprint": fingerprint(r.values),
                    }
                    for r in reconciled
                ],
                f,
                indent=2,
                ensure_ascii=False,
            )

        if reconciled:
            fields = list(reconciled[0].values.keys())
            with csv_path.open("w", encoding="utf-8", newline="") as f:
                w = csv.DictWriter(f, fieldnames=fields)
                w.writeheader()
                for r in reconciled:
                    w.writerow(r.values)

        self.log.write("store", json=str(json_path), csv=str(csv_path),
                       rows=len(reconciled))
        return {"json": json_path, "csv": csv_path}
