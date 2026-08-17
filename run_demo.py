"""
End-to-end demo.

Runs the agent against the three bundled sample sources (CSV, JSON, HTML)
and prints a human-readable summary. Designed to be the demo for the
three-minute screencast: it completes in under five seconds, shows the
agent detecting two distinct injection attacks (one in CSV, one in
HTML) and resolving a genuine conflict (Alice's phone and city differ
between CRM and the scraped dashboard).

Usage:
    python run_demo.py
"""

from __future__ import annotations

from pathlib import Path

from src import FieldSpec, SanitisationAgent, Schema


# Schema declaration for the customer dataset. Every record that doesn't
# match this shape is rejected by the schema layer of the detector.
SCHEMA = Schema(
    name="customer",
    key_field="customer_id",
    fields=[
        FieldSpec("customer_id", kind="id",     max_length=16),
        FieldSpec("email",       kind="email",  max_length=120),
        FieldSpec("name",        kind="str",    max_length=120),
        FieldSpec("phone",       kind="str",    max_length=40),
        FieldSpec("city",        kind="str",    max_length=80),
        FieldSpec("signup_date", kind="date"),
        FieldSpec("notes",       kind="str",    max_length=500, required=False),
    ],
    notes_field="notes",
)


# Source configuration. Trust weights reflect reality: CRM is the system
# of record, the marketing export is a snapshot from a week ago, the web
# scrape is least trusted and least recent.
SOURCES = [
    # (source_id,    kind, trust, observed_at)
    ("crm",       "csv",   0.95, "2024-08-15"),
    ("marketing", "json",  0.75, "2024-08-10"),
    ("web",       "html",  0.50, "2024-08-12"),
]

PATHS = {
    "crm":       Path("sample_data/customers_crm.csv"),
    "marketing": Path("sample_data/customers_marketing.json"),
    "web":       Path("sample_data/customers_web.html"),
}


def main() -> None:
    agent = SanitisationAgent(
        schema=SCHEMA,
        sources=SOURCES,
        strategy="weighted_trust_recency",
        log_path="logs/audit.jsonl",
    )

    print("=" * 72)
    print("SANITISATION AGENT - end-to-end run")
    print("=" * 72)
    summary = agent.run(PATHS)

    print("\n--- SUMMARY ----------------------------------------------")
    for k, v in summary.items():
        print(f"  {k}: {v}")
    print("\n--- CLEAN OUTPUT ----------------------------------------")
    clean = Path(summary["outputs"]["json"])
    data = __import__("json").loads(clean.read_text(encoding="utf-8"))
    for rec in data:
        print(f"  [{rec['key']}] sources={rec['sources']}")
        for f, v in rec["values"].items():
            if f == rec["key"]:
                continue
            marker = " *" if rec["conflicts"] else ""
            print(f"      {f} = {v}")
        for c in rec["conflicts"]:
            print(f"      ! {c['field']}: {c['candidates']} -> {c['winner_source']}")
        print()

    print("--- INJECTION ATTACKS REJECTED ----------------------------")
    rej = [e for e in agent.log.dump() if e["event"] == "reject"]
    for e in rej:
        print(f"  source={e['source']} row={e['row']} layer={e['layer']}")
        for r in e["reasons"]:
            print(f"      reason: {r}")
        print(f"      snippet: {e['snippet']!r}")
        print()
    print("=" * 72)
    print(f"Audit log: logs/audit.jsonl ({len(agent.log.dump())} events)")


if __name__ == "__main__":
    main()
