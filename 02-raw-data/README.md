
# 02-raw-data

Raw Elasticsearch event exports (`es-events/`) and per-run tool logs (`attack-logs/`)
are **not committed** — they are large (~Millions of events). Regenerate them from the run ledger with:

    python3 03-scripts/export_events.py

Feature datasets derived (obtained) from these events are in `04-features/`.
