#!/usr/bin/env python3
# verify_DOS.py — confirm each DoS run landed in ES under the src_ip filter,
# and show the DoS signature (sensor mix, Suricata flow vs alert, dest_port
# concentration, flood signatures). Mirrors verify_webattack.py / verify_postexploit.py.
# Needs the ES tunnel up (http://localhost:64298).
import csv, requests
LEDGER = "/mnt/c/tpot-project/01-run-ledger/run-ledger.csv"
ES, SRC = "http://localhost:64298", "192.168.32.1"

rows = [r for r in csv.DictReader(open(LEDGER, newline=""))
        if r["run_id"].startswith("D") and r["run_id"][1:].isdigit()]
if not rows:
    print("No D### rows yet — run run_dos.py first."); raise SystemExit
rows.sort(key=lambda r: int(r["run_id"][1:]))

def _post(path, body):
    return requests.post(f"{ES}/logstash-*/{path}", json=body, timeout=60).json()
def count(filters):
    return _post("_count", {"query": {"bool": {"filter": filters}}}).get("count")
def base(start, end):
    return [{"term": {"src_ip": SRC}},
            {"range": {"@timestamp": {"gte": start, "lte": end}}}]

def buckets(agg, key):
    b = agg.get(key, {}).get("buckets", [])
    return ", ".join(f'{x["key"]}:{x["doc_count"]}' for x in b)

print("=== per-run capture (src_ip=%s) ===" % SRC)
zero = []
for r in rows:
    rid, start, end, port = r["run_id"], r["start_time_utc"], r["end_time_utc"], r["target_port"]
    f = base(start, end)
    total = count(f)
    if not total: zero.append(rid)
    agg = _post("_search", {"size": 0, "query": {"bool": {"filter": f}}, "aggs": {
        "by_type": {"terms": {"field": "type.keyword", "size": 10}},
        "by_port": {"terms": {"field": "dest_port", "size": 6}},
        "by_evt":  {"terms": {"field": "event_type.keyword", "size": 6}},
        "src_ports": {"cardinality": {"field": "src_port"}},
    }}).get("aggregations", {})
    note = r["notes"].split(" | ")[0]
    print(f"\n[{rid}] {note}   (target {port})   TOTAL={total}")
    print(f"     sensors : {buckets(agg,'by_type')}")
    print(f"     ports   : {buckets(agg,'by_port')}")
    ev = buckets(agg, "by_evt")
    if ev: print(f"     suricata: {ev}")
    sp = agg.get("src_ports", {}).get("value")
    if sp is not None: print(f"     distinct src_ports: {sp}")

# flood signatures across the whole D window
start = min(r["start_time_utc"] for r in rows)
end   = max(r["end_time_utc"]   for r in rows)
agg = _post("_search", {"size": 0, "query": {"bool": {"filter":
        base(start, end) + [{"term": {"type.keyword": "Suricata"}},
                            {"term": {"event_type.keyword": "alert"}}]}},
        "aggs": {"sig": {"terms": {"field": "alert.signature.keyword", "size": 25}}}})
print("\n=== Suricata alert signatures fired (all D runs) ===")
if "aggregations" in agg:
    b = agg["aggregations"]["sig"]["buckets"]
    if b:
        for x in b: print(f'  {x["doc_count"]:>7}  {x["key"]}')
    else:
        print("  (no alert docs in window — floods may be logged as flow-only)")
else:
    print("  agg error (field name?):", agg.get("error", agg))

print("\n=== summary ===")
print(f"  runs checked : {len(rows)}")
print(f"  runs with ZERO events (NOT captured): {zero if zero else 'none — all captured'}")
