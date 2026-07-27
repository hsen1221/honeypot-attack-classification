#!/usr/bin/env python3
import csv, requests
LEDGER = "/mnt/c/tpot-project/01-run-ledger/run-ledger.csv"
ES, SRC = "http://localhost:64298", "192.168.32.1"

rows = [r for r in csv.DictReader(open(LEDGER, newline="")) if r["run_id"].startswith("W")]
if not rows:
    print("No W### rows yet — run the web campaign first."); raise SystemExit
start = min(r["start_time_utc"] for r in rows)
end   = max(r["end_time_utc"]   for r in rows)
win   = {"range": {"@timestamp": {"gte": start, "lte": end}}}
base  = {"term": {"src_ip": SRC}}

def count(extra):
    q={"query":{"bool":{"filter":[base,win]+extra}}}
    return requests.post(f"{ES}/logstash-*/_count",json=q,timeout=30).json().get("count")

print(f"window {start} -> {end}")
print("Tanner events :", count([{"term":{"type.keyword":"Tanner"}}]))
print("Snare events  :", count([{"term":{"type.keyword":"Snare"}}]))
print("Wordpot events:", count([{"term":{"type.keyword":"Wordpot"}}]))
print("port 80 events:", count([{"term":{"dest_port":80}}]))
print("port 8080 evts:", count([{"term":{"dest_port":8080}}]))

agg={"size":0,"query":{"bool":{"filter":[base,win,{"term":{"type.keyword":"Tanner"}}]}},
     "aggs":{"atk":{"terms":{"field":"response_msg.response.message.detection.name.keyword","size":15}}}}
r=requests.post(f"{ES}/logstash-*/_search",json=agg,timeout=30).json()
print("\nTanner attack-type classifications:")
if "aggregations" in r:
    for b in r["aggregations"]["atk"]["buckets"]:
        print(f'  {b["doc_count"]:>4}  {b["key"]}')
else:
    print("  agg error (field name?):", r.get("error", r))
