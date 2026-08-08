#!/usr/bin/env python3
import csv, requests
LEDGER = "/mnt/c/tpot-project/01-run-ledger/run-ledger.csv"
ES, SRC = "http://localhost:64298", "192.168.32.1"

rows = [r for r in csv.DictReader(open(LEDGER, newline="")) if r["run_id"].startswith("B")]
if not rows:
    print("No B### rows yet — run the online-guessing campaign first."); raise SystemExit
start = min(r["start_time_utc"] for r in rows)
end   = max(r["end_time_utc"]   for r in rows)
win   = {"range": {"@timestamp": {"gte": start, "lte": end}}}

def count(eventid):
    q = {"query": {"bool": {"filter": [{"term": {"src_ip": SRC}},
         {"term": {"eventid.keyword": eventid}}, win]}}}
    return requests.post(f"{ES}/logstash-*/_count", json=q, timeout=30).json().get("count")

print(f"window {start} -> {end}")
print("cowrie.login.failed :", count("cowrie.login.failed"))
print("cowrie.login.success:", count("cowrie.login.success"))

agg = {"size":0, "query":{"bool":{"filter":[{"term":{"src_ip":SRC}}, win]}},
       "aggs":{"u":{"terms":{"field":"username.keyword","size":10}},
               "p":{"terms":{"field":"password.keyword","size":10}}}}
r = requests.post(f"{ES}/logstash-*/_search", json=agg, timeout=30).json()
if "aggregations" in r:
    print("\ntop usernames:", [(b["key"], b["doc_count"]) for b in r["aggregations"]["u"]["buckets"]])
    print("top passwords:", [(b["key"], b["doc_count"]) for b in r["aggregations"]["p"]["buckets"]])
else:
    print("\nagg error:", r.get("error", r))
