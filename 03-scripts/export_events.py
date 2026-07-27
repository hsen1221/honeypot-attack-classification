#!/usr/bin/env python3
import csv, json, os, time, requests
from datetime import datetime, timedelta, timezone

LEDGER  = "/mnt/c/tpot-project/01-run-ledger/run-ledger.csv"
OUTDIR  = "/mnt/c/tpot-project/02-raw-data/es-events"
MANIFEST= "/mnt/c/tpot-project/02-raw-data/export-manifest.csv"
ES  = "http://localhost:64298"
SRC = "192.168.32.1"
PAD = 3
MGMT_PORTS = [64294,64295,64296,64297,64298,64305]
PAGE = 2000

def T(s): return datetime.strptime(s,"%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
def shift(s,sec): return (T(s)+timedelta(seconds=sec)).strftime("%Y-%m-%dT%H:%M:%SZ")

def fetch_all(start, end):
    """Use the Scroll API to pull every matching event, excluding mgmt ports."""
    q = {"size": PAGE,
         "query": {"bool": {
             "filter": [
                 {"term": {"src_ip": SRC}},
                 {"range": {"@timestamp": {"gte": start, "lte": end}}}],
             "must_not": [{"terms": {"dest_port": MGMT_PORTS}}]}}}
    docs = []
    # open scroll
    for attempt in range(4):
        try:
            r = requests.post(f"{ES}/logstash-*/_search?scroll=2m", json=q, timeout=90).json()
            break
        except Exception:
            if attempt==3: raise
            time.sleep(3)
    sid = r.get("_scroll_id")
    hits = r.get("hits",{}).get("hits",[])
    while hits:
        for h in hits: docs.append(h["_source"])
        for attempt in range(4):
            try:
                r = requests.post(f"{ES}/_search/scroll",
                                  json={"scroll":"2m","scroll_id":sid}, timeout=90).json()
                break
            except Exception:
                if attempt==3: raise
                time.sleep(3)
        sid = r.get("_scroll_id")
        hits = r.get("hits",{}).get("hits",[])
    # free the scroll context
    try: requests.delete(f"{ES}/_search/scroll", json={"scroll_id":[sid]}, timeout=30)
    except Exception: pass
    return docs

def main():
    os.makedirs(OUTDIR, exist_ok=True)
    rows = [r for r in csv.DictReader(open(LEDGER,newline=""))
            if r["run_id"][0] in "SBPWD" and r["run_id"][1:].isdigit()]
    print(f"{len(rows)} runs to export (TEST001 excluded)\n")

    man = open(MANIFEST,"w",newline="")
    mw = csv.writer(man); mw.writerow(["run_id","label","events_exported","start_utc","end_utc"])
    total=0
    for r in rows:
        rid=r["run_id"]; out=f"{OUTDIR}/{rid}.json"
        if os.path.exists(out):
            n=len(json.load(open(out)))
            if n>0:
                print(f"  {rid}  (already exported, {n} events) — skip")
                mw.writerow([rid,r["attack_type_label"],n,r["start_time_utc"],r["end_time_utc"]]); total+=n
                continue
        docs = fetch_all(shift(r["start_time_utc"],-PAD), shift(r["end_time_utc"],PAD))
        json.dump(docs, open(out,"w"))
        mw.writerow([rid,r["attack_type_label"],len(docs),r["start_time_utc"],r["end_time_utc"]])
        man.flush(); total+=len(docs)
        print(f"  {rid}  {r['attack_type_label']:<18} {len(docs)} events -> {rid}.json")
    man.close()
    print(f"\nDONE. {len(rows)} runs, {total} total events exported to {OUTDIR}")

if __name__ == "__main__":
    main()
