#!/usr/bin/env python3
import csv, requests
from datetime import datetime, timedelta, timezone

LEDGER = "/mnt/c/tpot-project/01-run-ledger/run-ledger.csv"
ES  = "http://localhost:64298"      # via the SSH tunnel
SRC = "192.168.32.1"
PAD = 3

def shift(ts, secs):
    dt = datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    return (dt + timedelta(seconds=secs)).strftime("%Y-%m-%dT%H:%M:%SZ")

def count(start, end):
    q = {"query":{"bool":{"filter":[
        {"term":{"src_ip":SRC}},
        {"range":{"@timestamp":{"gte":start,"lte":end}}}]}}}
    try:
        return requests.post(f"{ES}/logstash-*/_count", json=q, timeout=30).json().get("count","ERR")
    except Exception:
        return "ERR(tunnel?)"

with open(LEDGER, newline="") as f:
    rows = list(csv.DictReader(f))

zero = 0
for r in rows:
    c = count(shift(r["start_time_utc"], -PAD), shift(r["end_time_utc"], PAD))
    flag = "   <-- ZERO EVENTS, investigate" if c == 0 else ""
    if c == 0: zero += 1
    print(f'{r["run_id"]}  {r["attack_type_label"]:<16} events={c}{flag}')
print(f"\nChecked {len(rows)} runs, {zero} with zero events.")
