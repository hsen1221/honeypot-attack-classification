#!/usr/bin/env python3
import csv, os, shlex, subprocess, time
from datetime import datetime, timezone

LEDGER   = "/mnt/c/tpot-project/01-run-ledger/run-ledger.csv"
LOG_DIR  = "/mnt/c/tpot-project/02-raw-data/attack-logs"
TARGET   = "192.168.32.138"
SRC_SEEN = "192.168.32.1"
LABEL    = "scan"
PREFIX   = "S"
COOLDOWN = 25
MAX_RUNS = None

COLUMNS = ["run_id","attack_type_label","tool","exact_command","target_ip",
           "target_port","start_time_utc","end_time_utc","expected_honeypot",
           "src_ip_seen","notes"]

def utc_now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

def rows_done():
    if not os.path.exists(LEDGER): return 0
    n = 0
    with open(LEDGER, newline="") as f:
        for r in csv.DictReader(f):
            if r["run_id"].startswith(PREFIX) and r["run_id"][1:].isdigit():
                n += 1
    return n

def build_commands():
    cmds = []
    techniques = [("-sS","SYN"), ("-sT","connect"), ("-sV --version-intensity 0","version")]
    scopes = [("-p 21,22,23,80,443","5-common"), ("--top-ports 50","top-50"),
              ("--top-ports 100","top-100"), ("--top-ports 200","top-200"),
              ("--top-ports 500","top-500"), ("-p 1-1000","1-1000"),
              ("--top-ports 1000","top-1000")]
    timings = ["-T4","-T3","-T5"]
    i = 0
    for tech, tname in techniques:
        for sargs, sname in scopes:
            timing = timings[i % len(timings)]; i += 1
            cmds.append((f"-Pn {tech} {sargs} {timing} {TARGET}", sname,
                         "p0f/honeytrap/suricata", f"{tname} scan, {sname}, {timing}"))
    heavy = [
        (f"-Pn -sS -p- -T4 {TARGET}",                     "all-ports", "p0f/honeytrap/suricata", "SYN full port (HEAVY, minutes)"),
        (f"-Pn -sU --top-ports 30 -T4 {TARGET}",          "udp-top-30","dionaea/honeytrap",       "UDP scan (slow)"),
        (f"-Pn -A --top-ports 50 -T4 {TARGET}",           "top-50",    "p0f/honeytrap/suricata/cowrie", "aggressive scan"),
        (f"-Pn -A --top-ports 100 -T4 {TARGET}",          "top-100",   "p0f/honeytrap/suricata/cowrie", "aggressive scan wider"),
        (f"-Pn -sS -O --top-ports 100 -T4 {TARGET}",      "top-100",   "p0f/honeytrap/suricata", "SYN + OS detect"),
        (f"-Pn -sS -O --top-ports 500 -T4 {TARGET}",      "top-500",   "p0f/honeytrap/suricata", "SYN + OS detect wide"),
        (f"-Pn -sV --version-intensity 5 --top-ports 100 -T4 {TARGET}", "top-100", "p0f/honeytrap/suricata", "version intensity 5"),
        (f"-Pn -sS -f --top-ports 100 -T4 {TARGET}",      "top-100",   "p0f/honeytrap/suricata", "fragmented SYN (evasion)"),
        (f"-Pn -sS --scan-delay 150ms --top-ports 100 -T3 {TARGET}", "top-100", "p0f/honeytrap/suricata", "slow/stealth SYN"),
    ]
    return cmds + heavy

def main():
    os.makedirs(os.path.dirname(LEDGER), exist_ok=True)
    os.makedirs(LOG_DIR, exist_ok=True)
    new_file = not os.path.exists(LEDGER)
    cmds = build_commands()
    done = rows_done()
    todo = cmds[done:]
    if MAX_RUNS is not None:
        todo = todo[:MAX_RUNS]
    if not todo:
        print("Nothing to run — ledger already has all scan runs."); return

    with open(LEDGER, "a", newline="") as f:
        w = csv.DictWriter(f, fieldnames=COLUMNS)
        if new_file: w.writeheader()
        idx = done + 1
        first_start = last_end = None
        for args, scope, hp, note in todo:
            rid = f"{PREFIX}{idx:03d}"; idx += 1
            cmd = "nmap " + args
            print(f"[{rid}] {note}\n       {cmd}")
            start = utc_now(); first_start = first_start or start
            try:
                res = subprocess.run(shlex.split(cmd), capture_output=True,
                                     text=True, timeout=900)
                out = res.stdout
            except subprocess.TimeoutExpired:
                out = "TIMEOUT after 900s"; note += " (TIMEOUT)"
            end = utc_now(); last_end = end
            with open(f"{LOG_DIR}/{rid}.txt", "w") as lf: lf.write(out)
            w.writerow({"run_id":rid,"attack_type_label":LABEL,"tool":"nmap",
                        "exact_command":cmd,"target_ip":TARGET,"target_port":scope,
                        "start_time_utc":start,"end_time_utc":end,
                        "expected_honeypot":hp,"src_ip_seen":SRC_SEEN,"notes":note})
            f.flush()
            print(f"       {start} -> {end}   (cooldown {COOLDOWN}s)\n")
            time.sleep(COOLDOWN)
    print(f"Batch done. This batch window (UTC): {first_start} -> {last_end}")

if __name__ == "__main__":
    main()
