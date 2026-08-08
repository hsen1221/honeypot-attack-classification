#!/usr/bin/env python3
"""
Feature extractor for the T-Pot honeypot attack-classification dataset.

Reads exported per-run event JSON files (one file per run, named <run_id>.json),
computes behavioral features from the Elasticsearch telemetry ONLY (never from the
ledger's tool/expected_honeypot/notes columns), and writes TWO datasets:

  dataset_full.csv        - all behavioral features + per-honeypot event counts
  dataset_behavioral.csv  - behavioral features only (NO per-honeypot counts)

The ledger contributes exactly two things: the run_id->label mapping, and nothing else.
NGINX events (the user's own Kibana browsing) are excluded as contamination.
"""
import csv, json, os, glob, statistics
from collections import Counter
from datetime import datetime

# ---- paths (edit LEDGER/EVENTS/OUT if your layout differs) ----
LEDGER = "/mnt/c/tpot-project/01-run-ledger/run-ledger.csv"
EVENTS = "/mnt/c/tpot-project/02-raw-data/es-events"
OUT_FULL = "/mnt/c/tpot-project/04-features/dataset_full.csv"
OUT_BEHAV= "/mnt/c/tpot-project/04-features/dataset_behavioral.csv"

# honeypot types we count (NGINX excluded on purpose)
HP_TYPES = ["P0f","Suricata","Cowrie","Dionaea","Honeytrap","Heralding","Tanner","Fatt","Wordpot"]
EXCLUDE_TYPES = {"NGINX"}

def ts(d):
    """parse @timestamp (ms precision) to epoch seconds float; None if unparseable."""
    t = d.get("@timestamp")
    if not t: return None
    try:
        return datetime.strptime(t[:19], "%Y-%m-%dT%H:%M:%S").timestamp()
    except Exception:
        return None

def safe_div(a, b):
    return a / b if b else 0.0

def extract(run_id, label, docs):
    # drop contamination
    docs = [d for d in docs if d.get("type") not in EXCLUDE_TYPES]
    n = len(docs)
    f = {"run_id": run_id, "label": label}

    # ---------- volume ----------
    f["total_events"] = n

    # ---------- timing / rhythm ----------
    times = sorted([t for t in (ts(d) for d in docs) if t is not None])
    if len(times) >= 2:
        dur = times[-1] - times[0]
        gaps = [times[i+1]-times[i] for i in range(len(times)-1)]
        f["duration_sec"] = round(dur, 3)
        f["events_per_sec"] = round(safe_div(n, dur if dur>0 else 1), 4)
        f["inter_event_mean"] = round(statistics.mean(gaps), 4)
        f["inter_event_std"]  = round(statistics.pstdev(gaps), 4) if len(gaps)>1 else 0.0
        # burstiness: max events in any 1-second bucket / mean per active second
        sec_buckets = Counter(int(t) for t in times)
        max_burst = max(sec_buckets.values())
        f["burst_max_per_sec"] = max_burst
        f["burstiness"] = round(safe_div(max_burst, statistics.mean(sec_buckets.values())), 3)
    else:
        f["duration_sec"]=0.0; f["events_per_sec"]=0.0
        f["inter_event_mean"]=0.0; f["inter_event_std"]=0.0
        f["burst_max_per_sec"]=n; f["burstiness"]=0.0

    # ---------- port behavior ----------
    dports = [d.get("dest_port") for d in docs if d.get("dest_port") is not None]
    sports = [d.get("src_port") for d in docs if d.get("src_port") is not None]
    distinct_dports = len(set(dports))
    f["distinct_dest_ports"] = distinct_dports
    f["distinct_src_ports"]  = len(set(sports))
    f["ports_per_event"] = round(safe_div(distinct_dports, n), 5)   # ~1 scan, ~0 single-port
    if dports:
        top_port, top_ct = Counter(dports).most_common(1)[0]
        f["frac_on_top_port"] = round(safe_div(top_ct, len(dports)), 4)  # focused vs spread
    else:
        f["frac_on_top_port"] = 0.0

    # ---------- protocol / service spread ----------
    protos = set()
    for d in docs:
        for k in ("proto","protocol","app_proto"):
            v = d.get(k)
            if isinstance(v,str) and v: protos.add(v.lower())
    f["distinct_protocols"] = len(protos)

    # ---------- Cowrie behavioral (auth + commands) ----------
    eids = Counter(d.get("eventid") for d in docs if d.get("type")=="Cowrie" and d.get("eventid"))
    f["n_login_fail"]     = eids.get("cowrie.login.failed",0)
    f["n_login_success"]  = eids.get("cowrie.login.success",0)
    f["n_commands"]       = eids.get("cowrie.command.input",0)
    f["n_command_failed"] = eids.get("cowrie.command.failed",0)
    f["n_sessions"]       = eids.get("cowrie.session.connect",0)
    f["n_file_downloads"] = eids.get("cowrie.session.file_download",0)
    # distinct commands actually typed
    cmds = set(d.get("input") for d in docs
               if d.get("type")=="Cowrie" and d.get("eventid")=="cowrie.command.input" and d.get("input"))
    f["distinct_commands"] = len(cmds)
    
# ---------- other-honeypot auth attempts (Dionaea FTP, Heralding VNC) ----------
    # A real online-guessing ATTEMPT means a password was actually submitted.
    # Counts non-empty passwords from Dionaea (FTP) and Heralding (VNC), which DO
    # record the guessed password. Excludes Dionaea-MySQL handshakes (password == "")
    # and connection-only records (password == None) -- those reached the service but
    # submitted no password. These honeypots log no success/failure outcome, so this
    # feeds the ATTEMPT features only (n_auth_other, any_login_attempt).
    def _nonempty(v):
        return isinstance(v, str) and v.strip() != ""
    auth_other = 0
    for d in docs:
        if d.get("type") in ("Dionaea", "Heralding") and _nonempty(d.get("password")):
            auth_other += 1
    f["n_auth_other"] = auth_other


    # ---------- web behavior ----------
    web_docs = [d for d in docs if d.get("type") in ("Tanner","Wordpot")]
    f["n_http_events"] = len(web_docs)
    f["n_web_80"]   = sum(1 for d in docs if d.get("dest_port")==80)
    f["n_web_8080"] = sum(1 for d in docs if d.get("dest_port")==8080)
    # distinct URL paths touched (web recon breadth) - Tanner 'path', Wordpot 'url'
    paths = set()
    for d in web_docs:
        p = d.get("path") or d.get("url")
        if p: paths.add(p)
    f["distinct_web_paths"] = len(paths)

    # ---------- Suricata alerts by severity ----------
    sev = Counter(); sigs=set(); n_alert=0; n_flow=0
    for d in docs:
        if d.get("type")!="Suricata": continue
        et = d.get("event_type")
        if et=="flow": n_flow+=1
        a = d.get("alert")
        if isinstance(a,dict):
            n_alert+=1
            s = a.get("severity")
            if s is not None: sev[s]+=1
            sig = a.get("signature")
            if sig: sigs.add(sig)
    f["n_suricata_alerts"] = n_alert
    f["n_suricata_flows"]  = n_flow
    # Suricata severity: 1=high,2=med,3=low/info (higher number = less severe in ET rules)
    f["n_alert_sev_high"] = sev.get(1,0)+sev.get(2,0)   # meaningful alerts
    f["n_alert_sev_info"] = sev.get(3,0)                # informational noise
    f["distinct_signatures"] = len(sigs)

    # ---------- clean booleans (great for feature importance) ----------
    f["any_login_attempt"] = int(f["n_login_fail"]+f["n_login_success"]+f["n_auth_other"] > 0)
    f["any_login_success"] = int(f["n_login_success"] > 0)
    f["any_command_run"]   = int(f["n_commands"] > 0)
    f["any_file_download"] = int(f["n_file_downloads"] > 0)
    f["any_web_request"]   = int(f["n_http_events"] > 0)

    # ---------- per-honeypot counts (Set A ONLY) ----------
    tcount = Counter(d.get("type") for d in docs)
    hp = {f"n_{t.lower()}": tcount.get(t,0) for t in HP_TYPES}

    return f, hp

def main():
    # label map from ledger (labels + windows only; nothing else used)
    labels = {r["run_id"]: r["attack_type_label"]
              for r in csv.DictReader(open(LEDGER,newline=""))
              if r["run_id"][0] in "SBPWD" and r["run_id"][1:].isdigit()}

    rows_full=[]; rows_behav=[]
    for rid in sorted(labels):
        path = f"{EVENTS}/{rid}.json"
        if not os.path.exists(path):
            print(f"  WARN missing {rid}.json — skipped"); continue
        docs = json.load(open(path))
        base, hp = extract(rid, labels[rid], docs)
        rows_behav.append(dict(base))
        full = dict(base); full.update(hp)
        rows_full.append(full)

    # column order: behavioral features (shared), then honeypot counts for full
    behav_cols = list(rows_behav[0].keys())
    hp_cols = [f"n_{t.lower()}" for t in HP_TYPES]
    full_cols = behav_cols + hp_cols

    os.makedirs(os.path.dirname(OUT_FULL), exist_ok=True)
    with open(OUT_BEHAV,"w",newline="") as fh:
        w=csv.DictWriter(fh, fieldnames=behav_cols); w.writeheader(); w.writerows(rows_behav)
    with open(OUT_FULL,"w",newline="") as fh:
        w=csv.DictWriter(fh, fieldnames=full_cols); w.writeheader(); w.writerows(rows_full)

    print(f"WROTE {OUT_BEHAV}  ({len(rows_behav)} rows, {len(behav_cols)-2} features)")
    print(f"WROTE {OUT_FULL}   ({len(rows_full)} rows, {len(full_cols)-2} features)")
    # class balance
    c=Counter(r["label"] for r in rows_full); print("class balance:", dict(c))

if __name__ == "__main__":
    main()
