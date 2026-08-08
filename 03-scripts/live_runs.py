#!/usr/bin/env python3
"""
LIVE run-based attack classifier — idle-bounded segmentation (self-contained).

Treats each burst of activity bounded by idle periods (idle -> activity -> idle) as
ONE complete attack run, then classifies that whole run with the deployed XGBoost
model. Matches how the model was trained (on complete runs) and cleanly separates
sequential attacks from a single attacker without any fixed sliding window.

Each classified run is ALSO written as one document to the Elasticsearch index
'ml-predictions' (for the Kibana dashboard). The write can never crash the classifier
— on any failure it just prints a warning and the classification still stands.

Reuses the project feature extractor (extract_features.py) so live features match
training exactly. Everything else (ES query, model loading, prediction, dashboard
write) lives in this one file.

USAGE (on Kali, tunnel open):
    python3 live_runs.py                 # default 30s idle gap: scan/guessing/post-exploit/web
    python3 live_runs.py --idle 120      # DoS: its Suricata FLOW events log ~60-90s late

Stop with Ctrl+C.

WHY the idle gap differs (measured on this setup): scan ~3s / web ~10s internal gaps ->
30s is safe. online-guessing / post-exploit ~60s and DoS ~87s gaps are LATE LOGGING, not the
attack; 30s classifies the core burst (what the non-DoS training windows captured), while
DoS needs 120s because its training deliberately included the late flow events.

LIMITATION (documented): one run = everything between two idle periods. Run attacks
SEQUENTIALLY, spaced further apart than the idle gap. Concurrent attacks from different
sources would merge into one run; per-source session segmentation is future work.

Requires: requests, xgboost, scikit-learn, joblib, and extract_features.py in the same
dir (03-scripts/), plus deployed_model.pkl + feature_columns.json + class_labels.json in
06-models/.
"""
import argparse, json, os, sys, time, requests
from datetime import datetime, timedelta, timezone

# the ONLY project import: the exact feature extractor used in training (feature parity)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import extract_features as ef
import xgboost, joblib   # xgboost needed so joblib can unpickle the model

# ---------------------------------------------------------------- config
ES          = "http://localhost:64298"          # via SSH tunnel
SRC         = "192.168.32.1"
MGMT_PORTS  = [64294, 64295, 64296, 64297, 64298, 64305]
MODEL_DIR   = "/mnt/c/tpot-project/06-models"
MODEL_PATH  = os.path.join(MODEL_DIR, "deployed_model.pkl")
COLS_PATH   = os.path.join(MODEL_DIR, "feature_columns.json")
LABELS_PATH = os.path.join(MODEL_DIR, "class_labels.json")
PRED_INDEX  = "ml-predictions"   # where classified runs are written for Kibana
PAD         = 3   # +/- seconds around a run when pulling its events (matches training pad)

# ---------------------------------------------------------------- ES + model helpers
def now_utc(): return datetime.now(timezone.utc)
def iso(dt):   return dt.strftime("%Y-%m-%dT%H:%M:%SZ")

def fetch_events(start, end):
    """Scroll every matching event in [start,end], excluding NGINX + mgmt ports
       (same filtering as the training-data export)."""
    q = {"size": 2000,
         "query": {"bool": {
             "filter": [
                 {"term": {"src_ip": SRC}},
                 {"range": {"@timestamp": {"gte": start, "lte": end}}}],
             "must_not": [{"terms": {"dest_port": MGMT_PORTS}}]}}}
    docs = []
    try:
        r = requests.post(f"{ES}/logstash-*/_search?scroll=2m", json=q, timeout=60).json()
    except Exception as e:
        print(f"\nERROR: cannot reach Elasticsearch at {ES} — is the tunnel open?\n  {e}")
        sys.exit(1)
    sid = r.get("_scroll_id"); hits = r.get("hits", {}).get("hits", [])
    while hits:
        docs += [h["_source"] for h in hits]
        r = requests.post(f"{ES}/_search/scroll",
                          json={"scroll": "2m", "scroll_id": sid}, timeout=60).json()
        sid = r.get("_scroll_id"); hits = r.get("hits", {}).get("hits", [])
    try: requests.delete(f"{ES}/_search/scroll", json={"scroll_id": [sid]}, timeout=15)
    except Exception: pass
    return docs

def load_model():
    """Load the deployed XGBoost model (joblib pickle) + class-name map + column order."""
    model = joblib.load(MODEL_PATH)               # versions match Anaconda -> pickle is safe
    class_labels = json.load(open(LABELS_PATH))   # index = integer id -> class name
    cols = json.load(open(COLS_PATH))             # 32 feature names, exact order
    return model, class_labels, cols

def ensure_index():
    """Create the predictions index with an explicit, Kibana-friendly mapping (idempotent)."""
    try:
        if requests.head(f"{ES}/{PRED_INDEX}", timeout=15).status_code == 200:
            return  # already exists — leave it
        mapping = {"mappings": {"properties": {
            "@timestamp":      {"type": "date"},
            "predicted_class": {"type": "keyword"},
            "confidence":      {"type": "float"},
            "event_count":     {"type": "integer"},
            "duration_sec":    {"type": "float"},
            "run_start":       {"type": "date"},
            "run_end":         {"type": "date"},
            "probs": {"properties": {c: {"type": "float"} for c in
                      ["scan","online_guessing","post_exploitation","web_attack","denial_of_service"]}},
        }}}
        r = requests.put(f"{ES}/{PRED_INDEX}", json=mapping, timeout=30)
        print(f"created index '{PRED_INDEX}' (HTTP {r.status_code})")
    except Exception as e:
        print(f"(could not create dashboard index: {e} — classification will still work)")

def write_prediction(pred, ranked, feats, run_start, run_end):
    """POST one classified run to the predictions index. NEVER crashes the classifier."""
    try:
        doc = {
            "@timestamp":      iso(run_end),                    # when the run finished
            "predicted_class": pred,
            "confidence":      round(float(dict(ranked)[pred]), 4),
            "event_count":     int(feats.get("total_events", 0)),
            "duration_sec":    round((run_end - run_start).total_seconds(), 1),
            "run_start":       iso(run_start),
            "run_end":         iso(run_end),
            "probs":           {c: round(float(p), 4) for c, p in ranked},
        }
        r = requests.post(f"{ES}/{PRED_INDEX}/_doc", json=doc, timeout=15)
        if r.status_code in (200, 201):
            print(f"  \u2713 written to dashboard index '{PRED_INDEX}'")
        else:
            print(f"  (dashboard write failed: HTTP {r.status_code} — classification still valid)")
    except Exception as e:
        print(f"  (dashboard write skipped: {e} — classification still valid)")

def classify_docs(docs, model, class_labels, cols):
    """Extract features from docs and return (pred_name, ranked_probs, feats)."""
    feats, _hp = ef.extract("LIVE", "unknown", docs)          # SAME code as training
    x = [[float(feats.get(c, 0)) for c in cols]]              # exact column order
    pred_int = int(model.predict(x)[0])                        # XGBoost returns an INTEGER
    proba    = model.predict_proba(x)[0]                       # columns 0..N = class_labels order
    ranked   = sorted(zip(class_labels, proba), key=lambda t: -t[1])
    return class_labels[pred_int], ranked, feats

# ---------------------------------------------------------------- run detection
def parse_ts(s): return datetime.fromisoformat(s.replace("Z", "+00:00"))

def event_times(docs):
    return sorted(parse_ts(d["@timestamp"]) for d in docs
                  if d.get("type") not in ef.EXCLUDE_TYPES and d.get("@timestamp"))

def announce(pred, ranked, feats, run_start, run_end):
    dur, conf = (run_end - run_start).total_seconds(), dict(ranked)[pred]*100
    print(f"\n  {'='*54}")
    print(f"  ATTACK RUN CLASSIFIED  ({run_start.strftime('%H:%M:%S')} -> "
          f"{run_end.strftime('%H:%M:%S')}, {dur:.0f}s)")
    print(f"  {'='*54}")
    print(f"  >>> {pred.upper()}   (confidence {conf:.1f}%)\n")
    for c, p in ranked:
        print(f"    {c:18} {p*100:5.1f}%  {'#'*int(round(p*28))}")
    print("\n  key behavior:")
    for k in ["total_events", "distinct_dest_ports", "n_login_fail", "n_login_success",
              "n_commands", "n_http_events", "n_web_80", "n_web_8080"]:
        print(f"    {k:20} = {feats.get(k)}")
    print()

def classify_run(model, class_labels, cols, run_start, last_activity, min_events):
    """Pull the WHOLE run (start->last event, padded) and classify it as one attack."""
    run_docs = fetch_events(iso(run_start - timedelta(seconds=PAD)),
                            iso(last_activity + timedelta(seconds=PAD)))
    kept = [d for d in run_docs if d.get("type") not in ef.EXCLUDE_TYPES]
    if len(kept) < min_events:
        print(f"  (run had only {len(kept)} events — below {min_events}, skipped)")
        return
    pred, ranked, feats = classify_docs(run_docs, model, class_labels, cols)
    announce(pred, ranked, feats, run_start, last_activity)
    write_prediction(pred, ranked, feats, run_start, last_activity)

def run(poll, idle, min_events, max_run):
    print("loading deployed model...")
    model, class_labels, cols = load_model()
    ensure_index()
    print(f"model loaded  |  poll={poll:g}s  idle-gap={idle:g}s  "
          f"min-events={min_events}  max-run={max_run:g}s\n")
    print("watching the honeypot — run attacks one at a time, spaced > idle-gap apart.")
    print("Ctrl+C to stop.\n")

    in_run, run_start, last_activity = False, None, None
    try:
        while True:
            now = now_utc()
            lookback = now - timedelta(seconds=idle + poll + 5)     # always > idle-gap
            times = event_times(fetch_events(iso(lookback), iso(now + timedelta(seconds=2))))
            active = bool(times) and (now - times[-1]).total_seconds() < idle

            if active and not in_run:                              # idle -> run starts
                in_run, run_start, last_activity = True, times[0], times[-1]
                print(f"\n\u25b6 attack detected {run_start.strftime('%H:%M:%S')} — collecting...")
            elif active and in_run:                                # run continues
                last_activity = times[-1]
                elapsed = (now - run_start).total_seconds()
                since_last = (now - last_activity).total_seconds()  # seconds since newest event
                print(f"\r   collecting: {len(times)} events | run {elapsed:4.0f}s | "
                      f"idle {since_last:4.0f}s / {idle:.0f}s   ", end="", flush=True)
                if elapsed >= max_run:                             # safety: never-idle run
                    print(); classify_run(model, class_labels, cols, run_start, last_activity, 0)
                    in_run = False
            elif in_run and not active:                            # run -> idle: classify it
                print()
                classify_run(model, class_labels, cols, run_start, last_activity, min_events)
                in_run = False
            else:                                                  # idle, waiting
                if times:
                    quiet = (now - times[-1]).total_seconds()
                    print(f"\r\u00b7 idle {quiet:5.0f}s since last event — waiting for an attack...   ",
                          end="", flush=True)
                else:
                    print("\r\u00b7 idle — waiting for an attack...   ", end="", flush=True)

            time.sleep(poll)
    except KeyboardInterrupt:
        print("\n\nstopped.")

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--poll",       type=float, default=4.0,   help="seconds between checks")
    ap.add_argument("--idle",       type=float, default=30.0,  help="idle gap marking a run's end (use 120 for DoS)")
    ap.add_argument("--min-events", type=int,   default=10,    help="skip runs smaller than this")
    ap.add_argument("--max-run",    type=float, default=900.0, help="force-classify a run longer than this")
    args = ap.parse_args()
    run(args.poll, args.idle, args.min_events, args.max_run)

if __name__ == "__main__":
    main()