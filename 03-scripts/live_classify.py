#!/usr/bin/env python3
"""
LIVE attack classifier for the T-Pot honeypot project.

Pulls recent events from Elasticsearch (via the SSH tunnel), runs them through the
SAME feature extractor used for training (imported from extract_features.py, no
duplicated logic), loads the tuned Random Forest, and prints the predicted attack
class with per-class confidence.

USAGE (on Kali, with the tunnel open):
    python3 live_classify.py                 # classify the last 120 seconds
    python3 live_classify.py --minutes 3     # classify the last 3 minutes
    python3 live_classify.py --start 2026-07-15T10:00:00Z --end 2026-07-15T10:03:00Z

Requires:  requests, joblib, scikit-learn, and extract_features.py in the same dir
           (03-scripts/), plus rf_model.pkl + feature_columns.json in 05-models/.
"""
import argparse, json, os, sys, requests
from datetime import datetime, timedelta, timezone

# import the EXACT feature extractor used for training
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import extract_features as ef
import joblib

ES         = "http://localhost:64298"          # via SSH tunnel
SRC        = "192.168.32.1"
MGMT_PORTS = [64294,64295,64296,64297,64298,64305]
MODEL_DIR  = "/mnt/c/tpot-project/05-models"
MODEL_PATH = os.path.join(MODEL_DIR, "rf_model.pkl")
COLS_PATH  = os.path.join(MODEL_DIR, "feature_columns.json")

def now_utc():
    return datetime.now(timezone.utc)

def iso(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")

def fetch_events(start, end):
    """Scroll every matching event in [start,end], excluding NGINX + mgmt ports.
       (Same filtering as the training-data export.)"""
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
        print(f"ERROR: cannot reach Elasticsearch at {ES} — is the tunnel open?\n  {e}")
        sys.exit(1)
    sid = r.get("_scroll_id"); hits = r.get("hits",{}).get("hits",[])
    while hits:
        docs += [h["_source"] for h in hits]
        r = requests.post(f"{ES}/_search/scroll",
                          json={"scroll":"2m","scroll_id":sid}, timeout=60).json()
        sid = r.get("_scroll_id"); hits = r.get("hits",{}).get("hits",[])
    try: requests.delete(f"{ES}/_search/scroll", json={"scroll_id":[sid]}, timeout=15)
    except Exception: pass
    return docs

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--minutes", type=float, default=2.0, help="classify the last N minutes")
    ap.add_argument("--start", help="explicit UTC start, e.g. 2026-07-15T10:00:00Z")
    ap.add_argument("--end",   help="explicit UTC end")
    args = ap.parse_args()

    if args.start and args.end:
        start, end = args.start, args.end
    else:
        end_dt = now_utc() + timedelta(seconds=2)          # small look-ahead for clock skew
        start_dt = end_dt - timedelta(minutes=args.minutes)
        start, end = iso(start_dt), iso(end_dt)

    print(f"\n{'='*56}\nLIVE CLASSIFY   window (UTC): {start} -> {end}\n{'='*56}")

    # 1) pull events
    docs = fetch_events(start, end)
    docs_kept = [d for d in docs if d.get("type") not in ef.EXCLUDE_TYPES]
    print(f"events pulled: {len(docs)}  (after NGINX/mgmt exclusion: {len(docs_kept)})")
    if len(docs_kept) < 2:
        print("\nNot enough traffic in this window to classify.")
        print("Launch an attack first, then re-run within a minute or two.")
        return

    # 2) extract features with the SAME code used for training
    feats, _hp = ef.extract("LIVE", "unknown", docs)   # extract() drops NGINX itself

    # 3) build the feature vector in the model's exact column order
    cols = json.load(open(COLS_PATH))
    x = [[float(feats.get(c, 0)) for c in cols]]

    # 4) predict + confidence
    model = joblib.load(MODEL_PATH)
    pred = model.predict(x)[0]
    proba = model.predict_proba(x)[0]
    classes = list(model.classes_)
    ranked = sorted(zip(classes, proba), key=lambda t: -t[1])

    print(f"\n  >>> PREDICTED ATTACK TYPE:  {pred.upper()}  "
          f"(confidence {dict(ranked)[pred]*100:.1f}%)\n")
    print("  full probability breakdown:")
    for c, p in ranked:
        bar = "#" * int(round(p*30))
        print(f"    {c:18} {p*100:5.1f}%  {bar}")

    # 5) a few key observed features, for the demo narrative
    print("\n  key observed behavior:")
    for k in ["total_events","distinct_dest_ports","n_login_fail","n_login_success",
              "n_commands","n_http_events","n_web_80","n_web_8080"]:
        print(f"    {k:20} = {feats.get(k)}")
    print()

if __name__ == "__main__":
    main()
