# Honeypot Attack Classification

A **deployment-ready multi-honeypot system with an integrated machine-learning model** that automatically classifies each network attack into one of five categories from its **behavior** (not from which honeypot logged it), reaching **~98.7%** cross-validated accuracy.

Real attacks are generated in an isolated **T-Pot** lab, their telemetry is collected from Elasticsearch, summarized into 32 behavioral features, and used to train and compare six models. The deployed model (**XGBoost**) runs behind a live classifier that streams verdicts to a **Kibana** dashboard.

---

## Table of Contents

- [Overview](#overview)
- [Project Structure](#project-structure)
- [Requirements & Tools](#requirements--tools)
- [How to Run](#how-to-run)
- [Large Files & Data](#large-files--data)
- [Results](#results)
- [Documentation](#documentation)
- [Academic Use](#academic-use)

---

## Overview

The system lures attackers into honeypots that emulate real services, records their behavior, then automatically classifies each attack into one of five classes: **scan**, **online guessing**, **post-exploitation**, **web attack**, and **denial of service (DoS)**.

- **Environment:** T-Pot multi-honeypot platform (~19 Docker containers) + ELK stack (Elasticsearch / Logstash / Kibana), with a Kali (WSL2) attacker.
- **Data:** 150 labeled attack runs (5 classes × 30), auto-labeled by time window + source IP `192.168.32.1`.
- **Features:** 32 behavioral features per run.
- **Model:** Deployed XGBoost, selected from six models via 5-fold stratified cross-validation.
- **Live:** `live_runs.py` writes predictions to an `ml-predictions` index that a Kibana dashboard reads live.

---

## Project Structure

```
tpot-project/
├── environment/                      # the lab (T-Pot) config & inventory
│   ├── docker-compose.yml               # trimmed T-Pot stack (~19 containers)
│   ├── docker-compose.frozen-*.yml      # frozen snapshot of the stack
│   ├── running-containers.txt           # docker ps output
│   └── tpot version.txt                 # T-Pot version used
│
├── 01-run-ledger/
│   └── run-ledger.csv                # every attack run: id, label, tool, command, time window, target
│
├── 02-raw-data/                      # raw Elasticsearch exports — NOT committed (regenerable)
│   ├── README.md                        # how to regenerate the raw data
│   └── export-manifest.csv              # per-run event counts + time windows
│
├── 03-scripts/
│   ├── run_campaign.py                  # scan campaign (nmap)
│   ├── run_online_guessing.py           # online-guessing campaign (Hydra)
│   ├── run_postexploit.py               # post-exploitation campaign (sshpass)
│   ├── run_webattack.py                 # web-attack campaign (Nikto + curl)
│   ├── run_dos.py                       # DoS campaign (hping3 / ab / siege / slowhttptest)
│   ├── export_events.py                 # Elasticsearch -> per-run JSON
│   ├── extract_features.py              # events -> feature datasets
│   ├── live_runs.py                     # live classifier -> ml-predictions index
│   ├── verify_*.py                      # per-class capture verifiers
│   ├── test_connection.py               # Elasticsearch connectivity check
│   └── wordlists/                       # Hydra user/password lists
│
├── 04-features/
│   ├── dataset_behavioral.csv           # 32 behavioral features x 150 runs
│   ├── dataset_full.csv                 # + 9 per-honeypot counts (41 features)
│   └── field-map.md                     # Elasticsearch field dictionary
│
├── 05-notebooks/
│   ├── 01-EDA-and-datasets-comparison.ipynb   # EDA + behavioral-vs-full comparison
│   ├── 02-Random-Forest-tuning.ipynb          # Random Forest tuning
│   └── 03-classifiers-comparison.ipynb        # six-model comparison + selection
│
├── 06-models/
│   ├── deployed_model.json              # deployed XGBoost (portable native format)
│   ├── deployed_model_meta.json         # params, CV scores, versions, class order
│   ├── feature_columns.json             # the 32 feature names, in exact order
│   ├── class_labels.json                # integer -> class-name map
│   ├── model_comparison.csv             # the six-model leaderboard
│   ├── rf_params.json                   # tuned Random Forest params
│   └── rf_hyperparam_search.csv         # RF grid-search results
│
├── 07-report/                        # report source (Markdown / companion docs)
│   └── kibana-dashboard.md              # Kibana dashboard documentation
│
├── docs/                             # final report + high-resolution figures
│   |
│   ├── practical-report.pdf                # PDF version
│   └── figures/                        # diagrams & screenshots in high resolution (PNG / SVG)
│
├── .gitignore
└── README.md
```

---

## Requirements & Tools

### Infrastructure
- **T-Pot** (runs on Docker) on an isolated Debian VM.
- **ELK stack**: Elasticsearch, Logstash, Kibana (version 9.x).
- **Attacker machine**: Kali Linux on WSL2 (Windows).
- **ML host**: Anaconda (Python + Jupyter) on Windows.

### Attack tools (on Kali)
`nmap` · `hydra` · `sshpass` · `nikto` · `curl` · `hping3` · `apache2-utils` (ab) · `siege` · `slowhttptest`

### Python libraries
Python 3 with:
`pandas` · `numpy` · `scikit-learn==1.9.0` · `xgboost==3.2.0` · `matplotlib` · `seaborn` · `requests` · `joblib` · `jupyter`

Install them via `requirements.txt`:
```bash
pip install -r requirements.txt
```

---

## How to Run

> Requires the T-Pot lab running with Elasticsearch reachable. Live classification also needs an SSH tunnel to Elasticsearch.
> Edit the paths at the top of the scripts if your layout differs from `C:\tpot-project`.

```bash
# 1) generate data (from Kali) — resumable, one row per run in the ledger
python3 03-scripts/run_campaign.py
python3 03-scripts/run_online_guessing.py
python3 03-scripts/run_postexploit.py
python3 03-scripts/run_webattack.py
python3 03-scripts/run_dos.py

# 2) export each run's events from Elasticsearch to JSON
python3 03-scripts/export_events.py

# 3) build the feature datasets
python3 03-scripts/extract_features.py

# 4) train / compare / select the model -> open the notebooks in 05-notebooks/

# 5) live classification (writes predictions to the ml-predictions index for Kibana)
python3 03-scripts/live_runs.py             # 30s idle gap (default)
python3 03-scripts/live_runs.py --idle 120  # for DoS (late Suricata flow events)
```

**Kibana dashboard:** after predictions are written, register a data view on the pattern `ml-predictions*` with time field `@timestamp`, then build the dashboard (attack types over time, class distribution, average confidence, recent detections table). Details in `07-report/kibana-dashboard.md`.

---

## Large Files & Data

To keep the repository small, raw data and temporary files are **not committed** — they are fully regenerable:

- **Raw Elasticsearch events:** per-run events (~1.4M) are stored locally in `02-raw-data/es-events/` and are **excluded via `.gitignore`**. Regenerate them by running `export_events.py` (see `02-raw-data/README.md`).
- **T-Pot platform:** not part of this repo; install it from the official source: https://github.com/telekom-security/tpotce
- **joblib model (`.pkl`):** committed.

> Note: this project does not use large pre-trained models — the model is trained from scratch on our own data and is tiny. The heaviest dependency (T-Pot) is linked to its official source above instead of being uploaded.

---

## Results

| Model | Accuracy | Macro-F1 | Errors |
|---|:---:|:---:|:---:|
| **XGBoost** (deployed) | **0.9867** | 0.9866 | 2 |
| SVM (linear) | 0.9867 | 0.9866 | 2 |
| KNN | 0.9867 | 0.9866 | 2 |
| MLP | 0.9800 | 0.9800 | 3 |
| Random Forest | 0.9800 | 0.9799 | 3 |
| Logistic Regression | 0.9733 | 0.9732 | 4 |

- The **behavioral** dataset (32 features) and the **full** dataset (41 features) reach the **same 98.0% accuracy with identical predictions** — the 9 per-honeypot count features add nothing, so the model classifies **by behavior, not by sensor**. We therefore deploy the leaner behavioral model.
- All errors fall on the genuine **web-attack ↔ DoS** boundary (high-volume web runs that resemble floods).

---

## Documentation

The final report and its high-resolution figures live in the **`docs/`** folder:

- `docs/practical-report.pdf` — PDF version.
- `docs/figures/` — diagrams & screenshots in high resolution (PNG / SVG).
