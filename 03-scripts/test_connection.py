import requests

ES = "http://localhost:64298"   # reached via the SSH tunnel

# 1) list indices
r = requests.get(f"{ES}/_cat/indices?v&s=index", timeout=30)
print(r.text)

# 2) pull the 3 most recent Kali-sourced events
query = {
    "size": 3,
    "query": {"term": {"src_ip": "192.168.32.1"}},
    "sort": [{"@timestamp": "desc"}],
}
data = requests.post(f"{ES}/logstash-*/_search", json=query, timeout=30).json()

if "hits" not in data:
    print("\nERROR from Elasticsearch:", data)
else:
    hits = data["hits"]["hits"]
    print(f"\ngot {len(hits)} docs")
    for h in hits:
        s = h["_source"]
        print(s.get("@timestamp"), "|", s.get("type"), "|",
              s.get("src_ip"), "->", s.get("dest_port"))
