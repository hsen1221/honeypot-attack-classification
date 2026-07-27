# Field map (T-Pot / Elasticsearch 9.3.5) — verified 2026-07-09

Index pattern:        logstash-*
Timestamp field:      @timestamp        (UTC, has milliseconds)   [verified]
Source IP field:      src_ip = 192.168.32.1   (Kali via WSL2 NAT) [verified]
Dest IP field:        dest_ip                                     [verified]
Dest port field:      dest_port                                   [verified]
Src port field:       src_port                                    [verified]
Honeypot type field:  type   (for terms/aggregations use type.keyword on ES 9.x)  [verified]
    values seen so far: P0f, Suricata, Dionaea, Cowrie, Fatt, Tanner

# Self-tagging artifact (ignore in analysis):
#   geoip_ext /"Syrian Telecom / Damascus"
#   = the honeypot's own detected public IP, stamped on ALL events. NOT an attacker.

# Cowrie event field (confirm values during Steps 4-5):
Cowrie event field:   eventid
    values that matter:
      cowrie.session.connect
      cowrie.login.failed
      cowrie.login.success
      cowrie.command.input
      cowrie.command.failed
      cowrie.session.file_download
    credential fields:  username, password  (use .keyword for aggregations)
    command field:      input               (use .keyword for aggregations)

# Suricata fields:  event_type (flow / alert),  alert.signature
# Web (Tanner/Wordpot) fields: fill during Step 6

# Cowrie accepted credential (verified 2026-07-10): root:password
# Field mapping rule (ES 9.x): string fields need .keyword for aggregations
#   (eventid.keyword, username.keyword, password.keyword, input.keyword)
#   dest_port is 'long' -> use directly, no .keyword

# Web fields (Tanner/Snare, verified 2026-07-11):
#   type.keyword: "Tanner" / "Snare"
#   path      = requested URL (carries the payload)
#   method    = GET/POST
#   status    = HTTP status code
#   dest_port = 80 (Tanner/Snare), 8080 (Wordpot)
#   ATTACK CLASSIFICATION (Tanner's own detection):
#     response_msg.response.message.detection.name  -> "xss","sqli","lfi","index"(=benign),...
#   -> this is the RULE-BASED classifier for the 3-way comparison

# Step 6 web campaign complete (2026-07-11):
#   W001-W030 collected. Tanner classifies ONLY xss reliably (10/10 test),
#   labels sqli/lfi/cmd/xxe as "index" (benign) despite logging them fully.
#   -> documented finding: signature-based detection is brittle -> motivates ML.
#   Snare events = 0 (Snare fronts requests, Tanner does the logging/classification).
